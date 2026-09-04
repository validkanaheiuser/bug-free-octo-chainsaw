// c2redirect.m — XoaInfo Fake Auth (debug build)
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>

#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#define LOG_TAG "[XoaBypass] "

// ─── Block ABI ───────────────────────────────────────────────────────────────
typedef void (*BlockInvoke2)(void *, id, id);
struct BlockLayout { void *isa; int flags; int reserved; BlockInvoke2 invoke; };

static void callSuccessBlock(id block, NSData *arg) {
    if (!block) { NSLog(@LOG_TAG "successBlock: block=nil"); return; }
    struct BlockLayout *b = (__bridge struct BlockLayout *)block;
    if (!b || !b->invoke) { NSLog(@LOG_TAG "successBlock: invoke=nil"); return; }

    const uint8_t *bytes = (const uint8_t *)arg.bytes;
    NSLog(@LOG_TAG "successBlock: invoke=%p len=%zu b0=%02x b1=%02x class=%@",
          (void*)b->invoke, (size_t)arg.length,
          arg.length > 0 ? bytes[0] : 0,
          arg.length > 1 ? bytes[1] : 0,
          NSStringFromClass([arg class]));

    // Full base64 in 400-char chunks
    NSString *b64 = [arg base64EncodedStringWithOptions:0];
    NSUInteger total = b64.length, chunk = 400;
    for (NSUInteger i = 0; i < total; i += chunk) {
        NSUInteger end = MIN(i + chunk, total);
        NSLog(@LOG_TAG "  blob[%lu-%lu]: %@",
              (unsigned long)i, (unsigned long)(end-1),
              [b64 substringWithRange:NSMakeRange(i, end-i)]);
    }

    b->invoke(b, arg, nil);
    NSLog(@LOG_TAG "successBlock: returned");
}

// ─── Crypto helpers ───────────────────────────────────────────────────────────
static NSString *md5Hex(NSString *s) {
    const char *cs = [s UTF8String];
    unsigned char d[CC_MD5_DIGEST_LENGTH];
    CC_MD5(cs, (CC_LONG)strlen(cs), d);
    NSMutableString *r = [NSMutableString stringWithCapacity:32];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) [r appendFormat:@"%02x", d[i]];
    return r;
}

// blob = 03 01 | encSalt(8) | hmacSalt(8) | ivHeader(16) | CT | zeros(64)
// encKey   = PBKDF2(pw, encSalt||hmacSalt, SHA512, 10000, 32)
// actualIV = PBKDF2(pw, ivHeader,          SHA512, 10000, 16)
// plaintext: 16 random prefix bytes — XoaInfo parser skips first 16B after decryption
static NSData *rncryptEncrypt(NSData *plain, NSString *password) {
    const char *pw = [password UTF8String];
    size_t pwLen   = strlen(pw);

    uint8_t encSalt[8], hmacSalt[8], ivHeader[16], prefix[16];
    arc4random_buf(encSalt,  8);
    arc4random_buf(hmacSalt, 8);
    arc4random_buf(ivHeader, 16);
    arc4random_buf(prefix,   16);

    uint8_t combined[16];
    memcpy(combined, encSalt, 8);
    memcpy(combined + 8, hmacSalt, 8);

    uint8_t encKey[32], actualIV[16];
    CCKeyDerivationPBKDF(kCCPBKDF2, pw, pwLen, combined, 16, kCCPRFHmacAlgSHA512, 10000, encKey,   32);
    CCKeyDerivationPBKDF(kCCPBKDF2, pw, pwLen, ivHeader, 16, kCCPRFHmacAlgSHA512, 10000, actualIV, 16);

    NSMutableData *prefixed = [NSMutableData dataWithBytes:prefix length:16];
    [prefixed appendData:plain];

    size_t ctBufLen = prefixed.length + kCCBlockSizeAES128;
    void *ctBuf = malloc(ctBufLen);
    size_t ctLen = 0;
    CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
            encKey, 32, actualIV,
            prefixed.bytes, prefixed.length,
            ctBuf, ctBufLen, &ctLen);

    uint8_t hdr[2] = {0x03, 0x01};
    NSMutableData *blob = [NSMutableData data];
    [blob appendBytes:hdr      length:2];
    [blob appendBytes:encSalt  length:8];
    [blob appendBytes:hmacSalt length:8];
    [blob appendBytes:ivHeader length:16];
    [blob appendBytes:ctBuf    length:ctLen]; free(ctBuf);
    uint8_t trailer[64] = {0};
    [blob appendBytes:trailer  length:64];
    return blob;
}

static NSString *b64str(NSString *s) {
    return [[s dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];
}

// ─── Param helpers ────────────────────────────────────────────────────────────
static long long ecidFromSerialB64(NSString *b64) {
    if (!b64) return 1LL;
    NSData *d = [[NSData alloc] initWithBase64EncodedString:b64 options:0];
    if (!d) return 1LL;
    NSString *decoded = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
    NSArray *parts = [decoded componentsSeparatedByString:@"|"];
    return parts.count >= 3 ? [parts[2] longLongValue] : 1LL;
}

static long long nonceFromChecksumB64(NSString *b64, long long ecid) {
    if (!b64) return 1266394LL;
    NSData *d = [[NSData alloc] initWithBase64EncodedString:b64 options:0];
    if (!d) return 1266394LL;
    long long val = [[[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] longLongValue];
    NSLog(@LOG_TAG "checksum_val=%lld ecid=%lld", val, ecid);
    return val > ecid ? (val - ecid) / 124457LL : 1266394LL;
}

// ─── Response builders ────────────────────────────────────────────────────────
static NSData *buildLoginip(NSDictionary *params) {
    long long ecid  = ecidFromSerialB64(params[@"serial"]);
    long long nonce = nonceFromChecksumB64(params[@"checksum"], ecid);
    NSString *phase = md5Hex([NSString stringWithFormat:@"%lld", ecid + 51739121LL * nonce]);

    NSString *plain = [NSString stringWithFormat:
        @"expDate:2099-12-31 23:59:59|<>|phase:%@|<>|encrypted:%@|<>|"
        @"version_run:10|<>|message:Good|<>|retention:%@|<>|deleteList:%@|<>|",
        phase,
        b64str(@"#!/bin/sh\nexit 0\n"),
        b64str(@"\n"),
        b64str(@"\n")];

    NSLog(@LOG_TAG "loginip: ecid=%lld nonce=%lld phase=%@", ecid, nonce, phase);
    return rncryptEncrypt([plain dataUsingEncoding:NSUTF8StringEncoding],
                          [NSString stringWithFormat:@"%lld", nonce]);
}

static NSData *buildTeam(NSDictionary *params) {
    const long long teamV19 = 13981LL;
    long long ecid  = ecidFromSerialB64(params[@"serial"]);
    NSString *phase = md5Hex([NSString stringWithFormat:@"%lld", ecid + 51739121LL * teamV19]);

    NSString *x = (ecid == 5393981226811438LL) ? @"58716dc8bad43e293b8d2d0f4f53b609" : @"";
    NSString *plain = [NSString stringWithFormat:
        @"phase:%@|<>|version_run:10|<>|message:Good|<>|versionApp%@.expDate:|<>|",
        phase, x];

    NSLog(@LOG_TAG "team: ecid=%lld phase=%@", ecid, phase);
    return rncryptEncrypt([plain dataUsingEncoding:NSUTF8StringEncoding], @"13981");
}

// ─── Hook: j2cyd0Nd gateway ───────────────────────────────────────────────────
static void (*orig_b5Znk9Kh)(id, SEL, id, id, id, id);

static void hooked_b5Znk9Kh(id self, SEL _cmd,
                              id params, id path, id successBlock, id failureBlock) {
    NSString *pathStr = [NSString stringWithFormat:@"%@", path];
    NSLog(@LOG_TAG "gateway: %@ successBlock=%p", pathStr, (__bridge void*)successBlock);

    NSData *resp = nil;
    if ([pathStr containsString:@"loginip"]) {
        resp = buildLoginip((NSDictionary *)params);
    } else if ([pathStr containsString:@"team"] || [pathStr containsString:@"X2.1Public"]) {
        resp = buildTeam((NSDictionary *)params);
    }

    if (resp) {
        callSuccessBlock(successBlock, resp);
        return;
    }
    if (orig_b5Znk9Kh) orig_b5Znk9Kh(self, _cmd, params, path, successBlock, failureBlock);
}

// ─── Hook: s7AcUOKf preferences ──────────────────────────────────────────────
static id (*orig_q3uTJBk1)(id, SEL, id);

static id hooked_q3uTJBk1(id self, SEL _cmd, id key) {
    NSString *k = [NSString stringWithFormat:@"%@", key];
    id result = nil;
    BOOL spoofed = YES;
    if ([k isEqualToString:@"RunVersion"])   result = @"10";
    else if ([k isEqualToString:@"Password"]) result = @"ase1";
    else if ([k isEqualToString:@"DataRun"]) result = b64str(@"#!/bin/sh\nexit 0\n");
    else if ([k isEqualToString:@"RetenData"] ||
             [k isEqualToString:@"DeleteListData"]) result = b64str(@"\n");
    else { spoofed = NO; result = orig_q3uTJBk1 ? orig_q3uTJBk1(self, _cmd, key) : nil; }

    NSString *disp = result ? [NSString stringWithFormat:@"%@", result] : @"nil";
    if (disp.length > 60) disp = [[disp substringToIndex:60] stringByAppendingString:@"..."];
    NSLog(@LOG_TAG "pref[%@]%@ → %@", k, spoofed ? @"(spoofed)" : @"", disp);
    return result;
}

// ─── Hook: y8WisN9t = RNCryptor decryptor (class methods) ────────────────────

// +c6chSi59:b5NuCqT9:password:error:  (cipherData, ?, password, &error)
typedef NSData *(*DecryptPw)(id, SEL, id, id, NSString *, NSError **);
static DecryptPw orig_dec_pw = NULL;
static NSData *hooked_dec_pw(id cls, SEL _cmd, id arg1, id arg2, NSString *pw, NSError **err) {
    NSLog(@LOG_TAG "+c6chSi59:b5NuCqT9:password: arg1=%@/%zu arg2=%@ pw='%@'",
          NSStringFromClass([arg1 class]),
          [arg1 respondsToSelector:@selector(length)] ? [(NSData*)arg1 length] : 0,
          [arg2 description], pw);
    if ([arg1 isKindOfClass:[NSData class]])
        NSLog(@LOG_TAG "  arg1_b64=%.300@", [(NSData*)arg1 base64EncodedStringWithOptions:0]);
    else if ([arg1 isKindOfClass:[NSString class]])
        NSLog(@LOG_TAG "  arg1_str=%.300@", (NSString*)arg1);
    NSData *res = orig_dec_pw(cls, _cmd, arg1, arg2, pw, err);
    if (err && *err) NSLog(@LOG_TAG "  error=%@", *err);
    NSLog(@LOG_TAG "  → result len=%zu first=%.40@",
          res.length, [[NSString alloc] initWithData:[res subdataWithRange:NSMakeRange(0, MIN(40, res.length))] encoding:NSUTF8StringEncoding]);
    return res;
}

// +c6chSi59:b5NuCqT9:d2ZmQPQj:r1FIQ6ln:error:  (cipherData, ?, key, iv, &error)
typedef NSData *(*DecryptKeyIV)(id, SEL, id, id, id, id, NSError **);
static DecryptKeyIV orig_dec_kiv = NULL;
static NSData *hooked_dec_kiv(id cls, SEL _cmd, id a1, id a2, id a3, id a4, NSError **err) {
    NSLog(@LOG_TAG "+c6chSi59:b5NuCqT9:d2ZmQPQj:r1FIQ6ln: a1=%@/%zu a2=%@ a3=%zu a4=%zu",
          NSStringFromClass([a1 class]),
          [a1 respondsToSelector:@selector(length)] ? [(NSData*)a1 length] : 0,
          [a2 description],
          [a3 respondsToSelector:@selector(length)] ? [(NSData*)a3 length] : 0,
          [a4 respondsToSelector:@selector(length)] ? [(NSData*)a4 length] : 0);
    if ([a1 isKindOfClass:[NSData class]])
        NSLog(@LOG_TAG "  a1_b64=%.200@", [(NSData*)a1 base64EncodedStringWithOptions:0]);
    NSData *res = orig_dec_kiv(cls, _cmd, a1, a2, a3, a4, err);
    if (err && *err) NSLog(@LOG_TAG "  error=%@", *err);
    NSLog(@LOG_TAG "  → result len=%zu", res.length);
    return res;
}

// +c6chSi59:q69GFYW9:error:  (data, ?, &error)
typedef NSData *(*DecryptSimple)(id, SEL, id, id, NSError **);
static DecryptSimple orig_dec_simple = NULL;
static NSData *hooked_dec_simple(id cls, SEL _cmd, id a1, id a2, NSError **err) {
    NSLog(@LOG_TAG "+c6chSi59:q69GFYW9: a1=%@/%zu a2=%@",
          NSStringFromClass([a1 class]),
          [a1 respondsToSelector:@selector(length)] ? [(NSData*)a1 length] : 0,
          [a2 description]);
    if ([a1 isKindOfClass:[NSData class]])
        NSLog(@LOG_TAG "  a1_b64=%.200@", [(NSData*)a1 base64EncodedStringWithOptions:0]);
    NSData *res = orig_dec_simple(cls, _cmd, a1, a2, err);
    if (err && *err) NSLog(@LOG_TAG "  error=%@", *err);
    NSLog(@LOG_TAG "  → result len=%zu", res.length);
    return res;
}

// +c6chSi59:z4QMWDbr:r1FIQ6ln:error:  (data, ?, iv, &error)
typedef NSData *(*DecryptIV)(id, SEL, id, id, id, NSError **);
static DecryptIV orig_dec_iv = NULL;
static NSData *hooked_dec_iv(id cls, SEL _cmd, id a1, id a2, id a3, NSError **err) {
    NSLog(@LOG_TAG "+c6chSi59:z4QMWDbr:r1FIQ6ln: a1=%@/%zu a2=%@ a3=%zu",
          NSStringFromClass([a1 class]),
          [a1 respondsToSelector:@selector(length)] ? [(NSData*)a1 length] : 0,
          [a2 description],
          [a3 respondsToSelector:@selector(length)] ? [(NSData*)a3 length] : 0);
    NSData *res = orig_dec_iv(cls, _cmd, a1, a2, a3, err);
    if (err && *err) NSLog(@LOG_TAG "  error=%@", *err);
    NSLog(@LOG_TAG "  → result len=%zu", res.length);
    return res;
}

// ─── Hook: NSURLSession (diagnostic) ─────────────────────────────────────────
static NSURLSessionDataTask *(*orig_req)(id, SEL, NSURLRequest *, id);
static NSURLSessionDataTask *hooked_req(id self, SEL _cmd, NSURLRequest *req, id handler) {
    NSLog(@LOG_TAG "NSURLSession → %@", req.URL.absoluteString);
    return orig_req(self, _cmd, req, handler);
}

// ─── Constructor ─────────────────────────────────────────────────────────────
__attribute__((constructor)) static void initTweak(void) {
    NSLog(@LOG_TAG "=== XoaInfo Fake Auth Loaded (debug2) ===");

    // j2cyd0Nd gateway
    Class gw = objc_getClass("j2cyd0Nd");
    if (gw) {
        Method m = class_getInstanceMethod(gw, sel_registerName("b5Znk9Kh:q7C9eMnf:c7UND7t6:z0BQnrZN:"));
        if (m) {
            orig_b5Znk9Kh = (void(*)(id,SEL,id,id,id,id))method_getImplementation(m);
            method_setImplementation(m, (IMP)hooked_b5Znk9Kh);
            NSLog(@LOG_TAG "[OK] j2cyd0Nd gateway hooked");
        } else { NSLog(@LOG_TAG "[!] j2cyd0Nd method not found"); }
    } else { NSLog(@LOG_TAG "[!] j2cyd0Nd class not found"); }

    // s7AcUOKf preferences
    Class pref = objc_getClass("s7AcUOKf");
    if (pref) {
        Method m = class_getClassMethod(pref, sel_registerName("q3uTJBk1:"));
        if (m) {
            orig_q3uTJBk1 = (id(*)(id,SEL,id))method_getImplementation(m);
            method_setImplementation(m, (IMP)hooked_q3uTJBk1);
            NSLog(@LOG_TAG "[OK] s7AcUOKf preferences hooked");
        }
    }

    // y8WisN9t = RNCryptor — hook all c6chSi59 class methods (NOT instance method — returns primitive)
    Class dec = objc_getClass("y8WisN9t");
    if (!dec) { NSLog(@LOG_TAG "[!] y8WisN9t not found"); goto skip_dec; }

    {
        Method m;
        // +c6chSi59:b5NuCqT9:password:error:
        m = class_getClassMethod(dec, sel_registerName("c6chSi59:b5NuCqT9:password:error:"));
        if (m) {
            orig_dec_pw = (DecryptPw)method_getImplementation(m);
            method_setImplementation(m, (IMP)hooked_dec_pw);
            NSLog(@LOG_TAG "[OK] +c6chSi59:b5NuCqT9:password:error: hooked");
        }
        // +c6chSi59:b5NuCqT9:d2ZmQPQj:r1FIQ6ln:error:
        m = class_getClassMethod(dec, sel_registerName("c6chSi59:b5NuCqT9:d2ZmQPQj:r1FIQ6ln:error:"));
        if (m) {
            orig_dec_kiv = (DecryptKeyIV)method_getImplementation(m);
            method_setImplementation(m, (IMP)hooked_dec_kiv);
            NSLog(@LOG_TAG "[OK] +c6chSi59:b5NuCqT9:d2ZmQPQj:r1FIQ6ln:error: hooked");
        }
        // +c6chSi59:q69GFYW9:error:
        m = class_getClassMethod(dec, sel_registerName("c6chSi59:q69GFYW9:error:"));
        if (m) {
            orig_dec_simple = (DecryptSimple)method_getImplementation(m);
            method_setImplementation(m, (IMP)hooked_dec_simple);
            NSLog(@LOG_TAG "[OK] +c6chSi59:q69GFYW9:error: hooked");
        }
        // +c6chSi59:z4QMWDbr:r1FIQ6ln:error:
        m = class_getClassMethod(dec, sel_registerName("c6chSi59:z4QMWDbr:r1FIQ6ln:error:"));
        if (m) {
            orig_dec_iv = (DecryptIV)method_getImplementation(m);
            method_setImplementation(m, (IMP)hooked_dec_iv);
            NSLog(@LOG_TAG "[OK] +c6chSi59:z4QMWDbr:r1FIQ6ln:error: hooked");
        }
    }
    skip_dec:;

    // NSURLSession diagnostic
    Class sess = objc_getClass("NSURLSession");
    if (sess) {
        Method m = class_getInstanceMethod(sess, sel_registerName("dataTaskWithRequest:completionHandler:"));
        if (m) {
            orig_req = (NSURLSessionDataTask*(*)(id,SEL,NSURLRequest*,id))method_getImplementation(m);
            method_setImplementation(m, (IMP)hooked_req);
            NSLog(@LOG_TAG "[OK] NSURLSession hooked");
        }
    }
}
