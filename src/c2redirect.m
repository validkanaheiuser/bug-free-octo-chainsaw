// c2redirect.m — XoaInfo Fake Auth
// Hooks j2cyd0Nd gateway (loginip + team) and s7AcUOKf preferences.
// Builds correct RNCryptor v3 blobs — XoaInfo's own decryptor handles them.

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <CommonCrypto/CommonDigest.h>

#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#define LOG_TAG "[XoaBypass] "

// ─── Block invocation helper ──────────────────────────────────────────────────
// Objective-C blocks have a known ABI: first field after isa/flags/reserved is invoke fn.
typedef void (*BlockInvoke2)(void *, id, id);
struct BlockLayout { void *isa; int flags; int reserved; BlockInvoke2 invoke; };

static void callSuccessBlock(id block, NSData *arg) {
    if (!block) return;
    struct BlockLayout *b = (__bridge struct BlockLayout *)block;
    if (b && b->invoke) b->invoke(b, arg, arg);
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

// Custom RNCryptor v3: PBKDF2(SHA512) encKey + actualIV, AES-256-CBC-PKCS7
// blob = 0x03 0x01 | encSalt(8) | hmacSalt(8) | ivHeader(16) | CT | zeros(64)
static NSData *rncryptEncrypt(NSData *plain, NSString *password) {
    const char *pw = [password UTF8String];
    size_t pwLen   = strlen(pw);
    uint8_t encSalt[8], hmacSalt[8], ivHeader[16];
    arc4random_buf(encSalt, 8); arc4random_buf(hmacSalt, 8); arc4random_buf(ivHeader, 16);
    uint8_t combined[16]; memcpy(combined, encSalt, 8); memcpy(combined+8, hmacSalt, 8);
    uint8_t encKey[32], actualIV[16];
    CCKeyDerivationPBKDF(kCCPBKDF2, pw, pwLen, combined, 16, kCCPRFHmacAlgSHA512, 10000, encKey, 32);
    CCKeyDerivationPBKDF(kCCPBKDF2, pw, pwLen, ivHeader, 16, kCCPRFHmacAlgSHA512, 10000, actualIV, 16);
    size_t ctBufLen = plain.length + kCCBlockSizeAES128;
    void *ctBuf = malloc(ctBufLen); size_t ctLen = 0;
    CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
            encKey, 32, actualIV, plain.bytes, plain.length, ctBuf, ctBufLen, &ctLen);
    NSMutableData *blob = [NSMutableData dataWithCapacity:2+8+8+16+ctLen+64];
    uint8_t hdr[2] = {0x03, 0x01};
    [blob appendBytes:hdr length:2]; [blob appendBytes:encSalt length:8];
    [blob appendBytes:hmacSalt length:8]; [blob appendBytes:ivHeader length:16];
    [blob appendBytes:ctBuf length:ctLen]; free(ctBuf);
    uint8_t trailer[64] = {0}; [blob appendBytes:trailer length:64];
    return blob;
}

// Encrypt plaintext directly (no prefix) — XoaInfo parser reads from byte 0
static NSData *encryptedB64(NSString *plain, NSString *password) {
    NSData *enc = rncryptEncrypt([plain dataUsingEncoding:NSUTF8StringEncoding], password);
    return [[enc base64EncodedStringWithOptions:0] dataUsingEncoding:NSUTF8StringEncoding];
}

static NSString *b64str(NSString *s) {
    return [[s dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];
}

// ─── Param helpers ────────────────────────────────────────────────────────────

static long long ecidFromSerialB64(NSString *b64) {
    if (!b64) return 1LL;
    NSData *d = [[NSData alloc] initWithBase64EncodedString:b64 options:0];
    if (!d) return 1LL;
    NSArray *parts = [[[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding]
                      componentsSeparatedByString:@"|"];
    return parts.count >= 3 ? [parts[2] longLongValue] : 1LL;
}

static long long nonceFromChecksumB64(NSString *b64, long long ecid) {
    if (!b64) return 1266394LL;
    NSData *d = [[NSData alloc] initWithBase64EncodedString:b64 options:0];
    if (!d) return 1266394LL;
    long long val = [[[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] longLongValue];
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
    return encryptedB64(plain, [NSString stringWithFormat:@"%lld", nonce]);
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
    return encryptedB64(plain, @"13981");
}

// ─── Hook: j2cyd0Nd gateway ───────────────────────────────────────────────────

static void (*orig_b5Znk9Kh)(id, SEL, id, id, id, id);

static void hooked_b5Znk9Kh(id self, SEL _cmd,
                              id params, id path, id successBlock, id failureBlock) {
    NSString *pathStr = [NSString stringWithFormat:@"%@", path];
    NSLog(@LOG_TAG "gateway: %@", pathStr);

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
    if ([k isEqualToString:@"RunVersion"]) return @"10";
    if ([k isEqualToString:@"Password"])   return @"ase1";
    if ([k isEqualToString:@"DataRun"])    return b64str(@"#!/bin/sh\nexit 0\n");
    if ([k isEqualToString:@"RetenData"] ||
        [k isEqualToString:@"DeleteListData"]) return b64str(@"\n");
    return orig_q3uTJBk1 ? orig_q3uTJBk1(self, _cmd, key) : nil;
}

// ─── Hook: NSURLSession (diagnostic + catch any remaining requests) ───────────

static NSURLSessionDataTask *(*orig_req)(id, SEL, NSURLRequest *, id);
static NSURLSessionDataTask *hooked_req(id self, SEL _cmd, NSURLRequest *req, id handler) {
    NSLog(@LOG_TAG "NSURLSession → %@", req.URL.absoluteString);
    return orig_req(self, _cmd, req, handler);
}

// ─── Constructor ─────────────────────────────────────────────────────────────

__attribute__((constructor)) static void initTweak(void) {
    NSLog(@LOG_TAG "=== XoaInfo Fake Auth Loaded ===");

    Class gw = objc_getClass("j2cyd0Nd");
    if (gw) {
        Method m = class_getInstanceMethod(gw,
            sel_registerName("b5Znk9Kh:q7C9eMnf:c7UND7t6:z0BQnrZN:"));
        if (m) {
            orig_b5Znk9Kh = (void(*)(id,SEL,id,id,id,id))method_getImplementation(m);
            method_setImplementation(m, (IMP)hooked_b5Znk9Kh);
            NSLog(@LOG_TAG "[OK] j2cyd0Nd gateway hooked");
        } else { NSLog(@LOG_TAG "[!] j2cyd0Nd method not found"); }
    } else { NSLog(@LOG_TAG "[!] j2cyd0Nd class not found"); }

    Class pref = objc_getClass("s7AcUOKf");
    if (pref) {
        Method m = class_getClassMethod(pref, sel_registerName("q3uTJBk1:"));
        if (m) {
            orig_q3uTJBk1 = (id(*)(id,SEL,id))method_getImplementation(m);
            method_setImplementation(m, (IMP)hooked_q3uTJBk1);
            NSLog(@LOG_TAG "[OK] s7AcUOKf preferences hooked");
        }
    }

    Class sess = objc_getClass("NSURLSession");
    if (sess) {
        Method m = class_getInstanceMethod(sess,
            sel_registerName("dataTaskWithRequest:completionHandler:"));
        if (m) {
            orig_req = (NSURLSessionDataTask*(*)(id,SEL,NSURLRequest*,id))method_getImplementation(m);
            method_setImplementation(m, (IMP)hooked_req);
            NSLog(@LOG_TAG "[OK] NSURLSession hooked (diagnostic)");
        }
    }
}
