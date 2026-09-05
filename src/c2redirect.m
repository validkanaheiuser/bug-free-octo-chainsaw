// c2redirect.m — XoaInfo Fake Auth (debug build)
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#include <dlfcn.h>

#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#define LOG_TAG "[XoaBypass] "

// ─── MSHookFunction via ElleKit (no link-time dependency) ────────────────────
// XoaInfo's state machine calls method_getImplementation and verifies the IMP
// matches the expected (pre-hook) value. method_setImplementation changes the
// IMP slot and triggers the anti-tamper. MSHookFunction patches only the
// function body, leaving the Method struct IMP unchanged → verifier passes.
typedef void (*MSHookFunction_t)(void *symbol, void *hook, void **old);
static MSHookFunction_t _mshook = NULL;

static void hookImp(Method m, void *hook, void **orig, const char *tag) {
    if (!m) { NSLog(@LOG_TAG "[!] hookImp: null Method for %s", tag); return; }
    void *imp = (void *)method_getImplementation(m);
    if (_mshook) {
        _mshook(imp, hook, orig);
        NSLog(@LOG_TAG "[MSHook] %s @ %p", tag, imp);
    } else {
        // Fallback (will trigger anti-tamper, but records fact for debugging)
        *orig = imp;
        method_setImplementation(m, (IMP)hook);
        NSLog(@LOG_TAG "[WARN method_setImpl fallback] %s", tag);
    }
}

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

    // x = device-specific hash (formula unknown; hardcoded for test device).
    // versionApp{x}.expDate must carry an actual date or XoaInfo shows blank.
    NSString *x = (ecid == 5393981226811438LL) ? @"58716dc8bad43e293b8d2d0f4f53b609"
                                                : md5Hex([NSString stringWithFormat:@"%lld", ecid]);
    NSString *plain = [NSString stringWithFormat:
        @"phase:%@|<>|version_run:10|<>|message:Good|<>|versionApp%@.expDate:2099-12-31 23:59:59|<>|",
        phase, x];

    NSLog(@LOG_TAG "team: ecid=%lld phase=%@ x=%@", ecid, phase, x);
    return rncryptEncrypt([plain dataUsingEncoding:NSUTF8StringEncoding], @"13981");
}

// ─── State for q69GFYW9 interception ─────────────────────────────────────────
static volatile long long g_loginipEcid  = 0;
static volatile long long g_loginipNonce = 0;
static volatile long long g_teamEcid     = 0;
static volatile long long g_teamNonce    = 0;  // derived from team checksum param (fallback if n2=0)
static volatile BOOL      g_teamPending  = NO;
// x = hash field from team params (e.g. "0a372322..."), stripped of "0x" and lowercased.
// Server keys versionApp{x}.expDate under this device hash, NOT md5(ecid).
static NSString          *g_teamX        = nil;

// ─── Hook: j2cyd0Nd gateway ───────────────────────────────────────────────────
static void (*orig_b5Znk9Kh)(id, SEL, id, id, id, id);

static void hooked_b5Znk9Kh(id self, SEL _cmd,
                              id params, id path, id successBlock, id failureBlock) {
    NSString *pathStr = [NSString stringWithFormat:@"%@", path];
    NSLog(@LOG_TAG "gateway: %@ successBlock=%p", pathStr, (__bridge void*)successBlock);

    if ([pathStr containsString:@"loginip"]) {
        long long ecid  = ecidFromSerialB64(params[@"serial"]);
        long long nonce = nonceFromChecksumB64(params[@"checksum"], ecid);
        g_loginipEcid  = ecid;
        g_loginipNonce = nonce;
        NSLog(@LOG_TAG "loginip: ecid=%lld nonce=%lld", ecid, nonce);
        // Pass nil — block calls q69GFYW9(empty, nonce), intercepted in hooked_dec_simple.
        callSuccessBlock(successBlock, nil);
        return;
    } else if ([pathStr containsString:@"team"] || [pathStr containsString:@"X2.1Public"]) {
        long long tecid = ecidFromSerialB64(params[@"serial"]);
        g_teamEcid    = tecid;
        g_teamNonce   = nonceFromChecksumB64(params[@"checksum"], tecid);
        g_teamPending = YES;
        // x = device hash from params — server keys versionApp{x}.expDate under this.
        // Strip "0x"/"0X" prefix and lowercase to match the key format.
        NSString *hashRaw = [NSString stringWithFormat:@"%@", params[@"hash"]];
        if ([hashRaw hasPrefix:@"0x"] || [hashRaw hasPrefix:@"0X"])
            hashRaw = [hashRaw substringFromIndex:2];
        g_teamX = [hashRaw lowercaseString];
        NSLog(@LOG_TAG "team: ecid=%lld teamNonce=%lld x=%@ user=%@ params=%@",
              g_teamEcid, g_teamNonce, g_teamX, params[@"user"], params);
        callSuccessBlock(successBlock, nil);
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
    else if ([k isEqualToString:@"Password"]) {
        // Return the current nonce — XoaInfo re-reads Password right after loginip
        // to verify it matches the nonce it used. "ase1" (old placeholder) fails
        // that check and triggers reboot(). g_loginipNonce is 0 before any loginip.
        if (g_loginipNonce > 0) { result = [NSString stringWithFormat:@"%lld", g_loginipNonce]; }
        else { spoofed = NO; result = orig_q3uTJBk1 ? orig_q3uTJBk1(self, _cmd, key) : nil; }
    }
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
    size_t len1 = [arg1 respondsToSelector:@selector(length)] ? [(NSData*)arg1 length] : 0;
    NSLog(@LOG_TAG "+c6chSi59:b5NuCqT9:password: arg1=%@/%zu pw='%@'",
          NSStringFromClass([arg1 class]), len1, pw);
    if ([arg1 isKindOfClass:[NSData class]] && len1 > 0)
        NSLog(@LOG_TAG "  arg1_b64=%.300@", [(NSData*)arg1 base64EncodedStringWithOptions:0]);
    else if ([arg1 isKindOfClass:[NSString class]])
        NSLog(@LOG_TAG "  arg1_str=%.300@", (NSString*)arg1);

    if (len1 == 0 && g_teamPending && g_teamEcid != 0) {
        g_teamPending = NO;
        long long ecid   = g_teamEcid;
        long long pnonce = (g_loginipNonce > 0) ? g_loginipNonce : [pw longLongValue];
        NSString *phase  = md5Hex([NSString stringWithFormat:@"%lld", ecid + 51739121LL * pnonce]);
        NSString *x      = g_teamX ?: md5Hex([NSString stringWithFormat:@"%lld", ecid]);
        NSString *plain = [NSString stringWithFormat:
            @"phase:%@|<>|version_run:10|<>|message:Good|<>|"
            @"versionApp%@.expDate:2099-12-31 23:59:59|<>|"
            @"encrypted:%@|<>|retention:%@|<>|deleteList:%@|<>|",
            phase, x,
            b64str(@"#!/bin/sh\nexit 0\n"),
            b64str(@"\n"),
            b64str(@"\n")];
        NSLog(@LOG_TAG "  -> fake team plain (pw path) ecid=%lld loginipNonce=%lld phase=%@ x=%@", ecid, pnonce, phase, x);
        return [plain dataUsingEncoding:NSUTF8StringEncoding];
    }

    NSData *res = orig_dec_pw(cls, _cmd, arg1, arg2, pw, err);
    if (err && *err) NSLog(@LOG_TAG "  error=%@", *err);
    NSLog(@LOG_TAG "  -> result len=%zu", res.length);
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
// q69GFYW9 returns decrypted content WITHOUT the 16-byte prefix (already stripped internally).
typedef NSData *(*DecryptSimple)(id, SEL, id, id, NSError **);
static DecryptSimple orig_dec_simple = NULL;
static NSData *hooked_dec_simple(id cls, SEL _cmd, id a1, id a2, NSError **err) {
    size_t len1 = [a1 respondsToSelector:@selector(length)] ? [(NSData*)a1 length] : 0;
    long long n2 = [a2 respondsToSelector:@selector(longLongValue)] ? [(id)a2 longLongValue] : 0;
    NSLog(@LOG_TAG "+c6chSi59:q69GFYW9: a1=%@/%zu a2=%lld",
          NSStringFromClass([a1 class]), len1, n2);
    if ([a1 isKindOfClass:[NSData class]] && len1 > 0)
        NSLog(@LOG_TAG "  a1_b64=%.200@", [(NSData*)a1 base64EncodedStringWithOptions:0]);

    // Intercept empty-ciphertext call — success block couldn't extract ciphertext (our fake path).
    // Return plaintext directly; q69GFYW9 normally returns content WITHOUT prefix.
    if (len1 == 0) {
        if (n2 > 0 && n2 == g_loginipNonce && g_loginipEcid != 0) {
            long long ecid = g_loginipEcid, nonce = g_loginipNonce;
            NSString *phase = md5Hex([NSString stringWithFormat:@"%lld", ecid + 51739121LL * nonce]);
            NSString *plain = [NSString stringWithFormat:
                @"expDate:2099-12-31 23:59:59|<>|phase:%@|<>|encrypted:%@|<>|"
                @"version_run:10|<>|message:Good|<>|retention:%@|<>|deleteList:%@|<>|",
                phase, b64str(@"#!/bin/sh\nexit 0\n"), b64str(@"\n"), b64str(@"\n")];
            NSLog(@LOG_TAG "  → fake loginip plain ecid=%lld nonce=%lld phase=%@", ecid, nonce, phase);
            return [plain dataUsingEncoding:NSUTF8StringEncoding];
        }
        if (g_teamPending && g_teamEcid != 0) {
            g_teamPending = NO;
            long long ecid   = g_teamEcid;
            // Use the actual nonce XoaInfo passes (n2); fall back to checksum-derived g_teamNonce.
            // XoaInfo computes MD5(ECID+51739121*pnonce) and compares with "phase:" field.
            long long pnonce = (n2 > 0) ? n2 : ((g_teamNonce > 0) ? g_teamNonce : ((g_loginipNonce > 0) ? g_loginipNonce : 1266394LL));
            NSString *phase  = md5Hex([NSString stringWithFormat:@"%lld", ecid + 51739121LL * pnonce]);
            NSString *x      = g_teamX ?: md5Hex([NSString stringWithFormat:@"%lld", ecid]);
            // Mirror loginip format: same encrypted/retention/deleteList fields.
            // XoaInfo rangeOfString:"encrypted:" on team response — missing → Packaged3=0.
            NSString *plain = [NSString stringWithFormat:
                @"phase:%@|<>|version_run:10|<>|message:Good|<>|"
                @"versionApp%@.expDate:2099-12-31 23:59:59|<>|"
                @"encrypted:%@|<>|retention:%@|<>|deleteList:%@|<>|",
                phase, x,
                b64str(@"#!/bin/sh\nexit 0\n"),
                b64str(@"\n"),
                b64str(@"\n")];
            NSLog(@LOG_TAG "  → fake team plain ecid=%lld n2=%lld teamNonce=%lld phase=%@ x=%@", ecid, n2, pnonce, phase, x);
            return [plain dataUsingEncoding:NSUTF8StringEncoding];
        }
    }

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

// ─── Hook: y8WisN9t streaming instance method ────────────────────────────────
// -[y8WisN9t c6chSi59:] = addData: (streaming RNCryptor).
// Returns void — must declare void to avoid ARC objc_retain crash on primitive.
typedef void (*StreamAddIMP)(id, SEL, id);
static StreamAddIMP orig_stream_add = NULL;
static void hooked_stream_add(id self, SEL _cmd, id data) {
    size_t len = [data respondsToSelector:@selector(length)] ? [(NSData*)data length] : 0;
    NSLog(@LOG_TAG "-[y8WisN9t c6chSi59:] addData len=%zu self=%p", len, (__bridge void*)self);
    if (len > 0 && len <= 4096 && [data isKindOfClass:[NSData class]])
        NSLog(@LOG_TAG "  data_b64=%.400@", [(NSData*)data base64EncodedStringWithOptions:0]);
    orig_stream_add(self, _cmd, data);
    NSLog(@LOG_TAG "-[y8WisN9t c6chSi59:] returned");
}

// ─── Hook: s7AcUOKf setter ────────────────────────────────────────────────────
typedef void (*PrefSet)(id, SEL, id, id);
static PrefSet orig_pref_set = NULL;
static void hooked_pref_set(id self, SEL _cmd, id value, id key) {
    NSString *k = [NSString stringWithFormat:@"%@", key];
    NSString *v = value ? [NSString stringWithFormat:@"%@", value] : @"nil";
    if (v.length > 120) v = [[v substringToIndex:120] stringByAppendingString:@"..."];
    NSLog(@LOG_TAG "pref_SET[%@] = %@", k, v);
    if (orig_pref_set) orig_pref_set(self, _cmd, value, key);
}

// ─── Hook: s7AcUOKf setA3JKER2u: ─────────────────────────────────────────────
typedef void (*LicenseSetter)(id, SEL, BOOL);
static LicenseSetter orig_license_set = NULL;
static void hooked_license_set(id self, SEL _cmd, BOOL val) {
    NSLog(@LOG_TAG ">>> setA3JKER2u:(%d) <<<", (int)val);
    if (orig_license_set) orig_license_set(self, _cmd, val);
}

// ─── Hook: NSURLSession — logging only, MSHookFunction to avoid anti-tamper ───
typedef void (^CompHandler)(NSData *, NSURLResponse *, NSError *);

typedef NSURLSessionDataTask *(*ReqIMP)(id, SEL, NSURLRequest *, CompHandler);
static ReqIMP orig_req = NULL;
static NSURLSessionDataTask *hooked_req(id self, SEL _cmd, NSURLRequest *req, CompHandler origHandler) {
    NSString *urlStr = req.URL.absoluteString;
    NSString *method = req.HTTPMethod ?: @"GET";
    NSLog(@LOG_TAG "NSURLSession_req: %@ %@", method, urlStr);
    // Log body if POST
    if (req.HTTPBody.length > 0 && req.HTTPBody.length < 2000) {
        NSString *bodyStr = [[NSString alloc] initWithData:req.HTTPBody encoding:NSUTF8StringEncoding];
        NSLog(@LOG_TAG "  body: %@", bodyStr ?: [req.HTTPBody base64EncodedStringWithOptions:0]);
    }
    // Pass through — completion handler block untouched to avoid ARC block-destructor crash
    return orig_req(self, _cmd, req, origHandler);
}

typedef NSURLSessionDataTask *(*ReqUrlIMP)(id, SEL, NSURL *, CompHandler);
static ReqUrlIMP orig_req_url = NULL;
static NSURLSessionDataTask *hooked_req_url(id self, SEL _cmd, NSURL *url, CompHandler origHandler) {
    NSLog(@LOG_TAG "NSURLSession_url: %@", url.absoluteString);
    return orig_req_url(self, _cmd, url, origHandler);
}

// ─── Constructor ─────────────────────────────────────────────────────────────
__attribute__((constructor)) static void initTweak(void) {
    NSLog(@LOG_TAG "=== XoaInfo Fake Auth Loaded (debug3) ===");

    // Resolve MSHookFunction from ElleKit (loaded as Depends: ellekit).
    // Using RTLD_DEFAULT searches all already-loaded dylibs — no link needed.
    _mshook = (MSHookFunction_t)dlsym(RTLD_DEFAULT, "MSHookFunction");
    if (_mshook) NSLog(@LOG_TAG "[OK] MSHookFunction resolved @ %p", (void*)_mshook);
    else         NSLog(@LOG_TAG "[!] MSHookFunction not found — fallback to method_setImpl (WILL trigger anti-tamper)");

    // j2cyd0Nd gateway
    Class gw = objc_getClass("j2cyd0Nd");
    if (gw) {
        Method m = class_getInstanceMethod(gw, sel_registerName("b5Znk9Kh:q7C9eMnf:c7UND7t6:z0BQnrZN:"));
        hookImp(m, (void*)hooked_b5Znk9Kh, (void**)&orig_b5Znk9Kh, "j2cyd0Nd gateway");
    } else { NSLog(@LOG_TAG "[!] j2cyd0Nd class not found"); }

    // s7AcUOKf preferences
    Class pref = objc_getClass("s7AcUOKf");
    if (pref) {
        Method m;
        m = class_getClassMethod(pref, sel_registerName("q3uTJBk1:"));
        hookImp(m, (void*)hooked_q3uTJBk1, (void**)&orig_q3uTJBk1, "s7AcUOKf q3uTJBk1:");

        m = class_getClassMethod(pref, sel_registerName("c2Uu7nHV:forKey:"));
        if (m) hookImp(m, (void*)hooked_pref_set, (void**)&orig_pref_set, "s7AcUOKf c2Uu7nHV:forKey:");
        else NSLog(@LOG_TAG "[!] c2Uu7nHV:forKey: not found");

        m = class_getClassMethod(pref, sel_registerName("setA3JKER2u:"));
        if (m) hookImp(m, (void*)hooked_license_set, (void**)&orig_license_set, "s7AcUOKf setA3JKER2u:");
        else NSLog(@LOG_TAG "[!] setA3JKER2u: not found");
    }

    // y8WisN9t = RNCryptor — hook all c6chSi59 class methods (NOT instance method — returns primitive)
    Class dec = objc_getClass("y8WisN9t");
    if (!dec) { NSLog(@LOG_TAG "[!] y8WisN9t not found"); goto skip_dec; }

    {
        Method m;
        m = class_getClassMethod(dec, sel_registerName("c6chSi59:b5NuCqT9:password:error:"));
        hookImp(m, (void*)hooked_dec_pw, (void**)&orig_dec_pw, "+c6chSi59:b5NuCqT9:password:");

        m = class_getClassMethod(dec, sel_registerName("c6chSi59:b5NuCqT9:d2ZmQPQj:r1FIQ6ln:error:"));
        hookImp(m, (void*)hooked_dec_kiv, (void**)&orig_dec_kiv, "+c6chSi59:b5NuCqT9:d2ZmQPQj:");

        m = class_getClassMethod(dec, sel_registerName("c6chSi59:q69GFYW9:error:"));
        hookImp(m, (void*)hooked_dec_simple, (void**)&orig_dec_simple, "+c6chSi59:q69GFYW9:");

        m = class_getClassMethod(dec, sel_registerName("c6chSi59:z4QMWDbr:r1FIQ6ln:error:"));
        hookImp(m, (void*)hooked_dec_iv, (void**)&orig_dec_iv, "+c6chSi59:z4QMWDbr:");

        // -[y8WisN9t c6chSi59:] instance method (streaming addData: — void return)
        m = class_getInstanceMethod(dec, sel_registerName("c6chSi59:"));
        if (m) hookImp(m, (void*)hooked_stream_add, (void**)&orig_stream_add, "-[y8WisN9t c6chSi59:]");
        else   NSLog(@LOG_TAG "[!] -[y8WisN9t c6chSi59:] instance not found");
    }
    skip_dec:;

    // NSURLSession — hook for logging only; use MSHookFunction to avoid ARC block-copy crashes
    // from method_setImplementation on a class-cluster method.
    Class sess = objc_getClass("NSURLSession");
    if (sess) {
        Method m;
        m = class_getInstanceMethod(sess, sel_registerName("dataTaskWithRequest:completionHandler:"));
        if (m) hookImp(m, (void*)hooked_req, (void**)&orig_req, "NSURLSession dataTaskWithRequest");
        m = class_getInstanceMethod(sess, sel_registerName("dataTaskWithURL:completionHandler:"));
        if (m) hookImp(m, (void*)hooked_req_url, (void**)&orig_req_url, "NSURLSession dataTaskWithURL");
    }

}
