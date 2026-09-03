// c2redirect.m — XoaInfo Fake Auth
// Intercepts /loginip and /team only; builds correct encrypted fake responses.
// Everything else passes through untouched.

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <CommonCrypto/CommonDigest.h>

#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#define LOG_TAG "[XoaBypass] "

// ─── Param parsing ────────────────────────────────────────────────────────────

static NSDictionary *parseParams(NSURLRequest *req) {
    NSMutableDictionary *d = [NSMutableDictionary dictionary];
    NSString *src = nil;
    if (req.HTTPBody)
        src = [[NSString alloc] initWithData:req.HTTPBody encoding:NSUTF8StringEncoding];
    if (!src) src = req.URL.query;
    if (!src) return d;
    for (NSString *pair in [src componentsSeparatedByString:@"&"]) {
        NSArray *kv = [pair componentsSeparatedByString:@"="];
        if (kv.count >= 2) {
            NSString *val = [kv[1] stringByRemovingPercentEncoding];
            if (kv[0] && val) d[kv[0]] = val;
        }
    }
    return d;
}

// serial param = base64("SerialNum|MAC1|ECID|MAC2")
static long long ecidFromSerial(NSString *b64) {
    if (!b64) return 1LL;
    b64 = [b64 stringByReplacingOccurrencesOfString:@"%2B" withString:@"+"];
    b64 = [b64 stringByReplacingOccurrencesOfString:@"%3D" withString:@"="];
    NSData *d = [[NSData alloc] initWithBase64EncodedString:b64 options:0];
    if (!d) return 1LL;
    NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
    NSArray *parts = [s componentsSeparatedByString:@"|"];
    return parts.count >= 3 ? [parts[2] longLongValue] : 1LL;
}

// checksum param = base64(str(ECID + 124457 * nonce))
static long long nonceFromChecksum(NSString *b64, long long ecid) {
    if (!b64) return 1266394LL;
    b64 = [b64 stringByReplacingOccurrencesOfString:@"%2B" withString:@"+"];
    b64 = [b64 stringByReplacingOccurrencesOfString:@"%3D" withString:@"="];
    NSData *d = [[NSData alloc] initWithBase64EncodedString:b64 options:0];
    if (!d) return 1266394LL;
    long long val = [[[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] longLongValue];
    return val > ecid ? (val - ecid) / 124457LL : 1266394LL;
}

static NSString *md5Hex(NSString *s) {
    const char *cs = [s UTF8String];
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5(cs, (CC_LONG)strlen(cs), digest);
    NSMutableString *r = [NSMutableString stringWithCapacity:32];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) [r appendFormat:@"%02x", digest[i]];
    return r;
}

// ─── Custom RNCryptor encrypt ─────────────────────────────────────────────────
// encKey   = PBKDF2(pw, encSalt+hmacSalt, SHA512, 10000, 32)
// actualIV = PBKDF2(pw, ivHeader, SHA512, 10000, 16)
// blob     = 0x03 0x01 | encSalt(8) | hmacSalt(8) | ivHeader(16) | ciphertext | zeros(64)

static NSData *rncryptEncrypt(NSData *plain, NSString *password) {
    const char *pw = [password UTF8String];
    size_t pwLen   = strlen(pw);

    uint8_t encSalt[8], hmacSalt[8], ivHeader[16];
    arc4random_buf(encSalt, 8);
    arc4random_buf(hmacSalt, 8);
    arc4random_buf(ivHeader, 16);

    uint8_t combinedSalt[16];
    memcpy(combinedSalt, encSalt, 8);
    memcpy(combinedSalt + 8, hmacSalt, 8);

    uint8_t encKey[32], actualIV[16];
    CCKeyDerivationPBKDF(kCCPBKDF2, pw, pwLen, combinedSalt, 16, kCCPRFHmacAlgSHA512, 10000, encKey, 32);
    CCKeyDerivationPBKDF(kCCPBKDF2, pw, pwLen, ivHeader,     16, kCCPRFHmacAlgSHA512, 10000, actualIV, 16);

    size_t ctBufLen = plain.length + kCCBlockSizeAES128;
    void *ctBuf = malloc(ctBufLen);
    size_t ctLen = 0;
    CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
            encKey, 32, actualIV,
            plain.bytes, plain.length,
            ctBuf, ctBufLen, &ctLen);

    NSMutableData *blob = [NSMutableData dataWithCapacity:2+8+8+16+ctLen+64];
    uint8_t hdr[2] = {0x03, 0x01};
    [blob appendBytes:hdr        length:2];
    [blob appendBytes:encSalt    length:8];
    [blob appendBytes:hmacSalt   length:8];
    [blob appendBytes:ivHeader   length:16];
    [blob appendBytes:ctBuf      length:ctLen];
    free(ctBuf);
    uint8_t trailer[64] = {0};
    [blob appendBytes:trailer length:64];
    return blob;
}

// Prepend 16 random bytes before plaintext (real C2 blob format)
static NSData *withPrefix(NSString *plainStr) {
    NSMutableData *d = [NSMutableData dataWithLength:16];
    arc4random_buf(d.mutableBytes, 16);
    [d appendData:[plainStr dataUsingEncoding:NSUTF8StringEncoding]];
    return d;
}

static NSString *b64str(NSString *s) {
    return [[s dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];
}

// ─── Response builders ────────────────────────────────────────────────────────

static NSData *buildLoginipResponse(long long ecid, long long nonce) {
    NSString *phase = md5Hex([NSString stringWithFormat:@"%lld", ecid + 51739121LL * nonce]);

    NSString *script    = b64str(@"#!/bin/bash\nkillall -9 MobileSafari\n");
    NSString *retention = b64str(@"/private/var/Keychains/keychain-2.db");
    NSString *delList   = b64str(@"/private/var/mobile/Library/Cookies/Cookies.binarycookies");

    NSString *plain = [NSString stringWithFormat:
        @"expDate:2099-12-31 23:59:59|<>|phase:%@|<>|encrypted:%@|<>|"
        @"version_run:10|<>|message:Good|<>|retention:%@|<>|deleteList:%@|<>|",
        phase, script, retention, delList];

    NSData *encrypted = rncryptEncrypt(withPrefix(plain),
                                       [NSString stringWithFormat:@"%lld", nonce]);
    // Response body = base64 of the encrypted blob (as UTF-8 bytes)
    return [[encrypted base64EncodedStringWithOptions:0] dataUsingEncoding:NSUTF8StringEncoding];
}

static NSData *buildTeamResponse(long long ecid) {
    const long long teamV19 = 13981LL;
    NSString *phase = md5Hex([NSString stringWithFormat:@"%lld", ecid + 51739121LL * teamV19]);

    // Known X table (ECID → versionApp key)
    NSString *x = nil;
    if (ecid == 5393981226811438LL) x = @"58716dc8bad43e293b8d2d0f4f53b609";

    NSString *vaEntry = x ? [NSString stringWithFormat:
        @"|<>|versionApp%@.expDate:2099-12-31 23:59:59", x] : @"";

    NSString *plain = [NSString stringWithFormat:
        @"phase:%@|<>|version_run:10|<>|message:Good%@", phase, vaEntry];

    NSData *encrypted = rncryptEncrypt(withPrefix(plain), @"13981");
    return [[encrypted base64EncodedStringWithOptions:0] dataUsingEncoding:NSUTF8StringEncoding];
}

// ─── NSURLSession hook ────────────────────────────────────────────────────────

static NSURLSessionDataTask *(*orig_dataTask)(id, SEL, NSURLRequest *, id);

static NSURLSessionDataTask *hooked_dataTask(id self, SEL _cmd,
                                              NSURLRequest *request, id completionHandler) {
    NSString *path = request.URL.path;
    BOOL isLogin = [path containsString:@"loginip"];
    BOOL isTeam  = [path containsString:@"team"] || [path containsString:@"X2.1Public"];

    if (isLogin || isTeam) {
        NSLog(@LOG_TAG "Intercepted: %@", path);
        NSDictionary *params = parseParams(request);
        long long ecid = ecidFromSerial(params[@"serial"]);

        NSData *body = isLogin
            ? buildLoginipResponse(ecid, nonceFromChecksum(params[@"checksum"], ecid))
            : buildTeamResponse(ecid);

        if (body && completionHandler) {
            NSURL *url = request.URL;
            void (^handler)(NSData *, NSURLResponse *, NSError *) =
                (void (^)(NSData *, NSURLResponse *, NSError *))completionHandler;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 200 * NSEC_PER_MSEC),
                           dispatch_get_global_queue(0, 0), ^{
                NSHTTPURLResponse *resp = [[NSHTTPURLResponse alloc]
                    initWithURL:url statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:nil];
                handler(body, resp, nil);
            });
        }

        // Return a dummy cancelled task so callers can safely call [task resume]
        NSURLRequest *dummy = [NSURLRequest requestWithURL:[NSURL URLWithString:@"http://127.0.0.1:9/"]];
        NSURLSessionDataTask *task = orig_dataTask(self, _cmd, dummy, ^(NSData *d, NSURLResponse *r, NSError *e){});
        [task cancel];
        return task;
    }

    return orig_dataTask(self, _cmd, request, completionHandler);
}

// ─── Constructor ─────────────────────────────────────────────────────────────

__attribute__((constructor)) static void initTweak(void) {
    NSLog(@LOG_TAG "=== XoaInfo Fake Auth Loaded ===");
    Class sessCls = objc_getClass("NSURLSession");
    if (!sessCls) return;
    SEL sel = sel_registerName("dataTaskWithRequest:completionHandler:");
    Method m = class_getInstanceMethod(sessCls, sel);
    if (!m) return;
    orig_dataTask = (NSURLSessionDataTask *(*)(id, SEL, NSURLRequest *, id))method_getImplementation(m);
    method_setImplementation(m, (IMP)hooked_dataTask);
    NSLog(@LOG_TAG "[OK] NSURLSession hooked — intercepting /loginip and /team only");
}
