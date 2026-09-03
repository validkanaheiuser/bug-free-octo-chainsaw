//
//  c2redirect.m
//  XoaInfo C2 Redirect & Analysis Hook
//
//  Reverse-engineered custom RNCryptor engine and local C2 mock response generator
//  for malware analysis in isolated laboratory environment.
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <CommonCrypto/CommonDigest.h>

#define LOG_TAG @"[XoaInfo-C2Redirect] "

#pragma mark - Cryptographic Helpers

static NSString *MD5String(NSString *str) {
    if (!str) return @"";
    const char *cStr = [str UTF8String];
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5(cStr, (CC_LONG)strlen(cStr), digest);
    NSMutableString *result = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) {
        [result appendFormat:@"%02x", digest[i]];
    }
    return result;
}

//
// Custom RNCryptor v3 Implementation:
// Header: [0x03, 0x01] + encSalt (8B) + hmacSalt (8B) + ivHeader (16B)
// Key Derivation:
//   salt1 = encSalt (8B) + hmacSalt (8B) = 16B
//   encKey = PBKDF2(PRF=HMAC-SHA512, pwd, salt1, rounds=10000, dklen=32)
//   salt2 = ivHeader (16B)
//   actualIV = PBKDF2(PRF=HMAC-SHA512, pwd, salt2, rounds=10000, dklen=16)
// Cipher:
//   AES-256-CBC, PKCS7 padding
// Trailer:
//   32 bytes trailing data (HMAC placeholder)
//
static NSData *CustomRNCryptor_Encrypt(NSString *password, NSString *plaintext) {
    if (!password || !plaintext) return nil;

    uint8_t encSalt[8];
    uint8_t hmacSalt[8];
    uint8_t ivHeader[16];
    arc4random_buf(encSalt, sizeof(encSalt));
    arc4random_buf(hmacSalt, sizeof(hmacSalt));
    arc4random_buf(ivHeader, sizeof(ivHeader));

    uint8_t salt1[16];
    memcpy(salt1, encSalt, 8);
    memcpy(salt1 + 8, hmacSalt, 8);

    const char *pwdStr = [password UTF8String];
    size_t pwdLen = strlen(pwdStr);

    // Derive 32-byte AES key
    uint8_t encKey[32];
    int status = CCKeyDerivationPBKDF(
        kCCPBKDF2,
        pwdStr,
        pwdLen,
        salt1,
        sizeof(salt1),
        kCCPRFHmacAlgSHA512,
        10000,
        encKey,
        sizeof(encKey)
    );
    if (status != kCCSuccess) {
        NSLog(LOG_TAG @"Error deriving encKey: %d", status);
        return nil;
    }

    // Derive 16-byte actual AES IV from ivHeader
    uint8_t actualIV[16];
    status = CCKeyDerivationPBKDF(
        kCCPBKDF2,
        pwdStr,
        pwdLen,
        ivHeader,
        sizeof(ivHeader),
        kCCPRFHmacAlgSHA512,
        10000,
        actualIV,
        sizeof(actualIV)
    );
    if (status != kCCSuccess) {
        NSLog(LOG_TAG @"Error deriving actualIV: %d", status);
        return nil;
    }

    NSData *plainData = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
    size_t cipherBufferSize = [plainData length] + kCCBlockSizeAES128;
    void *cipherBuffer = malloc(cipherBufferSize);
    size_t bytesEncrypted = 0;

    status = CCCrypt(
        kCCEncrypt,
        kCCAlgorithmAES128,
        kCCOptionPKCS7Padding,
        encKey,
        kCCKeySizeAES256,
        actualIV,
        [plainData bytes],
        [plainData length],
        cipherBuffer,
        cipherBufferSize,
        &bytesEncrypted
    );
    if (status != kCCSuccess) {
        NSLog(LOG_TAG @"Error during AES encryption: %d", status);
        free(cipherBuffer);
        return nil;
    }

    // Assemble raw packet
    NSMutableData *packet = [NSMutableData dataWithCapacity:2 + 8 + 8 + 16 + bytesEncrypted + 32];
    uint8_t prefix[2] = { 0x03, 0x01 };
    [packet appendBytes:prefix length:2];
    [packet appendBytes:encSalt length:8];
    [packet appendBytes:hmacSalt length:8];
    [packet appendBytes:ivHeader length:16];
    [packet appendBytes:cipherBuffer length:bytesEncrypted];
    free(cipherBuffer);

    // 32-byte trailer
    uint8_t trailer[32];
    arc4random_buf(trailer, sizeof(trailer));
    [packet appendBytes:trailer length:32];

    // Base64 encode to string as expected by XoaInfo
    NSString *base64Str = [packet base64EncodedStringWithOptions:0];
    return [base64Str dataUsingEncoding:NSUTF8StringEncoding];
}

#pragma mark - Response Synthesis

static NSData *SynthesizePhase1Response(NSDictionary *params) {
    NSLog(LOG_TAG @"Synthesizing Phase 1 response for params: %@", params);

    // 1. Extract HardwareID from decoded serial
    long long hardwareID = 5393981226811438LL; // fallback default
    NSString *serialB64 = params[@"serial"];
    if (serialB64) {
        NSData *serialData = [[NSData alloc] initWithBase64EncodedString:serialB64 options:0];
        if (serialData) {
            NSString *serialStr = [[NSString alloc] initWithData:serialData encoding:NSUTF8StringEncoding];
            NSArray *parts = [serialStr componentsSeparatedByString:@"|"];
            if ([parts count] >= 3) {
                hardwareID = [parts[2] longLongValue];
                NSLog(LOG_TAG @"Extracted hardwareID from serial: %lld", hardwareID);
            }
        }
    }

    // 2. Extract nonce from decoded checksum: checksum = hardwareID + 124457 * nonce
    long long nonce = 1266394LL; // fallback
    NSString *checksumB64 = params[@"checksum"];
    if (checksumB64) {
        NSData *checksumData = [[NSData alloc] initWithBase64EncodedString:checksumB64 options:0];
        if (checksumData) {
            NSString *checksumStr = [[NSString alloc] initWithData:checksumData encoding:NSUTF8StringEncoding];
            long long checksumVal = [checksumStr longLongValue];
            if (checksumVal > hardwareID) {
                nonce = (checksumVal - hardwareID) / 124457LL;
                NSLog(LOG_TAG @"Derived nonce: %lld (from checksum: %lld)", nonce, checksumVal);
            }
        }
    }

    // 3. Compute phase = md5(hardwareID + 51739121 * nonce)
    long long phaseVal = hardwareID + 51739121LL * nonce;
    NSString *phaseStr = MD5String([NSString stringWithFormat:@"%lld", phaseVal]);
    NSLog(LOG_TAG @"Computed valid phase: %@", phaseStr);

    // 4. Safe benign research payloads (does NOT infect or wipe research device!)
    // Base64 of "#!/bin/sh\nexit 0\n"
    NSString *safeDropper = @"IyEvYmluL3NoCmV4aXQgMAo=";
    // Empty safe lists
    NSString *safeRetention = @"Cg==";
    NSString *safeDeleteList = @"Cg==";

    NSString *plaintext = [NSString stringWithFormat:
        @"expDate:2099-12-31 23:59:59|<>|"
        @"phase:%@|<>|"
        @"encrypted:%@|<>|"
        @"version_run:10|<>|"
        @"message:Good (Active Research Bypass)|<>|"
        @"retention:%@|<>|"
        @"deleteList:%@|<>|",
        phaseStr, safeDropper, safeRetention, safeDeleteList];

    NSString *password = [NSString stringWithFormat:@"%lld", nonce];
    NSData *encryptedResponse = CustomRNCryptor_Encrypt(password, plaintext);
    NSLog(LOG_TAG @"Generated Phase 1 encrypted payload (%lu bytes)", (unsigned long)[encryptedResponse length]);
    return encryptedResponse;
}

static NSData *SynthesizePhase2Response(NSDictionary *params) {
    NSLog(LOG_TAG @"Synthesizing Phase 2 (Team/Function verification) response");
    // Pre-encrypted valid phase 2 response (matches exact token accepted by binary)
    NSString *phase2B64 = @"AwHLLIAjcqPU9kyy8sYdUvb5qm7/bMiAOJkYS5UewFVQ2MVknUlvikHEfXxPXEn0iT8je0NwRcmt/P/vZzWYN5Zw1vl4c7+xaL1bL+euW5uJzsvGj25cb+m/Kgm1z/ZIgdSmUwkgvueFop4FfT8tgraonj6FgX4DwUjJ4D/MIIDPy5DFoVJ79j711wnB19I9Et8qPAiNsewjZ9DAHY37zoURJ5jEEBUJFuSbEQi2Z9/LyfLuSEyvYW8XJtQ4WbJkDDJ/LtQW3wxeSpDqDVnxGEkOlpM4jilAxJVwcown+TwOYuNEGqtzy8Wj0gGnXZjL5lsz5d89f5BN21CsEAyN0giY";
    return [phase2B64 dataUsingEncoding:NSUTF8StringEncoding];
}

#pragma mark - Hooks: j2cyd0Nd

static void (*orig_b5Znk9Kh)(id self, SEL _cmd, id params, id path, id successBlock, id failureBlock);

static void hooked_b5Znk9Kh(id self, SEL _cmd, id params, id path, id successBlock, id failureBlock) {
    NSString *pathStr = [NSString stringWithFormat:@"%@", path];
    NSLog(LOG_TAG @"Intercepted network gateway call to path: %@", pathStr);

    if ([pathStr containsString:@"loginip"] || [pathStr containsString:@"redeem"]) {
        NSLog(LOG_TAG @"Handling Phase 1 Login request locally...");
        NSData *response = SynthesizePhase1Response((NSDictionary *)params);
        if (successBlock && response) {
            void (^success)(id, int, id) = (void (^)(id, int, id))successBlock;
            dispatch_async(dispatch_get_main_queue(), ^{
                success(nil, 200, response);
            });
            return;
        }
    } else if ([pathStr containsString:@"team"] || [pathStr containsString:@"X2.1Public"]) {
        NSLog(LOG_TAG @"Handling Phase 2 Function Verification request locally...");
        NSData *response = SynthesizePhase2Response((NSDictionary *)params);
        if (successBlock && response) {
            void (^success)(id, int, id) = (void (^)(id, int, id))successBlock;
            dispatch_async(dispatch_get_main_queue(), ^{
                success(nil, 200, response);
            });
            return;
        }
    }

    if (orig_b5Znk9Kh) {
        orig_b5Znk9Kh(self, _cmd, params, path, successBlock, failureBlock);
    }
}

#pragma mark - Hooks: NSURLSession (Low-level Interceptor)

static NSURLSessionDataTask *(*orig_dataTaskWithRequest)(id self, SEL _cmd, NSURLRequest *request, id completionHandler);

static NSURLSessionDataTask *hooked_dataTaskWithRequest(id self, SEL _cmd, NSURLRequest *request, id completionHandler) {
    NSString *urlStr = [[request URL] absoluteString];
    if ([urlStr containsString:@"xoainfo"] || [urlStr containsString:@"125.212.220.224"]) {
        NSLog(LOG_TAG @"Intercepted low-level NSURLSession request to: %@", urlStr);
        if (completionHandler) {
            void (^handler)(NSData *, NSURLResponse *, NSError *) = (void (^)(NSData *, NSURLResponse *, NSError *))completionHandler;
            NSData *responseBody = nil;
            if ([urlStr containsString:@"loginip"]) {
                responseBody = SynthesizePhase1Response(nil);
            } else {
                responseBody = SynthesizePhase2Response(nil);
            }

            NSHTTPURLResponse *httpResponse = [[NSHTTPURLResponse alloc] initWithURL:[request URL]
                                                                          statusCode:200
                                                                         HTTPVersion:@"HTTP/1.1"
                                                                        headerFields:@{@"Content-Type": @"text/html; charset=UTF-8"}];
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                handler(responseBody, httpResponse, nil);
            });
        }
        return nil;
    }

    if (orig_dataTaskWithRequest) {
        return orig_dataTaskWithRequest(self, _cmd, request, completionHandler);
    }
    return nil;
}

#pragma mark - Hooks: Preference & License Overrides

static id (*orig_q3uTJBk1)(id self, SEL _cmd, id key);

static id hooked_q3uTJBk1(id self, SEL _cmd, id key) {
    NSString *keyStr = [NSString stringWithFormat:@"%@", key];
    if ([keyStr isEqualToString:@"RunVersion"]) {
        return @"10"; // Fully authorized execution mode
    }
    if ([keyStr isEqualToString:@"Password"]) {
        return @"ase1";
    }
    if (orig_q3uTJBk1) {
        return orig_q3uTJBk1(self, _cmd, key);
    }
    return nil;
}

#pragma mark - Tweak Initialization

__attribute__((constructor)) static void initTweak(void) {
    NSLog(LOG_TAG @"=== XoaInfo Security Research C2 Redirect Loaded ===");

    // 1. Hook Gateway Class j2cyd0Nd
    Class gatewayCls = objc_getClass("j2cyd0Nd");
    if (gatewayCls) {
        SEL selGateway = sel_registerName("b5Znk9Kh:q7C9eMnf:c7UND7t6:z0BQnrZN:");
        Method mGateway = class_getInstanceMethod(gatewayCls, selGateway);
        if (mGateway) {
            orig_b5Znk9Kh = (void (*)(id, SEL, id, id, id, id))method_getImplementation(mGateway);
            method_setImplementation(mGateway, (IMP)hooked_b5Znk9Kh);
            NSLog(LOG_TAG @"Successfully hooked j2cyd0Nd b5Znk9Kh:q7C9eMnf:c7UND7t6:z0BQnrZN:");
        }
    }

    // 2. Hook Preferences Class s7AcUOKf
    Class prefCls = objc_getClass("s7AcUOKf");
    if (prefCls) {
        SEL selPref = sel_registerName("q3uTJBk1:");
        Method mPref = class_getClassMethod(prefCls, selPref);
        if (mPref) {
            orig_q3uTJBk1 = (id (*)(id, SEL, id))method_getImplementation(mPref);
            method_setImplementation(mPref, (IMP)hooked_q3uTJBk1);
            NSLog(LOG_TAG @"Successfully hooked s7AcUOKf q3uTJBk1:");
        }
    }

    // 3. Hook NSURLSession dataTaskWithRequest:completionHandler:
    Class sessionCls = objc_getClass("NSURLSession");
    if (sessionCls) {
        SEL selSession = sel_registerName("dataTaskWithRequest:completionHandler:");
        Method mSession = class_getInstanceMethod(sessionCls, selSession);
        if (mSession) {
            orig_dataTaskWithRequest = (NSURLSessionDataTask *(*)(id, SEL, NSURLRequest *, id))method_getImplementation(mSession);
            method_setImplementation(mSession, (IMP)hooked_dataTaskWithRequest);
            NSLog(LOG_TAG @"Successfully hooked NSURLSession dataTaskWithRequest:completionHandler:");
        }
    }

    NSLog(LOG_TAG @"Initialization complete. All C2 communication will be intercepted and resolved locally.");
}
