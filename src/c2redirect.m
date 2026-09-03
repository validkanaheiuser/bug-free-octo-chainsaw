//
//  c2redirect.m
//  XoaInfo Standalone On-Device Bypass & C2 Response Synthesizer
//
//  100% Standalone - NO PC, NO Wi-Fi, NO Proxy, NO Mock Server needed!
//  Fixed Block Calling Convention (ABI register alignment for ARM64).
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <CommonCrypto/CommonDigest.h>
#import <SystemConfiguration/SystemConfiguration.h>

#define LOG_TAG @"[XoaInfo-StandaloneBypass] "

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
// Custom RNCryptor Engine (Reversed from XoaInfo malware)
//
static NSData *CustomRNCryptor_Encrypt(NSString *password, NSString *plaintext) {
    if (!password || !plaintext) return nil;

    uint8_t encSalt[8];
    uint8_t hmacSalt[8];
    uint8_t ivHeader[16];
    arc4random_buf(encSalt, sizeof(encSalt));
    arc4random_buf(hmacSalt, sizeof(hmacSalt));
    arc4random_buf(ivHeader, sizeof(ivHeader));

    // salt1 = encSalt (8) + hmacSalt (8) = 16 bytes
    uint8_t salt1[16];
    memcpy(salt1, encSalt, 8);
    memcpy(salt1 + 8, hmacSalt, 8);

    const char *pwdStr = [password UTF8String];
    size_t pwdLen = strlen(pwdStr);

    // 1. Derive 32-byte AES key via PBKDF2 HMAC-SHA512 (10,000 rounds)
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

    // 2. Derive 16-byte actual AES IV from ivHeader via PBKDF2 HMAC-SHA512 (10,000 rounds)
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

    // 3. Encrypt plaintext with AES-256-CBC, PKCS7 padding
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

    // 4. Assemble wire packet:
    // [0x03, 0x01] + encSalt (8) + hmacSalt (8) + ivHeader (16) + ciphertext + trailer (32)
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

    // 5. Base64 encode string to NSData
    NSString *base64Str = [packet base64EncodedStringWithOptions:0];
    return [base64Str dataUsingEncoding:NSUTF8StringEncoding];
}

#pragma mark - On-Device Dynamic Response Synthesis

static NSData *SynthesizePhase1Response(NSDictionary *params) {
    NSLog(LOG_TAG @"[Phase 1] Intercepted on-device Login request. Synthesizing valid response...");

    // 1. Extract HardwareID from serial (or live device query)
    long long hardwareID = 5393981226811438LL;
    NSString *serialB64 = params[@"serial"];
    if (serialB64) {
        NSData *serialData = [[NSData alloc] initWithBase64EncodedString:serialB64 options:0];
        if (serialData) {
            NSString *serialStr = [[NSString alloc] initWithData:serialData encoding:NSUTF8StringEncoding];
            NSArray *parts = [serialStr componentsSeparatedByString:@"|"];
            if ([parts count] >= 3) {
                hardwareID = [parts[2] longLongValue];
            }
        }
    }

    // 2. Extract nonce from checksum: checksum_val = hardwareID + 124457 * nonce
    long long nonce = 1266394LL;
    NSString *checksumB64 = params[@"checksum"];
    if (checksumB64) {
        NSData *checksumData = [[NSData alloc] initWithBase64EncodedString:checksumB64 options:0];
        if (checksumData) {
            NSString *checksumStr = [[NSString alloc] initWithData:checksumData encoding:NSUTF8StringEncoding];
            long long checksumVal = [checksumStr longLongValue];
            if (checksumVal > hardwareID) {
                nonce = (checksumVal - hardwareID) / 124457LL;
            }
        }
    }

    // 3. Compute phase = md5(hardwareID + 51739121 * nonce)
    long long phaseVal = hardwareID + 51739121LL * nonce;
    NSString *phaseStr = MD5String([NSString stringWithFormat:@"%lld", phaseVal]);

    NSLog(LOG_TAG @"[Phase 1] Nonce=%lld, HardwareID=%lld, Computed Phase Token=%@", nonce, hardwareID, phaseStr);

    // 4. Neutralized safe payload (Prevents wiping Keychains or dropping remote backdoors)
    NSString *safeDropper = @"IyEvYmluL3NoCmV4aXQgMAo="; // #!/bin/sh\nexit 0\n
    NSString *safeRetention = @"Cg==";
    NSString *safeDeleteList = @"Cg==";

    NSString *plaintext = [NSString stringWithFormat:
        @"expDate:2099-12-31 23:59:59|<>|"
        @"phase:%@|<>|"
        @"encrypted:%@|<>|"
        @"version_run:10|<>|"
        @"message:Good (Standalone On-Device Bypass Active)|<>|"
        @"retention:%@|<>|"
        @"deleteList:%@|<>|",
        phaseStr, safeDropper, safeRetention, safeDeleteList];

    NSString *password = [NSString stringWithFormat:@"%lld", nonce];
    NSData *encryptedResponse = CustomRNCryptor_Encrypt(password, plaintext);
    NSLog(LOG_TAG @"[Phase 1] Successfully generated Custom RNCryptor response in memory (%lu bytes)!", (unsigned long)[encryptedResponse length]);
    return encryptedResponse;
}

static NSData *SynthesizePhase2Response(NSDictionary *params) {
    NSLog(LOG_TAG @"[Phase 2] Intercepted on-device Function Verification request.");
    // Pre-encrypted valid Phase 2 token matching exact binary authorization
    NSString *phase2B64 = @"AwHLLIAjcqPU9kyy8sYdUvb5qm7/bMiAOJkYS5UewFVQ2MVknUlvikHEfXxPXEn0iT8je0NwRcmt/P/vZzWYN5Zw1vl4c7+xaL1bL+euW5uJzsvGj25cb+m/Kgm1z/ZIgdSmUwkgvueFop4FfT8tgraonj6FgX4DwUjJ4D/MIIDPy5DFoVJ79j711wnB19I9Et8qPAiNsewjZ9DAHY37zoURJ5jEEBUJFuSbEQi2Z9/LyfLuSEyvYW8XJtQ4WbJkDDJ/LtQW3wxeSpDqDVnxGEkOlpM4jilAxJVwcown+TwOYuNEGqtzy8Wj0gGnXZjL5lsz5d89f5BN21CsEAyN0giY";
    return [phase2B64 dataUsingEncoding:NSUTF8StringEncoding];
}

#pragma mark - Hook: j2cyd0Nd (UI Network Gateway)

static void (*orig_b5Znk9Kh)(id self, SEL _cmd, id params, id path, id successBlock, id failureBlock);

static void hooked_b5Znk9Kh(id self, SEL _cmd, id params, id path, id successBlock, id failureBlock) {
    NSString *pathStr = [NSString stringWithFormat:@"%@", path];
    NSLog(LOG_TAG @"j2cyd0Nd gateway called for path: %@", pathStr);

    if ([pathStr containsString:@"loginip"] || [pathStr containsString:@"redeem"]) {
        NSData *response = SynthesizePhase1Response((NSDictionary *)params);
        if (successBlock && response) {
            dispatch_async(dispatch_get_main_queue(), ^{
                @try {
                    NSLog(LOG_TAG @"Dispatching synthesized response into successBlock...");
                    //
                    // CRITICAL ABI FIX:
                    // In ARM64, the block implementation sub_1006A77C0 reads register X2 as the response NSData!
                    // Calling (response, response) places response into BOTH X1 and X2, completely eliminating
                    // register mismatch and preventing objc_retain crash on invalid status codes!
                    //
                    void (^block)(id, id) = (void (^)(id, id))successBlock;
                    block(response, response);
                    NSLog(LOG_TAG @"[SUCCESS] successBlock executed cleanly without errors!");
                } @catch (NSException *ex) {
                    NSLog(LOG_TAG @"Exception calling successBlock: %@", ex);
                }
            });
            return;
        }
    } else if ([pathStr containsString:@"team"] || [pathStr containsString:@"X2.1Public"]) {
        NSData *response = SynthesizePhase2Response((NSDictionary *)params);
        if (successBlock && response) {
            dispatch_async(dispatch_get_main_queue(), ^{
                @try {
                    NSLog(LOG_TAG @"Dispatching Phase 2 response into successBlock...");
                    void (^block)(id, id) = (void (^)(id, id))successBlock;
                    block(response, response);
                    NSLog(LOG_TAG @"[SUCCESS] Phase 2 block executed cleanly!");
                } @catch (NSException *ex) {
                    NSLog(LOG_TAG @"Exception in Phase 2 block: %@", ex);
                }
            });
            return;
        }
    }

    if (orig_b5Znk9Kh) {
        orig_b5Znk9Kh(self, _cmd, params, path, successBlock, failureBlock);
    }
}

#pragma mark - Hook: NSURLSession (Low-level In-Memory Interceptor)

static NSURLSessionDataTask *(*orig_dataTaskWithRequest)(id self, SEL _cmd, NSURLRequest *request, id completionHandler);

static NSURLSessionDataTask *hooked_dataTaskWithRequest(id self, SEL _cmd, NSURLRequest *request, id completionHandler) {
    NSString *urlStr = [[request URL] absoluteString];
    if ([urlStr containsString:@"xoainfo"] || [urlStr containsString:@"125.212.220.224"]) {
        NSLog(LOG_TAG @"Intercepted NSURLSession call to C2: %@", urlStr);
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

#pragma mark - Hook: c5p96gdE (Login View Controller auto-fill)

static void (*orig_n56shZcq)(id self, SEL _cmd, id password);

static void hooked_n56shZcq(id self, SEL _cmd, id password) {
    NSString *pwd = (NSString *)password;
    if (!pwd || [pwd length] == 0) {
        pwd = @"ase1";
        NSLog(LOG_TAG @"Auto-filled password 'ase1'");
    }
    if (orig_n56shZcq) {
        orig_n56shZcq(self, _cmd, pwd);
    }
}

#pragma mark - Hook: Preference & Authorization Overrides

static id (*orig_q3uTJBk1)(id self, SEL _cmd, id key);

static id hooked_q3uTJBk1(id self, SEL _cmd, id key) {
    NSString *keyStr = [NSString stringWithFormat:@"%@", key];
    if ([keyStr isEqualToString:@"RunVersion"]) {
        return @"10"; // Authorized mode
    }
    if ([keyStr isEqualToString:@"Password"]) {
        return @"ase1";
    }
    if (orig_q3uTJBk1) {
        id val = orig_q3uTJBk1(self, _cmd, key);
        if (!val) {
            if ([keyStr isEqualToString:@"realModel"]) return @"iPhone10,3";
            if ([keyStr isEqualToString:@"realInterModel"]) return @"D22AP";
        }
        return val;
    }
    return nil;
}

#pragma mark - Hook: Offline Reachability Simulation

static BOOL hooked_isReachable(id self, SEL _cmd) {
    return YES;
}

#pragma mark - Tweak Constructor

__attribute__((constructor)) static void initTweak(void) {
    NSLog(LOG_TAG @"=== XoaInfo 100%% Standalone On-Device Bypass Loaded ===");

    // 1. Hook Gateway Class j2cyd0Nd
    Class gatewayCls = objc_getClass("j2cyd0Nd");
    if (gatewayCls) {
        SEL sel = sel_registerName("b5Znk9Kh:q7C9eMnf:c7UND7t6:z0BQnrZN:");
        Method m = class_getInstanceMethod(gatewayCls, sel);
        if (m) {
            orig_b5Znk9Kh = (void (*)(id, SEL, id, id, id, id))method_getImplementation(m);
            method_setImplementation(m, (IMP)hooked_b5Znk9Kh);
            NSLog(LOG_TAG @"[OK] Hooked j2cyd0Nd gateway");
        }
    }

    // 2. Hook Preferences Class s7AcUOKf
    Class prefCls = objc_getClass("s7AcUOKf");
    if (prefCls) {
        SEL sel = sel_registerName("q3uTJBk1:");
        Method m = class_getClassMethod(prefCls, sel);
        if (m) {
            orig_q3uTJBk1 = (id (*)(id, SEL, id))method_getImplementation(m);
            method_setImplementation(m, (IMP)hooked_q3uTJBk1);
            NSLog(LOG_TAG @"[OK] Hooked s7AcUOKf preferences");
        }
    }

    // 3. Hook Login View Controller c5p96gdE
    Class loginVCCls = objc_getClass("c5p96gdE");
    if (loginVCCls) {
        SEL sel = sel_registerName("n56shZcq:");
        Method m = class_getInstanceMethod(loginVCCls, sel);
        if (m) {
            orig_n56shZcq = (void (*)(id, SEL, id))method_getImplementation(m);
            method_setImplementation(m, (IMP)hooked_n56shZcq);
            NSLog(LOG_TAG @"[OK] Hooked c5p96gdE login action");
        }
    }

    // 4. Hook Reachability to simulate online connection in Airplane mode
    Class reachCls = objc_getClass("p4m7JskN");
    if (reachCls) {
        SEL sel = sel_registerName("isReachable");
        Method m = class_getInstanceMethod(reachCls, sel);
        if (m) {
            method_setImplementation(m, (IMP)hooked_isReachable);
            NSLog(LOG_TAG @"[OK] Hooked Reachability (p4m7JskN isReachable)");
        }
    }

    // 5. Hook NSURLSession
    Class sessionCls = objc_getClass("NSURLSession");
    if (sessionCls) {
        SEL sel = sel_registerName("dataTaskWithRequest:completionHandler:");
        Method m = class_getInstanceMethod(sessionCls, sel);
        if (m) {
            orig_dataTaskWithRequest = (NSURLSessionDataTask *(*)(id, SEL, NSURLRequest *, id))method_getImplementation(m);
            method_setImplementation(m, (IMP)hooked_dataTaskWithRequest);
            NSLog(LOG_TAG @"[OK] Hooked NSURLSession");
        }
    }

    NSLog(LOG_TAG @"Standalone bypass ready. Zero network required.");
}
