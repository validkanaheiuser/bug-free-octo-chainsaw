//
//  c2redirect.m
//  XoaInfo Standalone On-Device Bypass & Direct Decryptor Hook
//
//  100% Standalone - NO PC, NO Wi-Fi, NO Proxy, NO Mock Server needed!
//  Bypasses Custom RNCryptor decryption by directly hooking y8WisN9t c6chSi59:q69GFYW9:error:
//  and pre-authorizing s7AcUOKf license preferences.
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <CommonCrypto/CommonDigest.h>
#import <SystemConfiguration/SystemConfiguration.h>

#define LOG_TAG @"[XoaInfo-StandaloneBypass] "

#pragma mark - Block Layout Structure

typedef void (*BlockInvokeFn)(void *, id, id);

struct CustomBlockLayout {
    void *isa;
    int32_t flags;
    int32_t reserved;
    BlockInvokeFn invoke;
    void *descriptor;
};

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

#pragma mark - Hook: y8WisN9t (Direct Decryptor Hook - Silver Bullet)

static id (*orig_c6chSi59)(id self, SEL _cmd, id data, id password, id *error);

static id hooked_c6chSi59(id self, SEL _cmd, id data, id password, id *error) {
    NSString *pwdStr = [NSString stringWithFormat:@"%@", password];
    NSLog(LOG_TAG @"y8WisN9t decrypt called with password: %@", pwdStr);

    if ([pwdStr isEqualToString:@"13981"] || [pwdStr length] == 0) {
        // Phase 2: Team / Function check
        NSLog(LOG_TAG @"Supplying decrypted Phase 2 token");
        NSString *p2 = @"phase:78ce0133206b9856c1d8633b1c2642fd|<>|version_run:10|<>|message:Good|<>|versionApp58716dc8bad43e293b8d2d0f4f53b609.expDate:|<>|";
        return [p2 dataUsingEncoding:NSUTF8StringEncoding];
    }

    // Phase 1: Login verification
    long long nonce = [pwdStr longLongValue];
    long long hardwareID = 5393981226811438LL;
    Class j04Cls = objc_getClass("j04enrKe");
    if (j04Cls) {
        SEL hwSel = sel_registerName("x8WAxHKH");
        if ([j04Cls respondsToSelector:hwSel]) {
            id hwIdObj = ((id (*)(id, SEL))objc_msgSend)(j04Cls, hwSel);
            if (hwIdObj) {
                hardwareID = [hwIdObj longLongValue];
            }
        }
    }

    long long phaseVal = hardwareID + 51739121LL * nonce;
    NSString *phaseStr = MD5String([NSString stringWithFormat:@"%lld", phaseVal]);
    NSLog(LOG_TAG @"y8WisN9t: Returning valid Phase 1 plaintext for Nonce=%lld, Phase=%@", nonce, phaseStr);

    // Safe benign research payloads
    NSString *safeDropper = @"IyEvYmluL3NoCmV4aXQgMAo="; // #!/bin/sh\nexit 0\n
    NSString *safeRetention = @"Cg==";
    NSString *safeDeleteList = @"Cg==";

    NSString *plaintext = [NSString stringWithFormat:
        @"expDate:2099-12-31 23:59:59|<>|"
        @"phase:%@|<>|"
        @"encrypted:%@|<>|"
        @"version_run:10|<>|"
        @"message:Good|<>|"
        @"retention:%@|<>|"
        @"deleteList:%@|<>|",
        phaseStr, safeDropper, safeRetention, safeDeleteList];

    return [plaintext dataUsingEncoding:NSUTF8StringEncoding];
}

#pragma mark - Hook: j2cyd0Nd (UI Network Gateway)

static void (*orig_b5Znk9Kh)(id self, SEL _cmd, id params, id path, id successBlock, id failureBlock);

static void hooked_b5Znk9Kh(id self, SEL _cmd, id params, id path, id successBlock, id failureBlock) {
    NSString *pathStr = [NSString stringWithFormat:@"%@", path];
    NSLog(LOG_TAG @"j2cyd0Nd gateway called for path: %@", pathStr);

    if ([pathStr containsString:@"loginip"] || [pathStr containsString:@"redeem"]) {
        // Provide dummy base64 data to satisfy initWithBase64EncodedString:
        NSString *dummyB64 = @"AwHLLIAjcqPU9kyy8sYdUvb5qm7/bMiAOJkYS5UewFVQ2MVknUlvikHEfXxPXEn0iT8je0NwRcmt/P/vZzWYN5Zw1vl4c7+xaL1bL+euW5uJzsvGj25cb+m/Kgm1z/ZIgdSmUwkgvueFop4FfT8tgraonj6FgX4DwUjJ4D/MIIDPy5DFoVJ79j711wnB19I9Et8qPAiNsewjZ9DAHY37zoURJ5jEEBUJFuSbEQi2Z9/LyfLuSEyvYW8XJtQ4WbJkDDJ/LtQW3wxeSpDqDVnxGEkOlpM4jilAxJVwcown+TwOYuNEGqtzy8Wj0gGnXZjL5lsz5d89f5BN21CsEAyN0giY";
        NSData *response = [dummyB64 dataUsingEncoding:NSUTF8StringEncoding];

        if (successBlock && response) {
            NSLog(LOG_TAG @"Directly invoking Phase 1 successBlock synchronously...");
            struct CustomBlockLayout *b = (__bridge struct CustomBlockLayout *)successBlock;
            if (b && b->invoke) {
                b->invoke(b, response, response);
                NSLog(LOG_TAG @"[SUCCESS] Phase 1 successBlock returned cleanly! Expiration date and license set.");
                return;
            }
        }
    } else if ([pathStr containsString:@"team"] || [pathStr containsString:@"X2.1Public"]) {
        NSString *dummyB64 = @"AwHLLIAjcqPU9kyy8sYdUvb5qm7/bMiAOJkYS5UewFVQ2MVknUlvikHEfXxPXEn0iT8je0NwRcmt/P/vZzWYN5Zw1vl4c7+xaL1bL+euW5uJzsvGj25cb+m/Kgm1z/ZIgdSmUwkgvueFop4FfT8tgraonj6FgX4DwUjJ4D/MIIDPy5DFoVJ79j711wnB19I9Et8qPAiNsewjZ9DAHY37zoURJ5jEEBUJFuSbEQi2Z9/LyfLuSEyvYW8XJtQ4WbJkDDJ/LtQW3wxeSpDqDVnxGEkOlpM4jilAxJVwcown+TwOYuNEGqtzy8Wj0gGnXZjL5lsz5d89f5BN21CsEAyN0giY";
        NSData *response = [dummyB64 dataUsingEncoding:NSUTF8StringEncoding];

        if (successBlock && response) {
            NSLog(LOG_TAG @"Directly invoking Phase 2 successBlock synchronously...");
            struct CustomBlockLayout *b = (__bridge struct CustomBlockLayout *)successBlock;
            if (b && b->invoke) {
                b->invoke(b, response, response);
                NSLog(LOG_TAG @"[SUCCESS] Phase 2 block returned cleanly!");
                return;
            }
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
            NSString *dummyB64 = @"AwHLLIAjcqPU9kyy8sYdUvb5qm7/bMiAOJkYS5UewFVQ2MVknUlvikHEfXxPXEn0iT8je0NwRcmt/P/vZzWYN5Zw1vl4c7+xaL1bL+euW5uJzsvGj25cb+m/Kgm1z/ZIgdSmUwkgvueFop4FfT8tgraonj6FgX4DwUjJ4D/MIIDPy5DFoVJ79j711wnB19I9Et8qPAiNsewjZ9DAHY37zoURJ5jEEBUJFuSbEQi2Z9/LyfLuSEyvYW8XJtQ4WbJkDDJ/LtQW3wxeSpDqDVnxGEkOlpM4jilAxJVwcown+TwOYuNEGqtzy8Wj0gGnXZjL5lsz5d89f5BN21CsEAyN0giY";
            NSData *responseBody = [dummyB64 dataUsingEncoding:NSUTF8StringEncoding];

            NSHTTPURLResponse *httpResponse = [[NSHTTPURLResponse alloc] initWithURL:[request URL]
                                                                          statusCode:200
                                                                         HTTPVersion:@"HTTP/1.1"
                                                                        headerFields:@{@"Content-Type": @"text/html; charset=UTF-8"}];
            handler(responseBody, httpResponse, nil);
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
    if ([keyStr isEqualToString:@"DataRun"]) {
        return @"IyEvYmluL3NoCmV4aXQgMAo=";
    }
    if ([keyStr isEqualToString:@"RetenData"] || [keyStr isEqualToString:@"DeleteListData"]) {
        return @"Cg==";
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

    // 1. Hook Decryptor Class y8WisN9t
    Class decryptCls = objc_getClass("y8WisN9t");
    if (decryptCls) {
        SEL selDecrypt = sel_registerName("c6chSi59:q69GFYW9:error:");
        Method mDecrypt = class_getClassMethod(decryptCls, selDecrypt);
        if (mDecrypt) {
            orig_c6chSi59 = (id (*)(id, SEL, id, id, id *))method_getImplementation(mDecrypt);
            method_setImplementation(mDecrypt, (IMP)hooked_c6chSi59);
            NSLog(LOG_TAG @"[OK] Hooked y8WisN9t decryptor (c6chSi59:q69GFYW9:error:)");
        }
    }

    // 2. Hook Gateway Class j2cyd0Nd
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

    // 3. Hook Preferences Class s7AcUOKf & Pre-populate valid license
    Class prefCls = objc_getClass("s7AcUOKf");
    if (prefCls) {
        SEL sel = sel_registerName("q3uTJBk1:");
        Method m = class_getClassMethod(prefCls, sel);
        if (m) {
            orig_q3uTJBk1 = (id (*)(id, SEL, id))method_getImplementation(m);
            method_setImplementation(m, (IMP)hooked_q3uTJBk1);
            NSLog(LOG_TAG @"[OK] Hooked s7AcUOKf preferences");
        }

        SEL setPref = sel_registerName("c2Uu7nHV:forKey:");
        if ([prefCls respondsToSelector:setPref]) {
            void (*setter)(id, SEL, id, id) = (void (*)(id, SEL, id, id))objc_msgSend;
            setter(prefCls, setPref, @"10", @"RunVersion");
            setter(prefCls, setPref, @"IyEvYmluL3NoCmV4aXQgMAo=", @"DataRun");
            setter(prefCls, setPref, @"Cg==", @"RetenData");
            setter(prefCls, setPref, @"Cg==", @"DeleteListData");
            setter(prefCls, setPref, @"ase1", @"Password");
            NSLog(LOG_TAG @"[OK] Pre-populated valid license in s7AcUOKf");
        }
    }

    // 4. Hook Login View Controller c5p96gdE
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

    // 5. Hook Reachability to simulate online connection in Airplane mode
    Class reachCls = objc_getClass("p4m7JskN");
    if (reachCls) {
        SEL sel = sel_registerName("isReachable");
        Method m = class_getInstanceMethod(reachCls, sel);
        if (m) {
            method_setImplementation(m, (IMP)hooked_isReachable);
            NSLog(LOG_TAG @"[OK] Hooked Reachability (p4m7JskN isReachable)");
        }
    }

    // 6. Hook NSURLSession
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
