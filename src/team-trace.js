// team-trace.js  — definitive team-flow tracer
// Answers: what URL/params does team send? what nonce for decrypt? what fields parsed?
//
// Usage:  frida -U -n XoaInfo -l team-trace.js
//         frida -U -f com.ienthach.XoaInfo -l team-trace.js
//
// Run with c2redirect tweak LOADED (so loginip already succeeds).
// Trigger "Reset Data" / team auth, then read output.
//
// Tags:
//   [GW]       gateway call: URL path + full params dict
//   [DEC]      every y8WisN9t decrypt call: nonce + blob length
//   [PARSE]    componentsSeparatedByString:|<>| — decrypted plaintext
//   [U05]      u05H89F1:n9G7AiPp: key/value extraction
//   [PREF]     c2Uu7nHV:forKey: preference writes after team
//   [LICENSE]  setA3JKER2u: call
//   [CMP]      isEqualToString: on 32-char hex (phase comparison)

'use strict';

const TAG = '[team-trace] ';

function s(h, max) {
    if (!h || h.isNull()) return 'nil';
    try {
        const t = new ObjC.Object(h).toString();
        return t.length > (max || 300) ? t.slice(0, max || 300) + '…' : t;
    } catch (_) { return h.toString(); }
}

function hook(cls, sel, callbacks) {
    const C = ObjC.classes[cls];
    if (!C) { console.log(TAG + '[!] class missing: ' + cls); return; }
    const m = C[sel];
    if (!m) { console.log(TAG + '[!] method missing: ' + cls + ' ' + sel); return; }
    try { Interceptor.attach(m.implementation, callbacks); }
    catch (e) { console.log(TAG + '[!] hook failed: ' + cls + ' ' + sel + ': ' + e); }
}

function hookNative(sym, callbacks) {
    const addr = Module.findGlobalExportByName(sym);
    if (!addr) { console.log(TAG + '[!] native sym missing: ' + sym); return; }
    try { Interceptor.attach(addr, callbacks); }
    catch (e) { console.log(TAG + '[!] hook failed: ' + sym + ': ' + e); }
}

// ─── 1. Gateway: log EVERY call with path + full params ─────────────────────
hook('j2cyd0Nd', '+ b5Znk9Kh:q7C9eMnf:c7UND7t6:z0BQnrZN:', {
    onEnter(args) {
        const path   = s(args[2], 200);
        const params = s(args[3], 600);
        console.log(TAG + '[GW] path="' + path + '"');
        console.log(TAG + '[GW] params=' + params);
    }
});

// ─── 2. Decrypt: log every call with nonce + blob size ───────────────────────
// y8WisN9t  c6chSi59:q69GFYW9:error:
//   args[2] = NSData* blob, args[3] = NSString* nonce/password
hook('y8WisN9t', '+ c6chSi59:q69GFYW9:error:', {
    onEnter(args) {
        const blob  = args[2];
        const nonce = s(args[3], 80);
        let blobLen = 0;
        try { blobLen = Number(new ObjC.Object(blob).length()); } catch (_) {}
        console.log(TAG + '[DEC] nonce="' + nonce + '" blobLen=' + blobLen);
    },
    onLeave(retval) {
        const plain = s(retval, 400);
        console.log(TAG + '[DEC] plaintext="' + plain + '"');
    }
});

// ─── 3. Parse: log |<>|-separated plaintext ─────────────────────────────────
hook('NSString', '- componentsSeparatedByString:', {
    onEnter(args) {
        const sep = s(args[2], 10);
        if (sep !== '|<>|') return;
        const str = s(args[0], 800);
        console.log(TAG + '[PARSE] "' + str + '"');
    }
});

// ─── 4. u05H89F1:n9G7AiPp: — key extraction from parsed array ───────────────
// This method is called like: [obj u05H89F1:arr n9G7AiPp:prefix]
// args[0]=self, args[1]=SEL, args[2]=arr, args[3]=prefix
// Let's hook NSArray's objectAtIndex and NSString hasPrefix as proxies
hook('NSString', '- hasPrefix:', {
    onEnter(args) {
        const prefix = s(args[2], 40);
        const str    = s(args[0], 200);
        // Only log if it looks like a field extraction
        if (str.length > 0 && (
            /^[a-z]/.test(str) || str.indexOf(':') > 0
        ) && prefix.length > 2 && /^[a-zA-Z]/.test(prefix)) {
            this.log = '[U05] "' + str.slice(0, 80) + '".hasPrefix("' + prefix + '")';
        }
    },
    onLeave(retval) {
        if (!this.log) return;
        console.log(TAG + this.log + ' => ' + (retval.toInt32() ? 'YES' : 'NO'));
    }
});

// Also hook substringFromIndex: to see extracted values
hook('NSString', '- substringFromIndex:', {
    onEnter(args) {
        const idx = args[2].toInt32();
        const str = s(args[0], 200);
        // Only interesting after a field prefix match
        if (idx > 2 && idx < 50 && str.length > idx) {
            this.extracted = str.slice(idx);
        }
    },
    onLeave(retval) {
        if (!this.extracted) return;
        const val = s(retval, 200);
        console.log(TAG + '[U05] extracted="' + val + '"');
        this.extracted = null;
    }
});

// ─── 5. Preference writes ────────────────────────────────────────────────────
hook('s7AcUOKf', '+ c2Uu7nHV:forKey:', {
    onEnter(args) {
        const val = s(args[2], 200);
        const key = s(args[3], 60);
        console.log(TAG + '[PREF] key="' + key + '" val="' + val + '"');
    }
});

// ─── 6. License setter ───────────────────────────────────────────────────────
hook('s7AcUOKf', '+ setA3JKER2u:', {
    onEnter(args) {
        console.log(TAG + '[LICENSE] setA3JKER2u:(' + args[2].toInt32() + ')');
        // Print backtrace to see call path
        try {
            const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                .slice(0, 8)
                .map(a => '  ' + a + '  ' + DebugSymbol.fromAddress(a))
                .join('\n');
            console.log(TAG + '[LICENSE] backtrace:\n' + bt);
        } catch (_) {}
    }
});

// ─── 7. Phase comparison (isEqualToString: on 32-char hex) ──────────────────
hook('NSString', '- isEqualToString:', {
    onEnter(args) {
        const left  = s(args[0], 40);
        const right = s(args[2], 40);
        if (/^[0-9a-f]{32}$/i.test(left)) {
            this.cmp = '"' + left + '" == "' + right + '"';
        }
    },
    onLeave(retval) {
        if (!this.cmp) return;
        console.log(TAG + '[CMP] ' + this.cmp + ' => ' + (retval.toInt32() ? 'MATCH ✓' : 'MISMATCH ✗'));
    }
});

// ─── 8. CFStringCompare (Plug4 may use CF-level) ────────────────────────────
hookNative('CFStringCompare', {
    onEnter(args) {
        try {
            const left  = new ObjC.Object(args[0]).toString();
            const right = new ObjC.Object(args[1]).toString();
            if (/^[0-9a-f]{32}$/i.test(left)) {
                this.cmp = '[CFCmp] "' + left + '" vs "' + right + '"';
            }
        } catch (_) {}
    },
    onLeave(retval) {
        if (!this.cmp) return;
        console.log(TAG + this.cmp + ' => ' + retval.toInt32());
    }
});

console.log(TAG + 'Loaded. Trigger Reset Data / team auth now.');
console.log(TAG + 'KEY tags: [GW]=gateway call, [DEC]=decrypt, [PARSE]=plaintext, [CMP]=phase');
