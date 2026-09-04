// team-debug.js — trace XoaInfo team auth validation
// Usage: frida -U XoaInfo -l team-debug.js   (after app launched)
//        or: frida -U -f com.xxx.XoaInfo -l team-debug.js --no-pause
//
// Answers three questions:
//   1. Which s7AcUOKf methods are called (getter + setter) and with what args?
//   2. Does XoaInfo parse our response via componentsSeparatedByString:|<>| ?
//   3. Is there a phase/MD5 comparison and does it match?

'use strict';

var TAG = '[team-debug] ';

// ── 1. Hook ALL s7AcUOKf class methods ─────────────────────────────────────
var prefCls = ObjC.classes.s7AcUOKf;
if (!prefCls) {
    console.log(TAG + '[!] s7AcUOKf not found — app may not be running yet');
} else {
    var hooked = 0;
    prefCls.$ownMethods.forEach(function(m) {
        try {
            Interceptor.attach(prefCls[m].implementation, {
                onEnter: function(args) {
                    this.m = m;
                    // Collect up to 3 ObjC args (skip self=args[0], _cmd=args[1])
                    this.a = [];
                    for (var i = 2; i <= 4; i++) {
                        try {
                            var s = new ObjC.Object(args[i]).toString();
                            this.a.push(s.length > 100 ? s.substring(0,100)+'…' : s);
                        } catch(e) { break; }
                    }
                },
                onLeave: function(ret) {
                    var retStr = '';
                    try {
                        if (!ret.isNull()) {
                            var s = new ObjC.Object(ret).toString();
                            retStr = ' → ' + (s.length > 100 ? s.substring(0,100)+'…' : s);
                        }
                    } catch(e) {}
                    console.log(TAG + '[PREF] ' + this.m + '(' + this.a.join(', ') + ')' + retStr);
                }
            });
            hooked++;
        } catch(e) {
            // skip non-hookable entries
        }
    });
    console.log(TAG + '[+] s7AcUOKf: hooked ' + hooked + ' of ' + prefCls.$ownMethods.length + ' methods');
}

// ── 2. Response parsing — componentsSeparatedByString:|<>| ─────────────────
var NSString = ObjC.classes.NSString;
Interceptor.attach(NSString['- componentsSeparatedByString:'].implementation, {
    onEnter: function(args) {
        try {
            var sep = new ObjC.Object(args[2]).toString();
            if (sep !== '|<>|') return;
            var str = new ObjC.Object(args[0]).toString();
            console.log(TAG + '[PARSE] sep="|<>|" str="' +
                (str.length > 400 ? str.substring(0,400)+'…' : str) + '"');
        } catch(e) {}
    }
});

// ── 3. Phase/MD5 comparison — isEqualToString: on 32-char hex strings ──────
Interceptor.attach(NSString['- isEqualToString:'].implementation, {
    onEnter: function(args) {
        try {
            var a = new ObjC.Object(args[0]).toString();
            var b = new ObjC.Object(args[2]).toString();
            // Only care about 32-char lowercase hex (MD5 hashes = phase values)
            if (a.length === 32 && /^[0-9a-f]{32}$/.test(a)) {
                this.cmp = '"' + a + '" == "' + b + '"';
            }
        } catch(e) {}
    },
    onLeave: function(ret) {
        if (this.cmp) {
            var match = ret.toInt32() ? 'MATCH ✓' : 'MISMATCH ✗';
            console.log(TAG + '[CMP] ' + this.cmp + '  =>  ' + match);
        }
    }
});

// ── 4. Also trace componentsSeparatedByString on any string with "phase:" ──
//    This catches any intermediate parsing step
Interceptor.attach(NSString['- hasPrefix:'].implementation, {
    onEnter: function(args) {
        try {
            var prefix = new ObjC.Object(args[2]).toString();
            if (prefix === 'phase' || prefix === 'versionApp' || prefix === 'expDate') {
                var self_str = new ObjC.Object(args[0]).toString();
                console.log(TAG + '[PREFIX] "' +
                    (self_str.length > 60 ? self_str.substring(0,60)+'…' : self_str) +
                    '".hasPrefix("' + prefix + '")');
            }
        } catch(e) {}
    }
});

console.log(TAG + 'Script loaded. Trigger Reset Data / team auth now.');
