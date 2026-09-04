/**
 * reboot-tracer.js — Trace + block all XoaInfo anti-tamper reboot paths
 *
 * Usage (attach to XoaInfo process):
 *   frida -U -n XoaInfo -l reboot-tracer.js
 *   frida -U -p <pid> -l reboot-tracer.js
 *   frida -U --attach-name XoaInfo -l reboot-tracer.js --no-pause
 *
 * What it does:
 *   1. Blocks every known iOS reboot syscall/API so device never actually reboots
 *   2. Prints full backtrace when any reboot path fires — reveals the exact
 *      anti-tamper call chain in XoaInfoPlug2.dylib
 *   3. Hooks s7AcUOKf (XoaInfo preference manager) to trace all method calls
 *   4. Monitors q69GFYW9 (RNCryptor decrypt) result — flags len=0 path
 */

'use strict';

const TAG = '[XoaReboot]';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function bt(ctx) {
    try {
        return Thread.backtrace(ctx || this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress)
            .join('\n        ');
    } catch (_) {
        try {
            return Thread.backtrace(ctx || this.context, Backtracer.FUZZY)
                .map(DebugSymbol.fromAddress)
                .join('\n        ');
        } catch (_2) {
            return '(backtrace unavailable)';
        }
    }
}

function box(title, lines) {
    const bar = '═'.repeat(Math.max(title.length + 4, 40));
    console.log(`\n${TAG} ╔${bar}╗`);
    console.log(`${TAG} ║  ${title.padEnd(bar.length - 2)}║`);
    lines.forEach(l => console.log(`${TAG} ║  ${l.padEnd(bar.length - 2)}║`));
    console.log(`${TAG} ╚${bar}╝`);
}

function tryAttach(modName, symName, label, onEnterCb, block) {
    let addr = null;
    try {
        addr = modName
            ? Module.getExportByName(modName, symName)
            : Module.getExportByName(null, symName);
    } catch (_) {
        try { addr = Module.getExportByName(null, symName); } catch (_2) {}
    }
    if (!addr || addr.isNull()) {
        // console.log(`${TAG} [skip] ${label} — not found`);
        return false;
    }
    console.log(`${TAG} [hook] ${label} @ ${addr}`);
    Interceptor.attach(addr, {
        onEnter(args) {
            const trace = bt(this.context);
            let extra = '';
            try { if (onEnterCb) extra = onEnterCb(args); } catch (_) {}
            box(`REBOOT PATH: ${label}`, [
                extra ? `Args: ${extra}` : '',
                `Backtrace:`,
                `        ${trace}`,
            ].filter(Boolean));
            if (block) {
                console.log(`${TAG} >>> BLOCKED <<<`);
                this._block = true;
            }
        },
        onLeave(retval) {
            if (this._block) retval.replace(ptr(-1));
        },
    });
    return true;
}

// ─── 1. BSD reboot() — most direct path ──────────────────────────────────────

tryAttach('libsystem_kernel.dylib', 'reboot',
    'reboot(howto)',
    args => `howto=0x${args[0].toInt32().toString(16)}`,
    true);

// reboot3() on newer iOS
tryAttach(null, 'reboot3',
    'reboot3(howto,arg)',
    args => `howto=${args[0]} arg=${args[1]}`,
    true);

// ─── 2. system() / execve / posix_spawn — shell reboot ───────────────────────

{
    const sysAddr = Module.getExportByName(null, 'system');
    if (sysAddr) {
        console.log(`${TAG} [hook] system() @ ${sysAddr}`);
        Interceptor.attach(sysAddr, {
            onEnter(args) {
                try {
                    const cmd = args[0].readCString();
                    if (/reboot|halt|shutdown|reboot3/i.test(cmd || '')) {
                        const trace = bt(this.context);
                        box('REBOOT via system()', [`cmd="${cmd}"`, `Backtrace:`, `        ${trace}`]);
                        console.log(`${TAG} >>> BLOCKED system() <<<`);
                        this._block = true;
                    }
                } catch (_) {}
            },
            onLeave(retval) { if (this._block) retval.replace(ptr(-1)); },
        });
    }
}

{
    const spawnAddr = Module.getExportByName(null, 'posix_spawn');
    if (spawnAddr) {
        console.log(`${TAG} [hook] posix_spawn() @ ${spawnAddr}`);
        Interceptor.attach(spawnAddr, {
            onEnter(args) {
                try {
                    const path = args[1].readCString();
                    if (/reboot|halt|shutdown/i.test(path || '')) {
                        const trace = bt(this.context);
                        box('REBOOT via posix_spawn()', [`path="${path}"`, `Backtrace:`, `        ${trace}`]);
                        console.log(`${TAG} >>> BLOCKED posix_spawn() <<<`);
                        this._block = true;
                    }
                } catch (_) {}
            },
            onLeave(retval) { if (this._block) retval.replace(ptr(-1)); },
        });
    }
}

{
    const execAddr = Module.getExportByName(null, 'execve');
    if (execAddr) {
        console.log(`${TAG} [hook] execve() @ ${execAddr}`);
        Interceptor.attach(execAddr, {
            onEnter(args) {
                try {
                    const path = args[0].readCString();
                    if (/reboot|halt|shutdown/i.test(path || '')) {
                        const trace = bt(this.context);
                        box('REBOOT via execve()', [`path="${path}"`, `Backtrace:`, `        ${trace}`]);
                        console.log(`${TAG} >>> BLOCKED execve() <<<`);
                        this._block = true;
                    }
                } catch (_) {}
            },
            onLeave(retval) { if (this._block) retval.replace(ptr(-1)); },
        });
    }
}

// ─── 3. SpringBoard / private framework reboot APIs ──────────────────────────

const SBS = '/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices';
['SBSReboot', 'SBReboot', 'SBSRelaunchSpringBoard'].forEach(fn => {
    tryAttach(SBS, fn, fn, args => `reason=${args[0]}`, true);
});

// MobileGestalt (some tweaks use it)
const MG = '/usr/lib/libMobileGestalt.dylib';
['MGReboot', 'MGPerformReboot'].forEach(fn => {
    tryAttach(MG, fn, fn, null, true);
});

// ─── 4. notify_post — reboot via Darwin notifications ────────────────────────

{
    const notifyAddr = Module.getExportByName(null, 'notify_post');
    if (notifyAddr) {
        console.log(`${TAG} [hook] notify_post() @ ${notifyAddr}`);
        Interceptor.attach(notifyAddr, {
            onEnter(args) {
                try {
                    const name = args[0].readCString() || '';
                    if (/reboot|shutdown|halt|power.*down/i.test(name)) {
                        const trace = bt(this.context);
                        box('REBOOT via notify_post()', [`name="${name}"`, `Backtrace:`, `        ${trace}`]);
                        console.log(`${TAG} >>> BLOCKED notify_post() <<<`);
                        this._block = true;
                    }
                } catch (_) {}
            },
            onLeave(retval) { if (this._block) retval.replace(ptr(-1)); },
        });
    }
}

// ─── 5. host_reboot Mach trap ─────────────────────────────────────────────────

tryAttach(null, 'host_reboot',
    'host_reboot(host,howto)',
    args => `host=${args[0]} howto=${args[1].toInt32()}`,
    true);

// ─── 6. abort() / _exit() — anti-tamper might terminate violently ─────────────

{
    const abortAddr = Module.getExportByName(null, 'abort');
    if (abortAddr) {
        console.log(`${TAG} [hook] abort() @ ${abortAddr}`);
        Interceptor.attach(abortAddr, {
            onEnter(args) {
                const trace = bt(this.context);
                box('abort() called', [`Backtrace:`, `        ${trace}`]);
                // Don't block abort — it won't reboot the device, just crash the process
            },
        });
    }
}

// ─── 7. ObjC: s7AcUOKf — XoaInfo preference/anti-tamper class ───────────────
// Hook ALL methods of s7AcUOKf to find which one triggers reboot.

if (ObjC.available) {
    function hookClass(className) {
        const cls = ObjC.classes[className];
        if (!cls) {
            console.log(`${TAG} [skip] ObjC class ${className} not found`);
            return;
        }
        console.log(`${TAG} [hook] all methods of ${className}`);

        // Instance methods
        cls.$ownMethods.forEach(sel => {
            try {
                const impl = cls[sel].implementation;
                Interceptor.attach(impl, {
                    onEnter(args) {
                        console.log(`${TAG} [${className}] ${sel} self=${args[0]}`);
                    },
                });
            } catch (_) {}
        });

        // Class methods
        const meta = ObjC.classes[`${className} (meta)`] || cls.$class;
        if (meta) {
            meta.$ownMethods.forEach(sel => {
                try {
                    const impl = meta[sel].implementation;
                    Interceptor.attach(impl, {
                        onEnter(args) {
                            console.log(`${TAG} [+${className}] ${sel}`);
                        },
                    });
                } catch (_) {}
            });
        }
    }

    // Hook after a short delay so all dylibs are loaded
    setTimeout(() => {
        hookClass('s7AcUOKf');  // XoaInfo preference manager / anti-tamper

        // Also hook j2cyd0Nd (gateway class) to see all its methods
        hookClass('j2cyd0Nd');

        // Scan for any class whose method name contains "reboot" (case-insensitive)
        Object.keys(ObjC.classes).forEach(name => {
            const cls = ObjC.classes[name];
            if (!cls) return;
            cls.$ownMethods.forEach(sel => {
                if (/reboot|tamper|antiTamper|anti_tamper|shutdown|forceReboot/i.test(sel)) {
                    console.log(`${TAG} [SUSPICIOUS] -[${name} ${sel}]`);
                    try {
                        Interceptor.attach(cls[sel].implementation, {
                            onEnter(args) {
                                const trace = bt(this.context);
                                box(`Suspicious method: -[${name} ${sel}]`,
                                    [`self=${args[0]}`, `Backtrace:`, `        ${trace}`]);
                                this._block = true;
                            },
                            onLeave(retval) {
                                if (this._block) retval.replace(ptr(0));
                            },
                        });
                    } catch (_) {}
                }
            });
        });

        console.log(`${TAG} ObjC hooks installed`);
    }, 1000);
}

// ─── 8. Monitor q69GFYW9 result length — flag when len=0 ─────────────────────
// q69GFYW9 returning len=0 is the trigger condition for anti-tamper reboot.
// Hook it at the ObjC level to catch the moment it happens and log the caller.

if (ObjC.available) {
    setTimeout(() => {
        const y8 = ObjC.classes['y8WisN9t'];
        if (!y8) {
            console.log(`${TAG} [skip] y8WisN9t class not found`);
            return;
        }

        // Find the +c6chSi59:q69GFYW9:error: class method
        const decSel = '+ c6chSi59:q69GFYW9:error:';
        if (y8.$class[decSel]) {
            console.log(`${TAG} [hook] y8WisN9t ${decSel}`);
            Interceptor.attach(y8.$class[decSel].implementation, {
                onEnter(args) {
                    const a1 = args[2]; // ciphertext (NSData)
                    const a2 = args[3]; // nonce
                    const len = ObjC.Object(a1).length ? ObjC.Object(a1).length() : 0;
                    this._nonce = a2;
                    this._cipherLen = len;
                },
                onLeave(retval) {
                    try {
                        const result = new ObjC.Object(retval);
                        const rlen = result.length ? result.length() : 0;
                        console.log(`${TAG} q69GFYW9 cipher=${this._cipherLen}B → result=${rlen}B`);
                        if (rlen === 0) {
                            const trace = bt(this.context);
                            box('q69GFYW9 returned EMPTY — anti-tamper will fire!',
                                [`cipherLen=${this._cipherLen}`, `Backtrace:`, `        ${trace}`]);
                        }
                    } catch (_) {}
                },
            });
        }
    }, 1500);
}

// ─── 9. XoaInfoPlug2.dylib — scan for reboot-looking code ───────────────────
// After dylib loads, scan its exports and find functions that look like
// anti-tamper triggers. Also trace any function calling reboot().

setTimeout(() => {
    const plug2 = Process.findModuleByName('XoaInfoPlug2.dylib');
    if (!plug2) {
        console.log(`${TAG} XoaInfoPlug2.dylib not loaded yet — will retry`);
        return;
    }
    console.log(`${TAG} XoaInfoPlug2.dylib base=${plug2.base} size=${plug2.size}`);

    // Log all exported symbols (there may be very few — tweak code is usually anonymous)
    const exps = plug2.enumerateExports();
    exps.forEach(e => console.log(`${TAG} export: ${e.name} @ ${e.address}`));

    // Find the reboot() call site inside the dylib:
    // Search for the ARM64 encoding of "bl <reboot>" or "bl <SBSReboot>".
    // reboot() address is known at runtime — compute relative offset and scan.
    let rebootAddr = null;
    try { rebootAddr = Module.getExportByName(null, 'reboot'); } catch (_) {}
    if (rebootAddr) {
        // ARM64 BL encoding: 0x94000000 | ((offset/4) & 0x3FFFFFF)
        // We can scan for calls that land near the reboot address.
        // Simpler: set a hardware breakpoint-style hook on reboot() and check
        // if the caller is inside XoaInfoPlug2 — tryAttach above already does this.
        console.log(`${TAG} reboot() @ ${rebootAddr} — will be caught by existing hook`);
    }

    console.log(`${TAG} XoaInfoPlug2 scan done`);
}, 2000);

// ─── Done ─────────────────────────────────────────────────────────────────────

console.log(`${TAG} ═══════════════════════════════════════════`);
console.log(`${TAG}   XoaInfo Reboot Tracer + Blocker Active`);
console.log(`${TAG}   All reboot syscalls/APIs are BLOCKED`);
console.log(`${TAG}   Backtrace will show anti-tamper call chain`);
console.log(`${TAG} ═══════════════════════════════════════════`);
