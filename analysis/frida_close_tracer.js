/*
 * frida_close_tracer.js - Attaches to sendto() on the player's phone and
 * prints a backtrace through libUE4.so whenever the game sends a UE4
 * "Close" bunch (a packet ending in the 4 bytes ff 05 00 c0 - see
 * docs/packet_notes.md for the bunch layout this matches).
 *
 * This answers "why did the client close the connection?" directly from
 * the client's own call stack, instead of guessing from the server side.
 *
 * Tested with Frida 17.x against an injected frida-gadget (no root
 * required on the phone - see docs/frida_setup.md for how that was set
 * up). Written for arm64; addresses printed are libUE4.so-relative and
 * can be fed straight into DecompAt.py (same offsets, no base needed
 * there either - DecompAt.py adds Ghidra's own base).
 *
 * Usage:
 *     frida -U -n Gadget -l frida_close_tracer.js
 * then join a server and leave; the backtrace prints when the Close
 * bunch is sent.
 */

console.log('arch=' + Process.arch);

const libc = Process.getModuleByName('libc.so');
const sendto = libc.getExportByName('sendto');
let count = 0;

Interceptor.attach(sendto, {
    onEnter(args) {
        const len = args[2].toInt32();
        if (len < 9 || len > 40) return;
        const bytes = new Uint8Array(args[1].readByteArray(len));
        const tail = Array.from(bytes.slice(len - 4))
            .map(x => x.toString(16).padStart(2, '0')).join('');
        if (tail !== 'ff0500c0') return;

        console.log('CLOSE packet #' + (++count) + ' len=' + len);
        console.log(
            Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(addr => {
                    const m = Process.findModuleByAddress(addr);
                    return m
                        ? m.name + '+0x' + addr.sub(m.base).toString(16)
                        : addr.toString();
                })
                .join('\n')
        );
    },
});

console.log('hook ready on sendto @ ' + sendto);
