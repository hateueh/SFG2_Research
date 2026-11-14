# Running Frida against SFG2 without root

The phone used for this project is **not rooted**. Frida was still made
to work by patching the APK to embed `frida-gadget` (an injection, not a
root exploit). The exact patching steps used are not written down in
this repo; what is confirmed is the result and the workflow:

- `frida -U -n Gadget -l <script>.js` attaches to the running game
  through the injected gadget.
- The gadget connects over the phone's own network stack, shown as
  `id=<phone-ip>:<port>` in Frida's banner.
- `libUE4.so` is only loaded once the game has actually started (not at
  process launch), so a script that grabs it with
  `Process.getModuleByName('libUE4.so')` immediately will throw
  `Error: unable to find module 'libUE4.so'`. Poll for it instead:

  ```js
  const t = setInterval(() => {
    const m = Process.findModuleByName('libUE4.so');
    if (m) { clearInterval(t); /* use m here */ }
  }, 300);
  ```

- Frida 17.x removed the old static `Module.getExportByName(name, export)`
  form. Use:
  - `Process.getModuleByName('libc.so').getExportByName('sendto')`
  - `Process.getGlobalExportByName('x')` for unnamed-module exports
  - `Process.getModuleByName('m').base` instead of `Module.findBaseAddress`

## Matching addresses to static analysis

Before trusting any address Frida prints against the Ghidra/radare2
analysis of a `libUE4.so` extracted from the APK, confirm it is the same
build by comparing raw bytes at one address, on both sides:

Frida:
```js
const m = Process.getModuleByName('libUE4.so');
console.log('size=' + m.size);
console.log(
  Array.from(new Uint8Array(m.base.add(0x1777600).readByteArray(32)))
    .map(x => x.toString(16).padStart(2, '0')).join('')
);
```

radare2 (on the extracted `.so`):
```bash
r2 -q -e bin.cache=true -c "p8 32 @ 0x1777600" apk/lib/arm64-v8a/libUE4.so
```

If the two hex strings match, every address from the static analysis
scripts in `analysis/` can be used directly against addresses seen live
in Frida (and vice versa), with no offset. If they don't match, the
phone has a different build (different APK version or ABI) and needs
its own `libUE4.so` pulled and analyzed separately.
