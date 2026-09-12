# PocRunner — iOS 26.6 CVE-2026 PoC harness (second app, 4 buttons)

A minimal standalone iOS app with **four buttons**, one per ByteV0rtex PoC for the
iOS 26.6 (23G71) kernel bugs fixed in 26.6.1 (23G83). Built from the same
build→IPA flow as DirtySlide; unsigned on purpose (re-sign before sideload).

## Buttons → upstream PoCs (vendored in `poc_vendors/`, git clones)

| Button | Repo / source | Entry |
|---|---|---|
| CVE-2026-64788 IOGPUFamily UAF (Metal) | `ByteV0rtex/CVE-2026-64788` | `poc_iogpu_uaf_run()` |
| CVE-2026-65330 tmpfs setxattr PAC #0x307a | `ByteV0rtex/CVE-2026-65330` | `cve65330_run()` |
| CVE-2026-65343 AppleKeyStore OOB read / KASLR | `ByteV0rtex/CVE-2026-65343` | `cve65343_run()` |
| CVE-2026-65349 getattrlist OOB write | `ByteV0rtex/CVE-2026-65349` | `cve65349_run()` |

Each PoC runs **in-process on a background thread**; its stdout/stderr is piped
into the on-screen log live and the whole transcript is mirrored to NSLog when
the run finishes (grep `[PocRunner]` in the device console). Buttons disable
while a run is active. `UIApplication.sharedApplication.idleTimerDisabled = YES`.

## Adaptations vs upstream (all in `PocRunner/pocs/`, logic untouched)

1. Entries renamed (no `main`) so they can live in one app binary.
2. Raw `SYS_exit` syscalls → `return` (they would kill the host app).
3. The two C PoCs write their test file to `/var/root/…` first, and fall back to
   `NSTemporaryDirectory()` if creation fails (sandbox-writable) — the vendor
   path is tried first, exactly as upstream. Note CVE-2026-65330's *vulnerable
   VNOP* is tmpfs-specific, so a container-path fallback exercises the syscall
   but not the tmpfs handler; the `/var/root` result is the meaningful one.
4. `poc_64788.m`: one diagnostic `printf("%@", tex)` was UB → replaced with a
   plain string (upstream bug; everything else byte-identical).

## Notes / expectations

- **Target**: iOS 26.6 (23G71) or earlier. Fixed in 26.6.1.
- 65330/65349 assume the ability to create files under `/var/root` (root /
  jailbroken or otherwise out-of-sandbox). Inside the app sandbox they report
  the EPERM from the vendor path and retry under the container tmp dir.
- 64788 is A14-tested upstream; on newer SoCs (e.g. iPhone 17) the overflow
  path may or may not fire — the button prints every step, so the verdict is
  readable either way. It interposes `abort`/`_mtlValidateStrideTextureParameters`
  via `__DATA,__interpose` and installs a SIGTRAP skip handler for its window
  only.
- 65343 captures the ACM handle by interposing `IOConnectCallMethod` and
  triggering an SE key sign; on configs that route SE ops through `secd` XPC it
  falls back to the zero-handle reachability probe.
- A panic/reboot during any run is the expected research outcome on a
  vulnerable device — same class of evidence the DirtySlide campaign collects.

## Build / package (mirrors DirtySlide, no codesign)

```bash
xcodebuild -project PocRunner/PocRunner.xcodeproj -scheme PocRunner \
  -configuration Release -sdk iphoneos -derivedDataPath /tmp/poc_dd \
  build CODE_SIGNING_ALLOWED=NO
rm -rf /tmp/poc_pkg; mkdir -p /tmp/poc_pkg/Payload
cp -R /tmp/poc_dd/Build/Products/Release-iphoneos/PocRunner.app /tmp/poc_pkg/Payload/
cd /tmp/poc_pkg && zip -qry ../PocRunner.ipa Payload   # → repo-root PocRunner.ipa
```

Re-sign `PocRunner.ipa` with the usual dev-cert tooling before sideloading.
Bundle id: `com.research.PocRunner`. Entitlements file ships with a
keychain-access-groups entry (re-signing tools apply their own profile).
