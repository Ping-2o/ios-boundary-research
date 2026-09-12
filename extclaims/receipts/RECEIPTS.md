> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# RECEIPTS — External claims verification (2026-09-07)

All paths relative to /Users/pauyedin/DirtySlide/extclaims/ unless absolute.
Work dir: work/ · Source IPSWs: ~/Downloads/iPhone17,5_26.6_23G71_Restore.ipsw, ~/Downloads/iPhone17,5_26.6.1_23G83_Restore.ipsw · KDK: /Library/Developer/KDKs/KDK_26.6_25G72.kdk

## Hashes
- Firmware/AOP/aopfw-v59aop.RELEASE.im4p  sha256 d0fb1c4cb823efe2b2b74f6aeb057aa3bea87c7dd6ca68f50eefb0941b569004
- Firmware/Rose/r2p1/ftab.bin             sha256 937db4c5a9f798595454755413f650d4b36c632c77446419c221a741cdd3da5c

## Claim 1 (AOP2/Rose) key receipts
- IPSW listing (unzip -l, 23G71): Firmware/AOP/aopfw-v59aop.RELEASE.im4p · Firmware/Rose/r2p1/ftab.bin · Firmware/all_flash/DeviceTree.v59ap.im4p · kernelcache.release.v59 · Firmware/dfu/iBSS|iBEC.v59.RELEASE.im4p. 23G83: identical set.
- DeviceTree (work/dt_23g71.json / dt_23g71.yaml; via `ipsw dtree -j`):
  - arm-io/aop compat iop,ascwrap-v6; child iop-aop-nub compat iop-nub,rtbuddy-v2; firmware-name "v59aop"; aop-target 1.
  - aop nub services: aop-audio, aop-voicetrigger (name-override AOPVoiceTriggerService), aop-smart-cover, aop-scm-xbar.
  - arm-io/dart-aop: compat "dart,t8110"; reg addr=0x100fc0000 sz=0xc000; sid-count 18; exclave-sid present; bypass-12 prop.
    mappers: mapper-aop(reg 0) + mapper-exclave-aop(reg 1) + mapper-admac-{leap-s,base-ns,leap-ns,base-s} + mapper-scm.
  - arm-io/aop-exclave-mailbox: compat iop,secure-rtbuddy-proxy; role AOP-EXCLAVE; exclave-service com.apple.service.SecureRTBuddyAOP (+ _EDK).
  - arm-io/aop-exclave-ioreporting: role AOP-EXCLAVE, compat iop,secure-rtbuddy-ioreporting.
  - dart-sep/mapper-sep-exclave; dart-dcp/mapper-dcp-exclave; dart-isp mapper-*-exclave (5) — exclave mappers are a platform-wide pattern.
  - BT/WiFi: pci-bridge0/2 wlan + bluetooth-pcie = wlan-pcie,bcm4387; arm-io/bluetooth compat bluetooth,n88 → NOT AOP.
  - Touch: arm-io/mtp (iop,ascwrap-v6) + iop-mtp-nub (rtbuddy-v2) + dart-mtp; mtp-aop-mux = hid-transport,mux → MTP is its own coprocessor.
  - UWB: aop-spmi0/uwb0, aop-spmi1/uwb (+ eclipse-heb, eclipse-idc) → UWB radios hang off AOP's SPMI control buses.
  - bypass-N props in t8140 DT: dart-aop bypass-12; dart-dcp bypass-15; dart-isp bypass-15; dart-ave/ave1 bypass-12; dart-ane bypass-10/13; dart-apcie0/1/2 bypass-16/18; dart-dispgrt bypass-8. All present-but-zero.
- AOP firmware (work/aopfw_out/*, via `ipsw fw aop`): BUND bundle; segments ktxt(0x17000) rtxt(0x16d000) utxt kdat rdat udat uetx usdt ubdl(0x33000).
  - "Rose Supervisor Service": ubdl.bin ("SUCCESS finding Rose Supervisor Service" / "FAILED to find Rose Supervisor Service"), rtxt.bin "rose-supervisor".
  - RTKit: "RTKit-3255.160.4.release", "@(#)PROGRAM:RTKAudioDriversT8140_RTK PROJECT:RTKitAudioDrivers-540.19", "PRNG !patchbay ecid=%llx" (patchbay mechanism).
  - Sensors: "DopplerFirmwareiPhone14b PROJECT:DopplerFirmware-106.0.0", "VoiceTrigger ready!", "CMSPUAmbientLightSensorPhone", accelerometer orientation lines.
  - No "packet filter" strings found in aopfw; APF appears in the fabric as dart prop "allow-dram-apf-slices-0" (dart-aop).
  - ubdl.bin: 0 raw Mach-O magics (sub-bundle payload is compressed/encoded) — "10 embedded sensor firmwares" not directly countable locally.
- Rose bundle (work/rose_rkos.bin, work/rose_sbd1.bin): ftab magic "rkosftab", 5 entries — rkos off 0x80 sz 0x96ba0; sbd1 off 0x96c20 sz 0x62980; bver off 0xf95a0 sz 0x43; icnf; _osl.
  - bver: "236.2708120003000000.4388|23.6.0.0|date:2026 7 11|chip_revision_b0"
  - rkos strings: RTKit-3255.160.4.release, RTK_THREAD_PRIORITY, SEC/MAC FSM threads, RTK_ST_OK, "Panic test @ %d" — full RTOS.
- Kernelcache 23G71 (work/kc.dec.strings, after `ipsw kernel dec`):
  - AOP2Endpoint1..AOP2Endpoint24: exactly 24 unique.
  - AppleAOP2: 31 hits; idents: com.apple.driver.AppleAOP2, AppleAOP2IOPMService, AppleAOP2KextTightbeamEndpoint, AppleAOP2SystemDriver, AppleAOP2Kext.
  - exclave: 609 lines (incl. exclave_indicator_controller_metrics_v1, __exclaves_bt, com.apple.private.exclaves.*).
  - iBoot (all_flash/iboot_dec_23g83.bin strings): path "aop/iop-aop-nub/rose", "function-rose_coredump-pre-p2"; 0 t8122 hits.
- KDK 26.6 (System/Library/Extensions/): AppleAOP2.kext (CFBundleIdentifier com.apple.driver.AppleAOP2; personalities AppleAOP2IOPMService, AppleAOP2SystemDriver, AOP2FirmwareService, AOP2Endpoints [IONameMatch AOP2Endpoint1..24 × RTBuddyEndpointService], AOP2AFKTightbeamEndpoints), AOPAudioDriver.kext, AppleAOPVoiceTrigger.kext, ExclaveKextClient.kext, ExclaveSEPManagerProxy.kext, ExclavesAudioKext.kext, AppleT8110DART.kext.
  - AppleT8110DART strings: "Obsolete 'sids', 'bypass', and/or 'bypass-address' properties present"; "full bypass mode not supported and bypass-%d property does not specify a bypass address"; "allow-mixed-bypass-mode"; "apf-bypass".

## Claim 2 (A17 I2C4) key receipts
- Repo: github.com/JGoyd/Apple-Silicon-A17-Flaw — created 2025-09-03, 15 stars, Python. Contents: "A17 Pro Forensic Audit Tool.py" (2995 B), README.md, V1.0/ ("A17 Flaw .md", "Executive Summary.md"), V2.0/ ("A17 Pro Flaw V2.0 .md"). Saved: extclaims/a17_audit_tool.py, a17_readme.md, a17_flaw_v1.md, a17_flaw_v2.md.
- Audit tool's 4 signals vs stock t8140 23G71 kernelcache (kc.dec.strings):
  - "RELEASE_ARM64_T8122": 0 hits (only "RELEASE_ARM64_T8140" ×2 present). BUT 33 t8122 strings total (AppleT8122USBXHCI/USBXDCI/DPTXPort/ProcessorTrace, "gpu,t8122", "usb-drd,t8122", "dptx-phy,t8122") = multi-SoC driver classes compiled in; DeviceTree contains 0 t8122 (clean per-board) but 23 "t8110" compat strings (dart,t8110 etc.).
  - "bypass-15": DT property of dart-dcp + dart-isp (present-but-zero) → ioreg prints "bypass-15" = <> on every device; DART kext logs "full bypass mode not supported".
  - "ACE Debug cannot be set. Missing boot-args.": VERBATIM in stock t8140 kernelcache (AppleHPM setLDCMPin family, 34 LDCM-related strings) = routine log line.
  - "site.AppleSPUCT836": AppleSPUCT836 ×8 in stock t8140 kernelcache.
- iBoot/iBSS/iBEC (23G71): 0 t8122 refs; fallback strings are benign boot-mode names (upgrade-fallback-boot-command, recover-fallback, syscfg-keybag-fallback-*).
- KDK: kernel.release.t8122 exists as a separate macOS (M3-class) kernel build — per-SoC builds; no cross-SoC fallback machinery anywhere in the boot chain.

## Claim 3 (A15 CAND-001) key receipts
- ipsw.me API: 19E241 / 15.4 / iPhone14,6 → signed: False, url https://updates.cdn-apple.com/2022FCSWinter/fullrestores/071-09790/177AE196-6D87-47EC-A21C-4263D106992A/iPhone14,6_15.4_19E241_Restore.ipsw (6,044,199,717 B).
- HTTP-range BuildManifest extraction (work/bm_19e241.plist): ProductBuildVersion 19E241; BuildIdentities = 2 × DeviceClass d49ap (Erase + Update); components = 80 each; iBSS/iBEC/iBoot/iBootData/LLB/SEP/RestoreSEP/DeviceTree/RestoreDeviceTree/KernelCache/RestoreKernelCache/RestoreRamDisk/BasebandFirmware all present; 0 components with inline EncryptionKey.
- Repo NOT located: searches for "T8110-CAND-001-STATIC-EVIDENCE", "cand001-guard-provenance", "CAND-001", "19E241 SecureROM static" → no GitHub hits (repo search + web). Run IDs / artifact digests unverifiable.
- Public SecureROM dump collections (securerom.fun, zzVertigo/SecureROMs "iPhone 2G – iPhone 11 Pro Max", c834606877/securerom) cover ≤ A13; retail A14/A15(A0+B0/B1)/A16 SecureROMs are not in known public dumps → the "pinned public ROM sources" premise for the cross-gen table is unestablished.

## Tooling
ipsw 3.1.706 (BuildCommit 017dec7baa452a6cea7abd5bc15146c1d758e995); curl; python3 (urllib Range + zipfile/plistlib); plutil; shasum; otool/nm/strings.
