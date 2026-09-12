> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# REPORT_EXTERNAL_CLAIMS.md — Forensic verification of three external "Apple Silicon flaw" writeups

**Date:** 2026-09-07 · **Method:** static verification only — no device runs, no exploit development, no fault injection.
**Local evidence base:** iPhone17,5 (iPhone 16e, **A18 / t8140**) IPSWs `23G71` (iOS 26.6) + `23G83` (26.6.1), KDK `KDK_26.6_25G72.kdk`, and an HTTP-range-extracted `BuildManifest.plist` from Apple's CDN for `iPhone14,6 / 15.4 / 19E241`.
**Receipts:** `/Users/pauyedin/DirtySlide/extclaims/` (work dir with hashes, extracted firmware, grep dumps; `receipts/RECEIPTS.md` for the evidence log).

---

## Verdict summary

| # | Claim | Verdict |
|---|---|---|
| 1 | "The Always-On Blind Spot" — AOP2/"Rose" on "A18 (t8150)", `mapper-exclave-aop@1`, 24 endpoints, unwitnessable Exclave DMA | **Structure: LARGELY CORROBORATED** (verified on the sibling t8140 die, incl. exact endpoint count and the Rose firmware bundle) · **SoC labeling: WRONG** · **Conclusion ("structurally broken privacy"): UNSUPPORTED** |
| 2 | "A17 Pro I2C4 Silicon Defect" — I2C4 failure → T8122 fallback kernel, DART `bypass-15` firewall disable, `NoEncryption` collapse | **UNSUPPORTED — every "detection signal" is a benign stock artifact present on healthy iPhones**; the core mechanism is architecturally incoherent as described |
| 3 | A15 CAND-001 static research branch (iPhone14,6 / 19E241) | **Manifest facts: VERIFIED EXACTLY** (2 d49ap identities × 80 components) · **Repo/artifacts: NOT LOCATED / unverifiable** · **ROM provenance: CONCERN** · **Epistemics: honest** (the only one of the three that does not overclaim) |

Cross-cutting pattern: claims 1 and 2 enumerate **real, benign platform artifacts** (DeviceTree properties, kernelcache strings, ioreg output) and re-narrate them as security disclosures. Claim 3 does the opposite: it uses weaker-looking metrics but states exactly what its evidence does and does not prove.

---

## Claim 1 — "The Always-On Blind Spot" (AOP2 / Rose)

### What verified TRUE on real A18 (t8140) firmware

| Claimed | Found locally (t8140, iOS 26.6) | Receipt |
|---|---|---|
| AOP as slave coprocessor via RTBuddy | DT node `arm-io/aop` (`iop,ascwrap-v6`) with child `iop-aop-nub` (`iop-nub,rtbuddy-v2`), `firmware-name: "v59aop"` | `dt_23g71.json` |
| `dart-aop` IOMMU with **`mapper-aop@0` + `mapper-exclave-aop@1`** | `arm-io/dart-aop` children: `mapper-aop` (reg 0), `mapper-exclave-aop` (**reg 1**), plus admac/scm mappers; reg base `0x100FC0000` (claim's `dart-aop@FC0000` = same low bits) | DT walk output |
| `AOP2Endpoint1..AOP2Endpoint24` (exactly 24) | **24** unique `AOP2Endpoint*` strings in the kernelcache; KDK `AppleAOP2.kext` Info.plist matches **verbatim** (IONameMatch list 1–24, `IOProviderClass: RTBuddyEndpointService`, `com.apple.driver.AppleAOP2`) | `kc.dec.strings`, KDK plist |
| `com.apple.driver.AppleAOP2` | 31 hits in kernelcache: `AppleAOP2Kext`, `AppleAOP2SystemDriver`, `AppleAOP2IOPMService`, `AppleAOP2KextTightbeamEndpoint` | `kc.dec.strings` |
| Coprocessor firmware codename **"Rose"** | **Real Apple bundle**: `Firmware/Rose/r2p1/ftab.bin` in the IPSW (magic `rkosftab`, 5 entries: `rkos`, `sbd1`, `bver`, `icnf`, `_osl`); `bver` = `236.2708120003000000.4388\|23.6.0.0\|date:2026 7 11\|chip_revision_b0`; `rkos` payload = full **RTKit-3255.160.4.release** image (FSM threads, assertions, panic paths); aopfw strings contain **"Rose Supervisor Service"** ("SUCCESS finding Rose Supervisor Service"); iBoot device path `aop/iop-aop-nub/rose` + `function-rose_coredump` | `Firmware/Rose/`, `aopfw_out/ubdl.bin` |
| Rose is a complete RTOS (page tables/heap/patchbay) | RTKit-3255 kernel + `RTK_*` API surface + string `PRNG !patchbay ecid=%llx` (the patchbay slot-fill mechanism is real RTKit) | `rose_rkos.bin`, `rtxt.bin.strings` |
| Ten embedded sensor programs (voice trigger, Doppler, ALS…) | aopfw strings: `DopplerFirmwareiPhone14b`, `VoiceTrigger ready!`, `CMSPUAmbientLightSensorPhone`, accelerometer orientation stack; DT: `aop-voicetrigger`, `aop-audio` services, ALS/GNSS nodes in the AOP sensor region | `aopfw_out/*.strings` |
| Exclave compartment + AOP↔Exclave bridge | DT: `aop-exclave-mailbox` (`iop,secure-rtbuddy-proxy`, **`exclave-service: com.apple.service.SecureRTBuddyAOP`**, `role: "AOP-EXCLAVE"`), `aop-exclave-ioreporting`, `exclave-sid` on dart-aop; kernelcache: **609 `exclave` strings** incl. `exclave_indicator_controller_metrics`; KDK ships `ExclaveKextClient.kext`, `ExclaveSEPManagerProxy.kext`, `ExclavesAudioKext.kext` | DT + kc + KDK |
| AOP firmware boots at power-on, always-on domain | `always-on` prop on dart-aop; AOP perf-counter/clk-gate fabric; iBoot references the rose node (iBoot loads AOP fw) | DT, iBoot strings |

### What is WRONG or UNVERIFIED in the writeup

1. **SoC identity is wrong.** "Apple A18 (t8150)" — locally, the A18 in iPhone 16e is **t8140** (`sptm.t8140.release`, `dart,t8110`-compat DARTs, `RTKitAudioDriversT8140` inside the AOP fw). Public spec sheets place **T8150 in the 2025 A19-Pro generation** (PhoneDB: "Apple A19 Pro APL1V12 T8150 (Thera)"). Either way, "A18 (t8150)" is not a valid pairing.
2. **Firmware format/name/hash mismatch.** Apple's AOP firmware ships as `aopfw-v59aop.RELEASE.im4p` — an RTKit **BUNDLE** (`BUND`) of segment images (`ktxt/rtxt/utxt/kdat/rdat/ubdl…`), not a flat "Mach-O 64-bit arm64 preload executable, NOUNDEFS" named `aopfw-rose.macho`. The quoted SHA-256 (`dc6bda7e…`) cannot be checked against any local Apple artifact and the filename it is attributed to does not exist in this form. The `_rtk_patchbay` "62 entries / 879 bytes" figure is unverifiable (no such binary locally), though the patchbay mechanism itself is real.
3. **Ownership overclaims.** On this die: **Bluetooth + Wi-Fi are Broadcom `BCM4387` on PCIe** (`wlan-pcie,bcm4387` under `pci-bridge*`) plus `arm-io/bluetooth` (`bluetooth,n88`) — not AOP-owned. **UWB** enumerates as `uwb`/`uwb0` *peripherals on AOP's SPMI power/control buses* (`aop-spmi0/1`) — a control/power plane, not radio ownership; the UWB radio is a separate die. **Touch** is its own RTBuddy coprocessor (`arm-io/mtp`, `iop-mtp-nub`, `dart-mtp`); AOP only hosts the `mtp-aop-mux` transport. Voice-trigger/Doppler/ALS/motion-assist: genuinely AOP-side. The mic path: `aop-audio` + voice trigger are AOP services — the mic-adjacency part of the claim is fair.
4. **The conclusion does not follow.** The writeup's own inventory shows the opposite of "nothing watches Rose": the Exclave fabric is precisely the mechanism that puts always-on sensor/audio work **outside the AP's reach** until a gate opens (wake-word etc.), and the kernelcache contains `exclave_indicator_controller_metrics` / `exclave_indicator_controller_chillpill_metrics_v1` — the privacy indicator is wired through the Exclave domain itself, i.e., a separate hardware-domain component sits between sensor capture and what apps can see. "Rose vouches for itself" ignores: signed SecureROM→iBoot→aopfw boot chain (Image4, per-component trustcache), the SEP's independent silicon witness (`SecureRTBuddyAOP_EDK`, `ExclaveSEPManagerProxy`), and the fact that an AP-side observer was never the countermeasure for coprocessors (it isn't for the SEP either, and nobody calls the SEP "structurally broken" for being a separate processor). The `mapper-exclave-aop` window is the **containment feature**, not a hole: it is how AOP DMA is scoped, not an open door into SEP material. Nothing in the writeup demonstrates AOP firmware tamper resistance being bypassed, a malicious-firmware vector, or any observer that a hardware indicator cannot override.
5. **"Verified Disclosure" status is self-assigned.** All quoted artifacts are stock enumeration — as the writeup itself admits ("no reverse engineering, no exploitation"). A trust-model opinion about a coprocessor is legitimate; labeling it "Verified Disclosure" of a privacy break is not supported by anything in the evidence chain.

**Claim-1 verdict: structure corroborated, conclusion unsupported.** The interesting true fact is that Rose/AOP2 with an Exclave DMA mapper and 24 endpoints is real and documented in every A15–A19-class device tree Apple ships. That is platform architecture, not a flaw.

---

## Claim 2 — "A17 Pro I2C4 Silicon Defect" (JGoyd/Apple-Silicon-A17-Flaw)

Repo verified to exist: `github.com/JGoyd/Apple-Silicon-A17-Flaw` (created 2025-09-03, 15 stars, Python; root = `A17 Pro Forensic Audit Tool.py` + README + `V1.0/` + `V2.0/`).

### The audit tool decoded

`A17 Pro Forensic Audit Tool.py` "detects" the Zombie state by four string matches on pre-extracted text files. Verification of each signal against **stock, healthy t8140 firmware**:

| "Indicator" in their tool | Reality on stock Apple silicon |
|---|---|
| `"RELEASE_ARM64_T8122" in kernel_identity_audit.txt` | Cross-SoC build tags are normal. The 23G71 (t8140/A18) kernelcache itself carries **33 `t8122` strings** (`AppleT8122USBXHCI`, `gpu,t8122`, …) — Apple compiles multi-SoC driver classes into one kernel. Most importantly, Apple ships **unified kernelcaches across same-generation SoCs** (Mac UKC practice: `kernel.release.t6020/t6031` pairs in the KDK); an A17-Pro-generation device whose shared cache is tagged `T8122` (the first chip of that generation) would show exactly their "smoking gun" on every healthy unit. DeviceTree is per-board and clean (0 t8122 hits in the t8140 DT), so the tag is a *kernel artifact*, not a per-device state. |
| `'"bypass-15" = <>' in memory_firewall_audit.txt` | **This is the fatal one.** `bypass-15` is a standard DeviceTree boolean property of `dart-dcp` and `dart-isp` on **t8140 too** (present-but-zero, ioreg prints it as `"bypass-15" = <>`). The DART kext's own strings: *"Obsolete 'sids', 'bypass', and/or 'bypass-address' properties present"* and *"full bypass mode not supported and bypass-%d property does not specify a bypass address"*. I.e., the property is a vestigial, always-off config knob — their tool would flag **every iPhone ever** as "memory firewall DISABLED". The quoted ioreg line is literally `+-o mapper-dcp@5 … IODARTMapper` — the *display* DART, present in every ioreg dump. |
| `"ACE Debug cannot be set. Missing boot-args." in logarchive_findings.txt` | This exact string is in the **stock t8140 production kernelcache** (AppleHPM/TC controller log line, fired whenever a USB-PD event requests LDCM/ACE-debug without dev boot-args). It is routine noise, not "silicon diagnosing its own catastrophic failure". |
| `"site.AppleSPUCT836" in content and "Ready" not in content` | `AppleSPUCT836` appears 8× in the stock t8140 kernelcache — a normal kext class string. |

### Mechanism-level refutations

- **"System switches from T8130 kernel to a T8122 kernel":** no such demotion machinery exists in any observable boot artifact; iBoot verifies a per-SoC-signed kernelcache from the Image4 trust chain, and the boot chain (iBSS/iBEC/iBoot, checked locally) contains zero T8122 references. Their own quoted ioreg (`Compatible = iPhone16,2, AppleARM, t8130`) is equally consistent with the benign UKC-sharing explanation.
- **"DART reconfigured to bypass-15 … enabling DMA-based exfiltration":** disproven above; additionally, `bypass-15` lives on the **display and ISP** DARTs, not on any DART associated with the claimed SEP/I2C4 path.
- **"Data partition mounts with NoEncryption":** the quoted `SYDStoreConfiguration: … type=NoEncryption` is a per-store SYDStore configuration type string — a normal class of log line — and a data partition mounting unencrypted while the SEP is "offline" would be an unbootable device (SEP-mediated file keys gate user data on every Apple-platform boot).
- **"SEP shares I2C4 with the digitizer":** on the sibling die, the SEP has its own DART (`dart-sep` + `mapper-sep-exclave`) and the digitizer is an independent MTP coprocessor; no artifact anywhere in the DT ties SEP init to a touch-controller bus.
- **"Inducible via VCC_MAIN fault injection during handover":** a bare assertion with no data, timeline, or reproduction; fault-injecting a power rail brown-outs silicon; it does not select a curated cross-SoC fallback kernel.

**Claim-2 verdict: UNSUPPORTED (effectively fabricated narrative around real benign artifacts).** Every one of its four "forensic signals" is present on healthy hardware, two of them verbatim in stock t8140 images. The "bypass-15 = firewall disabled" reading is contradicted by the DART driver's own strings. Nothing in the repo demonstrates a fault, a fallback, or a bypass — only that its author could grep.

---

## Claim 3 — A15 CAND-001 static research branch (iPhone14,6 / 19E241)

### Verified exactly

- `19E241` is a real iOS 15.4 build for iPhone14,6 (iPhone SE 3, A15/t8110/D49AP); Apple's CDN URL is still live (`updates.cdn-apple.com/…/iPhone14,6_15.4_19E241_Restore.ipsw`, 6,044,199,717 bytes); the build is **no longer signed** (ipsw.me: `signed: False`) — consistent with a "legacy restore" research target.
- HTTP-range extraction of `BuildManifest.plist` (ZIP64, ~282 KB) from the live IPSW reproduces their claims **to the digit**: ProductBuildVersion `19E241`; exactly **2 BuildIdentities**, both `d49ap` (`Erase` + `Update`); **80 components each**; iBSS/iBEC/iBoot/iBootData/LLB/SEP/RestoreSEP/DeviceTree/RestoreDeviceTree/KernelCache/RestoreKernelCache/RestoreRamDisk/BasebandFirmware all present. No component carries an in-manifest `EncryptionKey` (keys are ticketed, matching standard practice).
- The claimed component set ("iBSS, iBEC, iBoot, LLB, SEP, RestoreSEP, DeviceTree, kernel, baseband, restore ramdisk") is accurate.

### Not verifiable / concerns

- **The repository could not be located.** Searches for `T8110-CAND-001-STATIC-EVIDENCE`, `cand001-guard-provenance`, "CAND-001", "19E241 SecureROM static analysis" return nothing; GitHub code search without auth cannot confirm the listed run IDs (32417859667/32417859600/32417617161), artifact IDs, or digests. This report therefore cannot confirm the CFG metrics (27→89 instructions, 7→17 BBs, 3→13 compare→guard pairings, etc.) — they are presented as reported.
- **ROM provenance is the weak link.** A15-revision-pair SecureROM images (A15 A0 **and** A15 B0/B1) plus A14/A16 comparators are required for the cross-generation table. Known public SecureROM dump collections (securerom.fun, zzVertigo/SecureROMs) cover up to the A13 generation; retail A14/A15/A16 SecureROMs have never been part of the public dump sets, and per-stepping A15 ROM pairs would be even rarer. The branch's phrase "pinned public ROM sources" is therefore questionable unless the sources were private-then-redacted (which would itself explain the "redaction gates").
- **Assessment of the analysis, taking it at face value:** the metric set (instruction/BB/guard-branch deltas between ROM steppings) is weak-but-legitimate static triage; +7 "simple state/flag-validation-like guards" and a direct-call collapse are consistent with many benign causes (inlined validation, hardening, code motion). Their own caveat — "does not identify the validated field, establish attacker reachability, prove a vulnerability, or show that B0/B1 is a security fix" — is exactly right, and the "no exploit, research-only" boundary statement is credible.

**Claim-3 verdict: manifest facts VERIFIED; analysis artifacts UNVERIFIABLE (repo not found); ROM provenance CONCERN; epistemics honest.** Of the three, this is the only one that should be treated as genuine (if unverifiable) research, and even it explicitly claims no vulnerability.

---

## Method notes / reproducibility

All local commands are standard tooling (`ipsw` 3.1.706, `strings`, `shasum`, `plutil`, python3 zipfile/plistlib + raw HTTP Range):

```
ipsw dtree -j DeviceTree.v59ap.im4p          # DT → JSON (walk 'children' lists)
ipsw kernel dec kernelcache.release.v59      # payload is compressed; strings on the RAW file are useless
ipsw fw aop -i / -o aopfw_out aopfw-v59aop.RELEASE.im4p   # AOP bundle → ktxt/rtxt/…/ubdl segments
unzip -l <ipsw> | grep -iE 'aop|rose'        # Firmware/AOP/, Firmware/Rose/r2p1/ftab.bin, all_flash/DeviceTree*
# 19E241 manifest: Range GET EOCD → ZIP64 central directory → local header → inflate BuildManifest.plist
```

Key hashes (receipts):
- `aopfw-v59aop.RELEASE.im4p` SHA-256 `d0fb1c4cb823efe2b2b74f6aeb057aa3bea87c7dd6ca68f50eefb0941b569004`
- `Rose/r2p1/ftab.bin` SHA-256 `937db4c5a9f798595454755413f650d4b36c632c77446419c221a741cdd3da5c`

## What would change these verdicts

- Claim 1: a reproducible Rose-side misbehavior (a TamperResistant-boot-invalid aopfw accepted by a device, an indicator state contradicting Exclave-side reporting, or a documented SEP/Exclave revocation path AOP can bypass). An ioreg dump proves topology, not compromise.
- Claim 2: a genuine sysdiagnose from an A17 Pro device in a *broken* state showing kernel-tag **changes across boots on the same unit**, plus any artifact of a demotion code path (iBoot/xnu). A `bypass-N` property in a healthy ioreg proves nothing — it is in every one.
- Claim 3: the repo URL (or any mirror) with the listed workflow artifacts, and the actual ROM source manifest for the A14/A15A0/A15B0/A16 set.
