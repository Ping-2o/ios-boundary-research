> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

> **Read `AGENTS.md` first** if you are an agent or new contributor — it has the file
> paths, build/verify loop, static-analysis toolbox, and every editing gotcha we learned.
> Findings + verdicts: `FINDINGS.md`. Version history: `VERSIONS.md`.

---

## Repository layout

| Path | What it is |
|---|---|
| `DirtySlide/`, `UI/`, `src/`, `Makefile` | the Xcode app and payload sources — the Part 1 harness and the Part 2 macOS LPE |
| **[`analysis/`](#analysis--per-front-working-evidence)** | per-target working evidence: one markdown file per reverse-engineering front |
| **[`ios26.6iboot-bugs/`](#ios266iboot-bugs--the-ios-266-iboot-campaign)** | the iOS 26.6 iBoot bug campaign: 6 numbered reports, the on-device run kit, and the raw crash evidence |
| `PocRunner/`, `poc_65346.c`, `poc_vendors/` | PoC sources and the PoC runner app |
| `scripts/` | analysis tooling — Binary Ninja helpers, the string-ref locator, the `.ips` decoder |
| `REPORT_*.md`, `FINDINGS.md`, `VERSIONS.md`, `AGENTS.md` | campaign reports, findings, version history, and the agent handbook |

> Compiled PoC binaries (`*.ipa`, `poc_65346_ios`), the local Python venv, and the
> `.codegraph` index are all gitignored — see `.gitignore`.

### `analysis/` — per-front working evidence

One file per reverse-engineering front, holding the raw disassembly quotes, offsets, and
confidence labels behind the headline reports. Grouped by target:

- **AppleAVD / VideoToolbox decode** — `avd_gates.md`, `avd_flag_lead.md`, `avd_lgh_lead.md`,
  `avd_patch_descriptors.md`, `avd_pps_workbuf.md`, `avd_tiles.md`
- **Face ID bracket** — `fid_bracket.md`, `fid_node.md`, `fid_cve_closure.md`
- **AppleJPEGDriver** — `jpeg_encoder_overflow.md`, `jpeg_iostruct.md`, `jpeg_userclient.md`
- **Kernel / kext command buffers** — `kext_cmdbuf_alloc.md`, `kext_decodebuffer_patch.md`,
  `kext_frameparam_link.md`, `kext_patch_applier.md`, `kernel_ucoredump.md`
- **M2ScalerCSC** — `m2scaler_cmdbuf.md`, `m2scaler_math.md`
- **Pearl (secure element)** — `pearl_magic.md`, `pearl_payload.md`
- **SAR (sensor arbitration)** — `sar_externals.md`, `sar_write_index.md`
- **USB host-controller** — `usb_commandring.md`, `usb_descriptors.md`
- **VCPHEVC** — `vcphevc_file_parsers.md`, `vcphevc_profile_parser.md`, `vcphevc_recursion_verify.md`
- **UserClient / WebKit** — `uc_jpeg_userclient.md`, `uc_webkit.md`, `uc_webcore_wellknown_parser.md`
- **Row M (IOGPU UAF 64788)** — `row_m_iogpu_uaf_snippet.m`

### `ios26.6iboot-bugs/` — the iOS 26.6 iBoot campaign

The iBoot/boot-chain bug hunt, structured as six self-contained reports plus the tooling
used to reproduce them on a real device:

| Folder | Report |
|---|---|
| `Report1_DEFLATE/` | DEFLATE decompressor |
| `Report2_LZVN/` | LZVN decompressor |
| `Report3_LZFSE/` | LZFSE decompressor |
| `Report4_SPLT/` | SPLT (splat) handling |
| `Report5_HOMING/` | HOMING boot-stage logic |
| `Report6_NVRAM/` | NVRAM handling |
| `DeviceRunKit/` | on-device execution kit: payloads, control images, results, and the run scripts |

Supporting documents: `DELIVERY.md`, `DELIVERY_PATHS_24A435.md`, `IBEC_IBSS_24A435.md`,
`RECHECK_24A435_mBoot-20457.2.37.md`, and `PUBLISH.md`. This tree also carries the raw
**on-device crash evidence** — the tracked `.ips` reports and device logs that back every
claim in the reports (the `.zip` bundles are gitignored; rebuild them from the folders).

---

## the iOS research harness ("Privileged Boundary Hunter")

A plain Xcode app whose table rows each run a probe suite against system services.
Probes print timestamped console receipts per row; runs are guard-recovered
(SIGSEGV/BUS/ILL/TRAP/ABRT → the app never dies) and end with stability beats. **The
daemon (`videocodecd` / `mediaremoted`) may crash — that is the goal; correlate new
`.ips` to the row that was running via `captureTime <-> [stamp]`.**

### Buttons (6 rows — v142, the iOS 26.6 A-D regroup)

| Row | Target |
|---|---|
| A. AVE T-KILL 26.6 | The daemon-kill factory: 14 hostile-container cells on the symbol-pinned 23G71 abort sites — the 10 unconditional `CFNumberGetValue` keys in `AVE_GetPerFrameData` @0x2a05881d0 (incl. NEW POCLsb / CalculateYUVChecksum / MarkCurrentFrameAsLTR / the SliceQP scalar twin), `UserQpMap` (no type check @0x8948), `SetDPB` (bare `CFArrayGetCount` @0x2a05a1f54), `ReferenceL0` element-conf (the 7/7 .ips witness, LAST). The .ips is the receipt |
| B. AVE OOB-PRIMITIVE 26.6 | The multipass mode==1 unchecked `memmove(stats, blob, 1574)` @0x2a060e99c fed a <1574B blob via the PUBLIC `VTMultiPassStorageSetDataAtTimeStamp` = a daemon heap OOB READ feeding kernel-bound RC structs (the info-leak candidate). B01 short-blob / B02 1574-gate / B03 seq+round-trip |
| C. AVE KERNEL-QP 26.6 | The QP-map channel repro (M3 exact-size 130560 + the +455B side-channel + the clean SInt32@0 value axis +1/−255/INTMAX), the 3 SURVIVING ungated Prepare fields (MCTFEdgeCount / FilterGroupSize / AmbientViewingEnvironment INTMAX), the userDPB 2..17 boundary. Zero-death by design; the kernel log is the oracle |
| D. AVE NEW-SURFACES 26.6 | The never-fired 23G71 surfaces: the 21-key `DPB_*` per-frame family (incl. `DPB_ReferenceFrames_IOSurfaceID`), `FirstMbInRecvSlices` (the CFData multi-slice driver), the HEVC H9 keys `NaluType`/`TemporalID`, and the vt_Copy NULL-plane blitter repro (guard-free `ldrb` @fn+0x40 on 23G71) |
| E. DAEMON-CACHE escape | The bad_query class-13 sandbox-escape receipts (proven 4/4 on 26.x) — the support primitive for the MG row |
| F. MobileGestalt 64747 | The device-identity spoof via the escape (O_RDWR on the MG cache plist); a REBOOT-SURVIVING devType flip = a controllable kernel-config input (the UserQpMap size formula branches on devType). The reboot test is the verdict |


## Credits

- **khanhduytran0** — [DirtySlide](https://github.com/khanhduytran0/DirtySlide), the original macOS LPE this repo is forked from. The Part 2 payload, the app scaffold, and the iOS port are his work.
- **forcequitOS** — [bad_query](https://github.com/forcequitOS/bad_query), the ContainerManager class-13 sandbox escape. The escape primitive in `E. DAEMON-CACHE` row and the v126 IK row is a port of that PoC; confirmed live on iOS 27.0 beta 24A5355q and fixed in 24A435 RC.

Prior campaign history (v10–v175) is in `VERSIONS.md`. Per-front evidence is in `analysis/

# ios-boundary-research
iOS privileged-boundary research — VideoToolbox/AVE findings, DoS primitives, and negative results from iOS 26–27.


