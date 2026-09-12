# ios-boundary-research

iOS privileged-boundary research across system services, kernel-facing interfaces, and the iBoot boot chain — with reproducible harnesses, on-device validation, security findings, and negative results.

> [!IMPORTANT]
> ### Vendor disposition — the iBoot findings were closed by Apple
> Every iBoot finding in this repository was submitted to Apple Product Security (26 Aug – 02 Sep 2026) and **every one was closed as not a security issue**. Apple's reasoning is consistent: the decoder behavior described is real, but no attacker-controlled path to that code on a device was demonstrated — and one report's headline number was shown to be a harness artifact rather than a decoder property. The verbatim triage responses are recorded in [Vendor disposition](#vendor-disposition--apple-product-security) below.
>
> These findings are retained as research and negative results, not as confirmed vulnerabilities.

> [!NOTE]
> ### Open Research
> The single unresolved question across this campaign is **attacker-controlled delivery**: a demonstrated on-device path that feeds untrusted bytes to the affected boot-stage code. Contributions that establish such a path, eliminate a remaining false positive, or demonstrate concrete security impact are welcome.


> **Research note**
>
> This repository is research-assisted by AI agents (GLM-5.3-Flash, Qwen3.8-Flash-Next, GLM 5.3, and DeepSeek-V4.1-Flash), with findings checked against static analysis and on-device evidence.
>
> AI-generated hypotheses are not treated as confirmed vulnerabilities solely on the basis of model output. Security claims should be independently reproduced and evaluated against the corresponding evidence, including reachability and demonstrated security impact.

> **Read `AGENTS.md` first** if you are an agent or new contributor — it contains the file paths, build/verify loop, static-analysis toolbox, and editing gotchas learned during the research.
>
> Findings + verdicts: `FINDINGS.md`
> Version history: `VERSIONS.md`

---

## Vendor disposition — Apple Product Security

The iBoot/boot-chain reports in this repository were submitted to Apple Product Security between 26 Aug and 02 Sep 2026. **All of them were closed as not a security issue.** The responses below are reproduced verbatim; they are the authoritative assessment of these findings.

| Report | Apple ID | Submitted | Outcome | Apple's stated reason (verbatim) |
| --- | --- | --- | --- | --- |
| `Report1_DEFLATE/` | OE11073045811 | 26 Aug 2026 | Closed — not a security issue | *"The code does behave the way you describe, but this part of the startup process only handles data that has already been checked as genuine, and the route you outline for getting untrusted data there depends on a separate flaw that hasn't been shown to work. Without a real way for an attacker to reach this code on a device we aren't treating it as a security issue."* |
| `Report2_LZVN/` | OE110730442251 | 26 Aug 2026 | Closed — no vulnerability confirmed | *"…standard boot image loads verify signatures before decompression, and no attacker path to the decoder is demonstrated here."* Plus a direct refutation of the report's headline figure: *"The 65,536 byte figure comes from the harness rather than the decoder. In `qsweep.c` the `b0w` cell seeds only the first `dcap` bytes with `0x11`, but the dirty-span loop scans `dcap + 65536`, so the `0x5A` apron always counts as dirty. That is why `capSpanOOB` is exactly 65536 at every capacity tested."* |
| `Report3_LZFSE/` | OE110730468001 | 26 Aug 2026 | Closed — not a security issue | *"The data shown is read-only and is also not readily available to the attacker."* |
| `Report4_SPLT/` (submitted as the delivery argument for the decoder reports) | — | 26–27 Aug 2026 | Not accepted as a delivery path | *"The splt package restates the precondition rather than removing it. Your own analysis gives the requirement as control of the staged blob during manufacturing or upgrade staging, gated by hardware policy. The evidence provided is a host harness that calls selected firmware routines directly, with the algorithm identifier and loader context supplied by the harness rather than by the container, so it does not show the boot loader reaching that code with attacker supplied input. … The attack position is stated as a precondition rather than demonstrated."* |
| `Report5_HOMING/` | — | — | No disposition in this correspondence | — |
| `Report6_NVRAM/` | OE1107324358640 | 31 Aug 2026 | Closed — not actionable | *"This is not an actionable security report without evidence of it reproducing a security or privacy impact to a user on-device."* |
| `REPORT_M2SCALER.md` (`AppleM2ScalerCSCDriver`) | OE110768579232 | 02 Sep 2026 | Closed — no out-of-bounds access | *"After review, the validation gap that you observed does not result in an out-of-bounds access."* |

### What this changes in the repository

* **The findings are retained as research results, not vulnerabilities.** The disassembly citations, harnesses, and reproduction receipts are unchanged and still check out; what is *not* established is attacker-controlled delivery (or, for the M2Scaler validation gap, an out-of-bounds access at all).
* **One headline number is corrected.** `Report2_LZVN`'s `capSpanOOB` / `OOBpast4K = 65536` is a **harness measurement artifact** — the sweep's dirty-span window scanned `dcap + 65536`, so the marker apron always registered as dirty regardless of decoder behavior. The fault receipts (PC/LR offsets, signal class, the copy running past the destination) are unaffected; the claim that the overflow is "≥64 KB past any tested capacity" is not supported by that evidence. See the note at the top of `Report2_LZVN/README.md`.
* **The delivery question stays open, explicitly.** `DELIVERY_PATHS_24A435.md` remains the honest boundary document: the standard signed-image path was tested and found honest (auth-before-decode), and the staging-class paths depend on the `splt` container flaw that Apple declined to accept as reachable.

---

## Repository layout

| Path                                                     | What it is                                                                                                |
| -------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `DirtySlide/`, `UI/`, `src/`, `Makefile`                 | Xcode app and payload sources — the Part 1 iOS research harness and the Part 2 macOS LPE                  |
| **[`analysis/`](#analysis--per-front-working-evidence)** | Per-target working evidence: one Markdown file per reverse-engineering front                              |
| **[`ios26.6iboot-bugs/`](#ios-266-iboot-campaign)**      | The iOS 26.6 iBoot research campaign: six numbered reports, the on-device run kit, and raw crash evidence |
| `PocRunner/`, `poc_65346.c`, `poc_vendors/`              | PoC sources and the PoC runner app                                                                        |
| `scripts/`                                               | Analysis tooling — Binary Ninja helpers, string-reference locator, `.ips` decoder, and supporting scripts |
| `REPORT_*.md`, `FINDINGS.md`, `VERSIONS.md`, `AGENTS.md` | Campaign reports, findings, version history, and contributor/agent handbook                               |

> Compiled PoC binaries (`*.ipa`, `poc_65346_ios`), the local Python virtual environment, and the `.codegraph` index are gitignored — see `.gitignore`.

---

## Evidence model

The repository deliberately separates **observed behavior**, **security primitives**, **attacker reachability**, and **security impact**.

A crash or memory-safety primitive is not automatically treated as a confirmed vulnerability. Where relevant, reports distinguish between:

* **Observed** — behavior reproduced on-device or otherwise directly verified.
* **Primitive** — a memory-safety or control-flow primitive has been demonstrated.
* **Reachability** — a realistic attacker-controlled path to the affected code has been demonstrated.
* **Impact** — a concrete security or privacy consequence has been demonstrated.
* **Unresolved** — an important prerequisite remains unproven.
* **Negative result** — the investigated hypothesis did not produce the expected security impact.

This distinction is especially important for the iBoot research, where demonstrating a vulnerable decoder is separate from demonstrating that an attacker can supply data to that decoder during a real boot path.

---

## `analysis/` — per-front working evidence

One file per reverse-engineering front, holding the raw disassembly references, offsets, observations, and confidence labels behind the headline reports.

Grouped by target:

* **AppleAVD / VideoToolbox decode** — `avd_gates.md`, `avd_flag_lead.md`, `avd_lgh_lead.md`, `avd_patch_descriptors.md`, `avd_pps_workbuf.md`, `avd_tiles.md`
* **Face ID bracket** — `fid_bracket.md`, `fid_node.md`, `fid_cve_closure.md`
* **AppleJPEGDriver** — `jpeg_encoder_overflow.md`, `jpeg_iostruct.md`, `jpeg_userclient.md`
* **Kernel / kext command buffers** — `kext_cmdbuf_alloc.md`, `kext_decodebuffer_patch.md`, `kext_frameparam_link.md`, `kext_patch_applier.md`, `kernel_ucoredump.md`
* **M2ScalerCSC** — `m2scaler_cmdbuf.md`, `m2scaler_math.md`
* **Pearl (secure element)** — `pearl_magic.md`, `pearl_payload.md`
* **SAR (sensor arbitration)** — `sar_externals.md`, `sar_write_index.md`
* **USB host-controller** — `usb_commandring.md`, `usb_descriptors.md`
* **VCPHEVC** — `vcphevc_file_parsers.md`, `vcphevc_profile_parser.md`, `vcphevc_recursion_verify.md`
* **UserClient / WebKit** — `uc_jpeg_userclient.md`, `uc_webkit.md`, `uc_webcore_wellknown_parser.md`
* **Row M (IOGPU UAF 64788)** — `row_m_iogpu_uaf_snippet.m`

---

## iOS 26.6 iBoot campaign

The iBoot/boot-chain research is structured as six self-contained reports plus the tooling used for on-device validation.

| Folder             | Research target                                                             | Vendor outcome                                  |
| ------------------ | --------------------------------------------------------------------------- | ----------------------------------------------- |
| `Report1_DEFLATE/` | DEFLATE decompressor                                                        | Closed — delivery unproven (OE11073045811)      |
| `Report2_LZVN/`    | LZVN decompressor                                                           | Closed — delivery unproven; one figure refuted (OE110730442251) |
| `Report3_LZFSE/`   | LZFSE decompressor                                                          | Closed — read-only, not attacker-available (OE110730468001) |
| `Report4_SPLT/`    | SPLT / staged-container handling                                            | Not accepted as a delivery path                 |
| `Report5_HOMING/`  | HOMING boot-stage logic                                                     | No disposition in this correspondence           |
| `Report6_NVRAM/`   | NVRAM persistence and validation                                            | Closed — no on-device impact shown (OE1107324358640) |
| `DeviceRunKit/`    | On-device execution kit: payloads, control images, results, and run scripts | —                                               |

Supporting documents include:

`DELIVERY.md`
`DELIVERY_PATHS_24A435.md`
`IBEC_IBSS_24A435.md`
`RECHECK_24A435_mBoot-20457.2.37.md`
`PUBLISH.md`

The tree also contains raw **on-device crash evidence**, including tracked `.ips` reports and device logs used to validate the reported behavior.

The evidence establishes the behavior tested by each report; attacker reachability and security impact are assessed separately and are not inferred from a crash alone. All six reports were submitted to Apple Product Security and **closed as not a security issue** — see [Vendor disposition](#vendor-disposition--apple-product-security).

---

## The iOS research harness — "Privileged Boundary Hunter"

A plain Xcode app whose table rows each run a probe suite against system services.

Probes print timestamped console receipts per row. Runs are guard-recovered (`SIGSEGV` / `SIGBUS` / `SIGILL` / `SIGTRAP` / `SIGABRT` → the app itself remains alive) and end with stability measurements.

The target daemon (`videocodecd` / `mediaremoted`) may crash — that is an expected research oracle. New `.ips` reports are correlated with the probe row that was running using:

```text
captureTime <-> [stamp]
```


## Research status

The repository intentionally contains both positive and negative results.

A finding appearing in the repository does **not** by itself mean that Apple, a CVE authority, or the author considers it a confirmed exploitable vulnerability.

In particular, the iBoot findings demonstrate interesting memory-safety behavior while leaving attacker-controlled delivery or end-to-end security impact unresolved. Those cases are retained because the underlying reverse-engineering and negative conclusions are useful research results — and because the vendor disposition on them is itself a result: **Apple reviewed all six and closed every one**, with the delivery path (not the decoder behavior) as the consistent blocker.

The most useful next contributions are therefore: a demonstrated on-device delivery path into the boot-stage decoders, a correction of any remaining measurement artifact of the kind Apple identified in `Report2_LZVN`, or a concrete security impact for the persisted-NVRAM integrity gap.

See [Vendor disposition](#vendor-disposition--apple-product-security) for the verbatim triage responses, `FINDINGS.md` for the current verdicts, and `VERSIONS.md` for campaign history.

---

## Credits

* **khanhduytran0** — [DirtySlide](https://github.com/khanhduytran0/DirtySlide), the original macOS LPE this repository is forked from. The Part 2 payload, app scaffold, and iOS port are his work.
* **forcequitOS** — [bad_query](https://github.com/forcequitOS/bad_query), the ContainerManager class-13 sandbox escape. The escape primitive used in the `E. DAEMON-CACHE` row and the v126 IK row is a port of that PoC; it was confirmed live on iOS 27.0 beta 24A5355q and later fixed in 24A435 RC.

Prior campaign history (v10–v175) is documented in `VERSIONS.md`.

Per-front reverse-engineering evidence is in `analysis/`.

---

## Disclaimer

This repository is a research archive, not a claim that every investigated behavior constitutes a security vulnerability.

Reproduction should be performed only on devices and software that you are authorized to test. Security impact should be evaluated from the complete chain — affected code, attacker-controlled input, realistic reachability, and demonstrated impact — rather than from isolated crashes or primitives.
