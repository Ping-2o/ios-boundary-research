> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# AppleSARService — IOUserClient external-method OOB-write audit

Target: `com.apple.driver.AppleSARService`, iOS 27.0 RC (build 24A435)
Tool: Binary Ninja (MCP, read-only). No Ghidra / IDA.
Binary view: `view_7`, Mach-O kext, aarch64 / mac-aarch64,
image `0xfffffff0076cdd30` … `0xfffffff00b9fc030`.

Constraints observed: `bn_binary_view_set_active` and `bn_open_item_open` were **not** called
(shared view). All evidence below is from read-only queries.

---

## 0. Bottom line

**No out-of-bounds kernel write was found through any `AppleSARServiceUserClient`
external method.** The four methods named in the task — `extSARSensingCAInfo`,
`extSARSensingCACurrentState`, `extSARSensingCALastSubmit`, `extStateABOsiris` —
plus `extSarRFSensingSignal` **all validate `structureOutputSize` before writing**,
and each writes exactly the number of bytes it validates. The new
`"output size mismatch"` string is the *fix* for the reference method; the sibling
methods already carried equivalent checks.

The `"Current Write Index is out of the bound"` lead is **REFUTED** (see §7) — it is
internal ring-buffer bookkeeping in `enqueueFlushSnapshotGated`, not reachable from a
user client.

A clean negative is the result here.

---

## 1. Job #1 — the static `IOExternalMethodDispatch` table was NOT located

I could not find a static `IOExternalMethodDispatch[]` array in this kext.
This is a genuine negative, with concrete evidence:

| Location | Size | What it actually contains |
| --- | --- | --- |
| `__TEXT,__const` @ `0xfffffff0076f3418` | `0x1286` | Numeric constant pool. Starts `6400 0400 1e00 1e00 … 00000040 00000000` (`0x40000000`), then `06 aaaa…`, `ff aaaa…` masks, and short literals `"OCP"`, `"OCP5"`. `bn_data_variable_list` over the whole section returns 49 entries at an 8-byte stride — a constants pool, not a 24-byte-stride dispatch array. |
| `__DATA_CONST,__const#10` @ `0xfffffff008112678` | `0xdd08` | PAC/chained-fixup pointer metadata: 8-byte values with bit 63 set (e.g. `f87d4502 71371180` → `0x8011377102457df8`), plus repeated records `{0x54, 0x00400000006f7627, 0, 0}`. C++ vtable / class metadata, not `IOExternalMethodDispatch`. No run of 80 entries whose targets fall in the handler cluster. |
| all 17 sections (`bn_section_list`) | — | No `__ios`, no extra dispatch section. |

Corroborating tool blindness (pre-existing limitation of this view):

- `bn_data_xrefs_to 0xfffffff0076fe334`, `…6fe510`, and code `0xfffffff00948d500` → **0 rows**.
- `bn_function_callers 0xfffffff00948d500` → **0 rows** (handlers are table/switch-indirect).
- `bn_symbol_list query="ext"` → only `__macho_header__TEXT*` internals; no method/table symbols.
- `bn_function_search "external"` → 0 (previously established).

**Consequence:** selector indices below are reconstructed from the handler cluster and
the `__cstring` name strings; the per-entry declared `scalarIn/structInSize/scalarOut/structOutSize`
**could not be read from a table**. Job #5 is therefore answered by inference (§5).

---

## 2. The external-method handler cluster and the 80 method names

`__text` contains 81 contiguous functions with signature
`int64_t(int64_t* arg1, int64_t arg2, void* arg3)` (i.e.
`IOExternalMethodAction` = `(target, reference, IOExternalMethodArguments*)`),
addresses `0xfffffff009481970` … `0xfffffff009495c88`, spacing ≈ `0x3ec` (not uniform).
A 82nd same-signature function sits outside the cluster at `0xfffffff0094d87f4`
(auto-discovered, 73 BB) — a worker, not a handler.

`__cstring` contains exactly **80** strings of the form
`static IOReturn AppleSARServiceUserClient::ext<Name>(AppleSARService *, void *, IOExternalMethodArguments *)`.
In address order (this is the source/selector order):

| # | name string @ | method | | # | name string @ | method |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 0x76fb255 | extGetSPMIEventTrackingArray | | 41 | 0x76fde20 | extSarServiceProfile |
| 2 | 0x76fb311 | extRegisterReceivingKernelMessage | | 42 | 0x76fdeb7 | extUpdateAudio |
| 3 | 0x76fb87e | extWiFiState | | 43 | 0x76fdf9f | extUpdateScreenState |
| 4 | 0x76fb9a7 | extBTState | | 44 | 0x76fe04c | extUpdateOrientation |
| 5 | 0x76fba15 | extThreadState | | 45 | 0x76fe140 | extAntennaOnTop |
| 6 | 0x76fba87 | extAccessoryState | | 46 | 0x76fe1da | extUpdateOcclusion |
| 7 | 0x76fbb71 | extSARSelectionTunerState | | 47 | 0x76fe2bb | extSarRFSensingSignal |
| 8 | 0x76fbdb5 | extSARSelectionState | | 48 | 0x76fe3ba | extStateABTuner |
| 9 | 0x76fbede | extVoiceState | | 49 | 0x76fe49c | extStateABOsiris |
| 10 | 0x76fc007 | extTunerState | | 50 | 0x76fe57b | extVSWRLearning |
| 11 | 0x76fc0f2 | extSpeakerState | | 51 | 0x76fe65d | extVSWROnlyMode |
| 12 | 0x76fc1d2 | extGripState | | 52 | 0x76fe73a | extSARBlockedRegion |
| 13 | 0x76fc2a3 | extPowerState | | 53 | 0x76fe80c | extPTDRegisterInterrupt |
| 14 | 0x76fc379 | extWristState | | 54 | 0x76fe89c | extPTDUnRegisterInterrupt |
| 15 | 0x76fc44f | extSARConsumed | | 55 | 0x76fe930 | extPTDGetDebugInfo |
| 16 | 0x76fc52a | extMPEConsumed | | 56 | 0x76fe9b6 | extConnectivitySarBudget |
| 17 | 0x76fc605 | extRegulatory | | 57 | 0x76fea6b | extConnectivityRegulatoryInfo |
| 18 | 0x76fc6df | extARBuffer | | 58 | 0x76feb2f | extConnectivitySarReport |
| 19 | 0x76fc7ab | extCentralSAR | | 59 | 0x76febe4 | extCentralWiFi |
| 20 | 0x76fc881 | extCentralMPE | | 60 | 0x76fec7b | extCentralBT |
| 21 | 0x76fc957 | extCentralTER | | 61 | 0x76fed0c | extCentralTotalSAR |
| 22 | 0x76fca3a | extRegulatoryLimit | | 62 | 0x76fedaf | extCentralTotalMPE |
| 23 | 0x76fcb36 | extRegulatoryAverage | | 63 | 0x76fee52 | extWifiSAR |
| 24 | 0x76fcc43 | extCellularSAR | | 64 | 0x76feedd | extBtSAR |
| 25 | 0x76fcd8b | extCellularMPE | | 65 | 0x76fef62 | extTotalSAR |
| 26 | 0x76fcea5 | extConnectivitySAR | | 66 | 0x76feff0 | extTotalMPE |
| 27 | 0x76fcfa1 | extConfigHSAR | | 67 | 0x76ff07e | extCellularBudget |
| 28 | 0x76fd1c9 | extConfigSARFusion | | 68 | 0x76ff11e | extConnectivityResidual |
| 29 | 0x76fd2bd | extSARFusionStateINT | | 69 | 0x76ff1d0 | extWifiResidual |
| 30 | 0x76fd3c2 | extSARFusionStateMAV | | 70 | 0x76ff26a | extBtResidual |
| 31 | 0x76fd4c7 | extSARFusionStateDAL | | 71 | 0x76ff2fe | extCellularHSARSupported |
| 32 | 0x76fd5cc | extUpdateE85MitigationRequest | | 72 | 0x76ff39d | extConnectivityHSARSupported |
| 33 | 0x76fd722 | extBlockAccessories | | 73 | 0x76ff444 | extCentralUWB |
| 34 | 0x76fd799 | extSARTransitionWaitTime | | 74 | 0x76ff4d8 | extUWBRadio |
| 35 | 0x76fd885 | extAntennaClusterConfig | | 75 | 0x76ff566 | extUWBActive |
| 36 | 0x76fd98c | extCallState | | 76 | 0x76ff5f7 | extBudgetScalingFactor |
| 37 | 0x76fda5d | extCellularSARBoostState | | 77 | 0x76ff6a6 | extSARSensingCAInfo |
| 38 | 0x76fdad9 | extFaceDetection | | 78 | 0x76ff791 | extSARSensingCACurrentState |
| 39 | 0x76fdbc0 | extFrontCameraState | | 79 | 0x76ff828 | extSARSensingCALastSubmit |
| 40 | 0x76fdcb1 | extUplinkConstraintCondition | | 80 | 0x76ff8de | extoverrideUseCaseDetection |

(`#` = position in `__cstring` order = presumed selector index; addresses are
`0xfffffff0076f…` truncated.)

### 2.1 Verified selector → handler-address mapping

Mapping was established by decompiling each handler and reading its **embedded log
string** (the method's own name). Every handler logs
`"%s:%d: One of these is NULL: sarService: %p, reference: %p, arguments: %p\n"` on
bad input, so the name is unambiguous.

`__text` order does **not** exactly equal source order: two legacy methods
(`extGetSPMIEventTrackingArray`, `extRegisterReceivingKernelMessage`) are emitted out
of place (their log format uses only two pointers — `…sarService: %p, reference: %p\n`
and `…sarService: %p, me: %p\n` — which is how they were identified).

| selector | method | handler (`ext<Name>`) | verified by |
| --- | --- | --- | --- |
| 3 | extWiFiState | `0xfffffff009481970` | log string, line 0x49 |
| 4 | extBTState | `0xfffffff009481c80` | line 0x4a |
| 5 | extThreadState | `0xfffffff009481f90` | line 0x4b |
| 31 | extSARFusionStateDAL | `0xfffffff009489478` | line 0x90 |
| 32 | extUpdateE85MitigationRequest | `0xfffffff009489864` | line 0x91 |
| 33 | extBlockAccessories | `0xfffffff009489c50` | line 0x69 |
| 2 | extRegisterReceivingKernelMessage | `0xfffffff009489f50` | line 0x28f; tail-calls `registerCallback` |
| 34 | extSARTransitionWaitTime | `0xfffffff00948a018` | line 0x6b |
| 35 | extAntennaClusterConfig | `0xfffffff00948a4ec` | line 0x6c |
| 36 | extCallState | `0xfffffff00948a9c0` | line 0x6d |
| 37 | extCellularSARBoostState | `0xfffffff00948ae94` | line 0x6e |
| 38 | extFaceDetection | `0xfffffff00948b1a4` | line 0x9b |
| 39 | extFrontCameraState | `0xfffffff00948b590` | line 0x9c |
| 40 | extUplinkConstraintCondition | `0xfffffff00948b97c` | line 0x76 |
| 41 | extSarServiceProfile | `0xfffffff00948be50` | line 0x77 |
| 43 | extUpdateScreenState | `0xfffffff00948c550` | line 0xab |
| 44 | extUpdateOrientation | `0xfffffff00948c93c` | line 0xac |
| 45 | extAntennaOnTop | `0xfffffff00948cd28` | line 0xad |
| 46 | extUpdateOcclusion | `0xfffffff00948d114` | line 0xae (`"rfOcclusion"`) |
| **47** | **extSarRFSensingSignal** | **`0xfffffff00948d500`** | line 0xaf |
| **49** | **extStateABOsiris** | **`0xfffffff00948dcd8`** | log string |
| **77** | **extSARSensingCAInfo** | **`0xfffffff009494cd8`** | log string |
| **78** | **extSARSensingCACurrentState** | **`0xfffffff0094950c4`** | log string |
| **79** | **extSARSensingCALastSubmit** | **`0xfffffff0094954b0`** | log string |
| **80** | **extoverrideUseCaseDetection** | **`0xfffffff00949589c`** | log string |
| — | *(not an ext method)* `registerCallback` | `0xfffffff009495c88` | log string |

Handler addresses for the ~55 methods not listed were **not individually confirmed**
and are deliberately omitted rather than guessed. The cluster-address list is available
and the ordering rule is `C = N-2` for N∈[3,5], interleaved with selectors 1–2,
and `C = N` for N ≥ 34.

---

## 3. Job #2/#3/#4 — per-method output-size validation verdicts

### Reference: `extSARSensingCACurrentState` (selector 78)

`0xfffffff0094950c4` is a 24-instruction tail-call stub that forwards
`(service, scalarInput, structureInput, structureInputSize, scalarOutput,
scalarOutputCount, structureOutput, structureOutputSize)` to
`vtable[0x548]`, i.e. **`sub_fffffff0094d64b0`** (`rfSensingCACurrentState`).

`sub_fffffff0094d64b0` — the check that IS present (this is the new one):

```asm
0xfffffff0094d64c8  cbz     x1, 0xfffffff0094d6588        ; scalarInput == NULL -> err
0xfffffff0094d64cc  ldr     w8, [x1]
0xfffffff0094d64d0  cmp     w8, #0x3
0xfffffff0094d64d4  b.ne    0xfffffff0094d6588            ; flag != kGet(3) -> "only supports kGet"
0xfffffff0094d64dc  cbz     x6, 0xfffffff0094d6680        ; structureOutput == NULL -> err
0xfffffff0094d64e0  cmp     w19, #0x67                    ; *** structureOutputSize == 0x67 ***
0xfffffff0094d64e4  b.ne    0xfffffff0094d6680            ; else -> output-size-mismatch error
```

The error branch at `0xfffffff0094d6680` reloads `mov w8, #0x67` (the expected size,
at `0xfffffff0094d66c8`) and logs the new string:

```
0xfffffff00770172e  "%s::%s:%d: rfSensingCACurrentState output size mismatch (%u vs %zu)"
0xfffffff0076e1dab  (duplicate copy of the same string)
```

The async worker `sub_fffffff0094d6758` writes **exactly 0x67 bytes** into
`structureOutput` (`*x9 = *(x8+0x2d0); x9[1] = *(x8+0x270); … x9[0x19] = 2;
*(x9+0x66) = 0;`).

**Verdict: VALIDATED — REFUTED as a bug.** Check `0x67` == write `0x67`.

### `extSARSensingCAInfo` (selector 77) — worker `sub_fffffff0094c94fc`

Args decoded from `IOExternalMethodArguments`: `+0x48` structInSize → `x24`,
`+0x4c` scalarOutputCount → `x25`, `+0x38` scalarOutput → `x9`, `+0x40`
structureOutput → `x8`, `+0x50` structureOutputSize → `x23`, `+0x28` scalarInput (flag).

Checks present, in order: flag NULL → `"The command flag is empty!"`;
`scalarOutputCount >= 2` → `"Given scalar output size (%u) is beyond the max size (%u)"` (max 1);
scalarOutput NULL → `"The scalar output parameter is NULL!"`;
for flag<2, `structInSize != 7` → `"Input size (%u) is not the SAR Consumed Structure Size (%u)"`.

flag==3 write path (widths confirmed in disassembly, **not** from the int32* decompile rendering):

```asm
0xfffffff0094c97b4  ldrb    w10, [x20, #0x220]
0xfffffff0094c97b8  and     x10, x10, #0x1
0xfffffff0094c97bc  str     x10, [x9]            ; 8-byte store to scalarOutput
0xfffffff0094c97c0  cmp     w23, #0x7            ; *** structureOutputSize == 7 ***
0xfffffff0094c97c4  b.ne    0xfffffff0094c9a84   ; else "Output size (%u) is not the Structure Size (%u)"
0xfffffff0094c97cc  stur    wzr, [x8, #0x3]
0xfffffff0094c97d0  str     wzr, [x8]
0xfffffff0094c97d4  ldr     x9, [x20, #0x210]
0xfffffff0094c97d8  ldr     w10, [x9]
0xfffffff0094c97dc  ldrh    w11, [x9, #0x4]
0xfffffff0094c97e0  ldrb    w9, [x9, #0x6]
0xfffffff0094c97e4  strb    w9, [x8, #0x6]
0xfffffff0094c97e8  strh    w11, [x8, #0x4]
0xfffffff0094c97ec  str     w10, [x8]
```

Writes byte offsets 0..6 = **exactly 7 bytes**. **Verdict: VALIDATED — REFUTED.**

### `extSARSensingCALastSubmit` (selector 79) — worker `sub_fffffff0094c9ef0`

flag==3 path:

```asm
0xfffffff0094ca098  ldr     x8, [x19, #0x40]     ; structureOutput
0xfffffff0094ca09c  ldr     w23, [x19, #0x50]    ; structureOutputSize
0xfffffff0094ca0a0  ldrb    w10, [x20, #0x238]
0xfffffff0094ca0a4  and     x10, x10, #0x1
0xfffffff0094ca0a8  str     x10, [x9]            ; 8-byte store to scalarOutput
0xfffffff0094ca0ac  cmp     w23, #0x67           ; *** structureOutputSize == 0x67 ***
0xfffffff0094ca0b0  b.ne    0xfffffff0094ca42c   ; else "Output size (%u) is not the Structure Size (%u)"
0xfffffff0094ca0b8  stur    xzr, [x8, #0x5f]
0xfffffff0094ca0c0  stp     q0, q0, [x8, #0x40]
0xfffffff0094ca0c4  stp     q0, q0, [x8, #0x20]
0xfffffff0094ca0c8  stp     q0, q0, [x8]
0xfffffff0094ca0cc  ldr     x9, [x20, #0x228]
0xfffffff0094ca0d0  ldp     q0, q1, [x9]
0xfffffff0094ca0d4  ldp     q2, q3, [x9, #0x20]
0xfffffff0094ca0d8  ldp     q4, q5, [x9, #0x40]
0xfffffff0094ca0dc  ldr     w10, [x9, #0x60]
0xfffffff0094ca0e0  ldrh    w11, [x9, #0x64]
0xfffffff0094ca0e4  ldrb    w9, [x9, #0x66]
0xfffffff0094ca0e8  strb    w9, [x8, #0x66]
0xfffffff0094ca0ec  strh    w11, [x8, #0x64]
0xfffffff0094ca0f0  str     w10, [x8, #0x60]
0xfffffff0094ca0f4  stp     q4, q5, [x8, #0x40]
0xfffffff0094ca0f8  stp     q2, q3, [x8, #0x20]
0xfffffff0094ca0fc  stp     q0, q1, [x8]
```

Zeroes + copies 0x67 bytes. Also validates scalarOutputCount (<2) and scalarOutput (!=NULL).
**Verdict: VALIDATED — REFUTED.**

### `extSarRFSensingSignal` (selector 47) — worker `sub_fffffff0094bcaac`

```asm
0xfffffff0094bcd5c  cmp     w25, #0x3
0xfffffff0094bcd60  b.ne    0xfffffff0094bcf58   ; flag != 3 -> "The given flag (%u) is not recognizable!"
0xfffffff0094bcd64  ldrb    w10, [x20, #0x158]
0xfffffff0094bcd68  and     x10, x10, #0x1
0xfffffff0094bcd6c  str     x10, [x9]            ; 8-byte store to scalarOutput
0xfffffff0094bcd70  cmp     w23, #0x1            ; *** structureOutputSize == 1 ***
0xfffffff0094bcd74  b.ne    0xfffffff0094bd020   ; else "Output size (%u) is not the Structure Size (%u)"
0xfffffff0094bcd78  mov     w19, #0
0xfffffff0094bcd7c  strb    wzr, [x8]            ; 1 byte
0xfffffff0094bcd80  ldr     x9, [x20, #0x148]
0xfffffff0094bcd84  ldrb    w9, [x9]
0xfffffff0094bcd88  strb    w9, [x8]             ; 1 byte
```

Input side also checked: `structInSize == 1` (else
`"Input size (%u) is not the SAR Consumed Structure Size (%u)"`). **Verdict: VALIDATED — REFUTED.**

### `extStateABOsiris` (selector 49) — worker `sub_fffffff0094bde34`

Byte-identical shape to `extSarRFSensingSignal` (same 0x73b length, 512 disassembly lines):

```asm
0xfffffff0094be0e4  cmp     w25, #0x3
0xfffffff0094be0e8  b.ne    0xfffffff0094be2e0
0xfffffff0094be0ec  ldrb    w10, [x20, #0x208]
0xfffffff0094be0f0  and     x10, x10, #0x1
0xfffffff0094be0f4  str     x10, [x9]            ; 8-byte store to scalarOutput
0xfffffff0094be0f8  cmp     w23, #0x1            ; *** structureOutputSize == 1 ***
0xfffffff0094be0fc  b.ne    0xfffffff0094be3a8
0xfffffff0094be100  mov     w19, #0
0xfffffff0094be104  strb    wzr, [x8]
0xfffffff0094be108  ldr     x9, [x20, #0x1f8]
0xfffffff0094be10c  ldrb    w9, [x9]
0xfffffff0094be110  strb    w9, [x8]
```

**Verdict: VALIDATED — REFUTED.**

### `flag==2` fall-through paths — checked, no output write

These paths are reached **before** the `structureOutputSize` compare. I verified they do
not touch `structureOutput`:

| worker | path | what it does |
| --- | --- | --- |
| `sub_fffffff0094bd1e8` | RFSensingSignal flag==2 | `*x19[0x2a] = *x19[0x29]` — service-to-service copy; returns `!(*(*x19+0x580))(x19)` |
| `sub_fffffff0094be570` | StateABOsiris flag==2 | logs `"Updating State Osiris"`, returns `!(*(*x19+0x5b8))(x19, *(arg1+0x28), **(arg1+0x30))` |
| `sub_fffffff0094c9c4c` | CAInfo flag==2 | logs `"Updating Sensing CA Info"`, returns `!(*(*x19+0x5b0))(x19, …)` |

None of these receive a `structureOutput` pointer, so no caller-buffer write is possible.
**Verdict: REFUTED (SPECULATIVE candidate eliminated).**

### Summary table of verified output writes

| method | dest | bytes written | caller size required | verdict |
| --- | --- | --- | --- | --- |
| extSARSensingCACurrentState | `args+0x40` (structureOutput) | 0x67 | `== 0x67` | REFUTED |
| extSARSensingCAInfo | `args+0x40` | 7 | `== 7` | REFUTED |
| extSARSensingCALastSubmit | `args+0x40` | 0x67 | `== 0x67` | REFUTED |
| extSarRFSensingSignal | `args+0x40` | 1 | `== 1` | REFUTED |
| extStateABOsiris | `args+0x40` | 1 | `== 1` | REFUTED |
| (all five) | `args+0x38` (scalarOutput) | 8 | `scalarOutputCount < 2` + non-NULL | REFUTED |

---

## 4. Job #6 — input side

For every method above, the input side is also gated:

- `structInSize` (`args+0x48`) is compared before use:
  `== 7` for `extSARSensingCAInfo`, `== 0x67` for `extSARSensingCALastSubmit`
  (flag<2 branch), `== 1` for `extSarRFSensingSignal`.
- `scalarInput` (`args+0x28`) is dereferenced only after a NULL check
  (`"The command flag is empty!"`).
- `structureInput` (`args+0x30`) is NULL-checked in the outer handler
  (`"No structure input is given!"`).

No handler dereferences a caller-controlled size without comparing it first.

---

## 5. Job #5 — the dispatch-table entry itself

The static `IOExternalMethodDispatch` entry could **not** be read (§1). Two observations:

1. Each handler performs its own `structureOutputSize` check *inside* the handler body.
   If the framework-level table had a non-zero `checkStructureOutputSize`, IOKit would
   reject a mismatched caller **before** the handler ran, and the in-handler check would
   be dead code. The presence (and, in this build, the *addition*) of in-handler checks
   strongly implies the table entry declares `structureOutputSize = 0` (framework does not
   police it) — i.e. **the handler is the only gate**. After this build's change, the gate
   is correct for all five methods examined.
2. The newly added string `"rfSensingCACurrentState output size mismatch (%u vs %zu)"`
   marks the method where the gate was **missing in the previous build and was added
   here**. Its siblings already had equivalent gates, so there is no remaining hole.

Declared `scalarIn/structInSize/scalarOut/structOutSize` per selector remain **unknown**
(not fabricated).

---

## 6. Ranked candidates

| rank | candidate | function : address | confidence |
| --- | --- | --- | --- |
| 1 | OOB write via `extSARSensingCACurrentState` output | `sub_fffffff0094d64b0` @ `0xfffffff0094d64b0` | **REFUTED** — `cmp w19,#0x67` + NULL check before 0x67-byte write |
| 2 | OOB write via `extSARSensingCAInfo` output | `sub_fffffff0094c94fc` @ `0xfffffff0094c94fc` | **REFUTED** — `cmp w23,#0x7` before 7-byte write |
| 3 | OOB write via `extSARSensingCALastSubmit` output | `sub_fffffff0094c9ef0` @ `0xfffffff0094c9ef0` | **REFUTED** — `cmp w23,#0x67` before 0x67-byte write |
| 4 | OOB write via `extSarRFSensingSignal` output | `sub_fffffff0094bcaac` @ `0xfffffff0094bcaac` | **REFUTED** — `cmp w23,#0x1` before 1-byte write |
| 5 | OOB write via `extStateABOsiris` output | `sub_fffffff0094bde34` @ `0xfffffff0094bde34` | **REFUTED** — `cmp w23,#0x1` before 1-byte write |
| 6 | OOB write on `flag==2` fall-through (bypasses the size compare) | `0xfffffff0094bd1e8`, `0xfffffff0094be570`, `0xfffffff0094c9c4c` | **REFUTED** — no `structureOutput` pointer is passed; no caller-buffer write |
| 7 | OOB write via `scalarOutput` with `scalarOutputCount == 0` | same five workers | **REFUTED** — `scalarOutputCount < 2` gate + explicit non-NULL check; IOKit yields NULL for count 0, caught by `cbz` |
| 8 | `"Current Write Index is out of the bound"` ring-buffer write | `enqueueFlushSnapshotGated` @ `0xfffffff0094d3efc` | **REFUTED** — see §7 |
| 9 | Some other of the ~75 unexamined external methods writes an unchecked output | not examined | **SPECULATIVE** — no evidence; would require per-method decompilation |

No candidate reaches **PROVEN BUG** or **STRONG**.

---

## 7. The `"Current Write Index is out of the bound"` lead — REFUTED

`0xfffffff0077019ab` = `"Current Write Index is out of the bound: %d\n"`.

Per the prior/parallel analysis in `analysis/sar_write_index.md`, this string lives in
`enqueueFlushSnapshotGated` @ `0xfffffff0094d3efc`:

- ring of 8 descriptor slots, each `{ u64 ptr; u32 count; }` at `queue+8`, stride 16;
- write index `u32` @ `queue+0x88`, read index @ `queue+0x8c`; element size `0x67`;
- bound check at `0xfffffff0094d440c` `cmp w9, #0x7` / `0xfffffff0094d4410` `b.hi`
  — an **unsigned** compare, which is correct for a 0..7 index;
- the index is **internal** (initialised to 0, incremented `(index+1) mod 8`) and the
  routine is timer/baseband driven.

It is not reachable from a sandboxed user client through an external method.
**All candidates in that lead are REFUTED.**

---

## 8. Reproducibility

```
bn_binary_view_info                      -> view_7, Mach-O, aarch64/mac-aarch64
bn_string_list query="AppleSARServiceUserClient::ext" limit=200   -> 80 names
bn_function_decompile 0xfffffff0094950c4  -> extSARSensingCACurrentState stub -> vtable+0x548
bn_function_disassembly 0xfffffff0094d64b0 offset 0   -> cmp w19,#0x67 guard
bn_function_disassembly 0xfffffff0094d64b0 offset 110 -> error branch, mov w8,#0x67
bn_memory_read 0xfffffff00770172e len 72 -> "rfSensingCACurrentState output size mismatch (%u vs %zu)"
bn_memory_read 0xfffffff0077019ab len 48 -> "Current Write Index is out of the bound: %d\n"
bn_function_disassembly 0xfffffff0094c94fc offset 170 -> cmp w23,#0x7
bn_function_disassembly 0xfffffff0094c9ef0 offset 100 -> cmp w23,#0x67
bn_function_disassembly 0xfffffff0094bcaac offset 202 -> cmp w23,#0x1
bn_function_disassembly 0xfffffff0094bde34 offset 202 -> cmp w23,#0x1
```

**Note on decompiler output:** BN renders several of these destination pointers as
`int32_t*`/`int128_t*`, which makes offsets look like 3/4/6/12. Every store width in §3
was re-read from `bn_function_disassembly`; the byte offsets quoted are the disassembly's.
