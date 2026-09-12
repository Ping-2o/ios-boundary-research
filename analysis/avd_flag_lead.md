> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# AVD `CAVDAvcDecoder` flag-asymmetry lead — verdict

**Target:** `AVD.videodecoder`, iOS 27.0 RC (24A435), Mach-O ios-aarch64, image base `0x22a341000`.
**Method:** Binary Ninja (MCP) only. Read-only queries; no `bn_binary_view_set_active` / `bn_open_item_open`.
**Lead under test:** driving `CAVDAvcDecoder + 0xa` to an **odd value ≠ 1** (e.g. 3) via the writer at `VASetParams` would simultaneously disable the 4096-pixel cap (`VAStartDecode`) and the "Frame resolution change not supported" check (`processParserOut`) → in-band SPS OOB.

## VERDICT: **REFUTED** (as stated)

The **asymmetry is real** (`==1` vs `&1` on the same byte), but the exploit mechanism is not:

1. `CAVDAvcDecoder + 0xa` is written **only at decoder-creation time** by `AppleAVDCommandBuilder::createDecoder`, from `_sAppleAVDCreateDecoderOut + 0x30` — a session-config field, not bitstream data.
2. The **per-frame / in-band path does NOT write `[0xa]`.** The helper's selector `0x14` (the path the lead pointed at) resolves to AVC switch Case `0x9`, i.e. `[0xb74]`, a *different* field. (The original lead conflated the switch case index `0x14` = selector `0x1f` with the selector value `0x14` = case `0x9`.)
3. Every producer of the two guard bytes is a boolean: `? 1 : 0` normalisation, `!= 0` tests, and a platform-derived bit.

---

## 1. The two guards (quoted pseudo-C + decisive disassembly)

### 1a. `CAVDAvcDecoder::VAStartDecode` @ `0x22a42e2f0`

```c
if (*(this + 0xa) == 1 && !(*(this + 0x1d36) & 1) && (x8_7 > 0xff || x9_6 >= 0x100))
{
    // .cold.6 -> "AppleAVD: ERROR: ... video resolution %ux%u exceeds allowed maximum"
    return 0x136;
}
```
`x8_7 = *(SPS + 0x616)`, `x9_6 = *(SPS + 0x618)`; width `= (x8_7<<4)+0x10`, height `= (x9_6<<4)+0x10` ⇒ cap ≈ 4096. **Exact-equality test:**

```
0x22a42e50c  ldrb    w10, [x19, #0xa]
0x22a42e510  cmp     w10, #0x1          ; <-- EXACT == 1
0x22a42e514  b.ne    0x22a42e538
0x22a42e518  mov     w10, #0x1d36
0x22a42e51c  add     x10, x19, x10
0x22a42e520  ldrb    w10, [x10]         ; second gate: [this+0x1d36]
0x22a42e524  tbnz    w10, #0, 0x22a42e538
0x22a42e528  cmp     w8, #0xff
0x22a42e52c  b.hi    0x22a42e5c0
0x22a42e530  cmp     w9, #0x100
0x22a42e534  b.hs    0x22a42e5c0
```

### 1b. `CAVDAvcDecoder::processParserOut` @ `0x22a42ec00`

```c
if (!(*(this_1 + 0xa) & 1))
{
    // strict equality: new width/height/chroma_format/bit_depth vs stored
    if (x19_4 != *(this_1 + 0xb9c)) goto "Frame resolution change not supported";   // -> 0x131
    if (x23_2 != this_1[0x174])      goto "Frame resolution change not supported";
    ...
}
else
{
    // bit0 set: width/height/chroma/bit-depth checks SKIPPED (DPB-size check remains)
    x25_4 = *(this_1 + 0x1d2c);
    if (x25_4 < x21_4) goto "DPB Size Requirement Changed";
}
```
**Bit-test (ANY odd value):**

```
0x22a42ef94  ldrb    w8, [x22, #0xa]
0x22a42ef98  tbnz    w8, #0, 0x22a42f00c     ; <-- bit0 set => skip resolution-change checks
...
0x22a42f160  ldrb    w8, [x22, #0xa]
0x22a42f164  tbz     w8, #0, 0x22a42f178
...
0x22a42f17c  cmp     w19, w25
0x22a42f180  b.ne    0x22a42f6e4             ; -> 0x22a42f75c "...Frame resolution change not supported"
```
String @ `0x22a42f75c`: `"AppleAVD: WARNING: %{public}s(): #### <WARNING> Frame resolution change not supported Frame %d old %d %d new %d %d\n"` (error `0x131`).

**⇒ The asymmetry (`cmp #1` vs `tbnz #0`) is confirmed in both pseudo-C and disassembly.** The lead's first sub-task is answered: real, not an illusion. Semantics: `[0xa]==1` ⇒ cap on + changes allowed; `[0xa]==0` ⇒ no cap + changes rejected; `[0xa]==odd≠1` ⇒ no cap + changes allowed (the hypothetical gap).

---

## 2. Writers of `CAVDAvcDecoder + 0xa` and `+0x1d36`

`CAVDAvcDecoder::VASetParams` @ `0x22a364de4` — switch on `arg2 - 0xb`, jump table `0x22a365228`. The **only** case that touches `[0xa]`:

```
0x22a364f5c  {Case 0x14}                ; switch index 0x14  =>  selector arg2 = 0x1f
0x22a364f60  ldrb    w8, [x2]
0x22a364f64  strb    w8, [x19, #0xa]    ; [this+0xa] = low byte of *arg3
```
And `[0x1d36]` (entry sets `x8 = this + 0x1d24`):

```
0x22a364f6c  {Case 0x2f}                ; switch index 0x2f  =>  selector arg2 = 0x3a
0x22a364f70  ldrb    w9, [x2]
0x22a364f74  strb    w9, [x8, #0x12]    ; [this+0x1d36] = low byte of *arg3
```
No other case in the 375-instruction switch stores to `[x19,#0xa]`. (Case `0x9`, selector `0x14`, stores `[x19,#0xb74]` — see §3.)

### Senders of selectors `0x1f` and `0x3a`

`AppleAVDCommandBuilder::createDecoder` @ `0x22a34932c` (`arg3 = _sAppleAVDCreateDecoderOut*`, `arg2 = _sAppleAVDCreateDecoderIn*`):

```
0x22a349674  mov     x24, x20
0x22a349678  ldr     w8, [x24, #0x30]!    ; w8 = *(createOut+0x30); x24 = &(createOut+0x30)
0x22a34967c  cmp     w8, #0
0x22a349680  cset    w8, ne
0x22a349684  strb    w8, [x28, #0x524]    ; this+0x1524 = (*(createOut+0x30) != 0)
0x22a349688  ldr     x16, [x26]
0x22a349698  ldr     x8, [x16, #0x68]!    ; decoder->VASetParams
0x22a34969c  mov     x0, x26
0x22a3496a0  mov     w1, #0x1f
0x22a3496a4  mov     x2, x24
0x22a3496ac  blraa   x8, x16              ; VASetParams(0x1f, &createOut+0x30)  -> [0xa]
...
0x22a349934  add     x2, x22, #0x13c       ; &(createIn+0x13c)
0x22a349938  mov     w1, #0x3a
0x22a349940  blraa   x8, x16              ; VASetParams(0x3a, &createIn+0x13c) -> [0x1d36]
```
So **both** guard bytes are latched once, at `createDecoder`, from create in/out structs. `bn_function_callers(0x22a34eb34)` = 1 (only `_AppleAVDDecodeFrameInternal`), and `bn_function_callers(0x22a347ae4)` = 1 (`_AppleAVDInitializeDecoder`), so the create chain is `_AppleAVDInitializeDecoder` → `_AppleAVDCreateDecodeDeviceInternal` → `createDecoder`.

---

## 3. The per-frame path writes `[0xb74]`, not `[0xa]` — refutes the lead's premise

`AppleAVDCommandBuilder::decodeFrameFigHelper_VASetParameters` @ `0x22a34e6fc` (called from `decodeFrameFig`; `arg2 = _sAppleAVDDecodeFrameFigIn*`):

```
0x22a34e9d4  ldrb    w8, [x19, #0x854]      ; w8 = FigIn+0x854  (videoContext+0xdc4, a byte)
0x22a34e9d8  cbz     w8, 0x22a34ea50
0x22a34e9dc  stp     xzr, xzr, [sp] {var_60} {var_58}
0x22a34e9e0  str     wzr, [sp, #0x10 {var_50}]
0x22a34e9e4  strb    w8, [sp {var_60}]       ; var_60[0] = FigIn+0x854
0x22a34e9e8  ldr     d0, [x19, #0x858]
0x22a34e9ec  stur    d0, [sp, #0x4 {var_60+0x4}]
0x22a34e9f0  mov     w8, #0x178b
0x22a34e9fc  strb    w9, [x8]                ; this+0x178b = 1
0x22a34ea1c  mov     w1, #0x14               ; selector 0x14
0x22a34ea24  blraa   x8, x16                 ; VASetParams(0x14, &var_60)
```
Selector `0x14` for `CAVDAvcDecoder` = switch Case `0x9`:

```
0x22a365114  {Case 0x9}
0x22a365118  ldrb    w8, [x2]
0x22a36511c  strb    w8, [x19, #0xb74]       ; <-- writes [0xb74], NOT [0xa]
0x22a365120  ldur    d0, [x2, #0x4]
0x22a365124  str     d0, [x19, #0xb78]
```
Likewise the helper's selector `0x2f` (lead's "second flag" claim) resolves to Case `0x24` → `[0xbc4]`/`[0xbc8]`, **not** `[0x1d36]`; `[0x1d36]` is reached only via selector `0x3a` (Case `0x2f`), sent by `createDecoder` (§2).

**Consequence:** the in-band/bitstream metadata (`_sAppleAVDDecodeFrameFigIn` fields `+0x854`/`+0x858`, sourced from `_sAppleAVDVideoContext+0xdc4`/`+0xdc8`) cannot drive `[0xa]`. The lead's reachability story is dead.

---

## 4. Value domains of the two guard bytes

`_AppleAVDDecodeFrameInternal` @ `0x22a34e380` builds the `FigIn` struct (`x27 = sp+0x18`); `struct+0x854 = sp+0x86c`:

```
0x22a34e4c4  ldrb    w8, [x20, #0xdc4]      ; videoContext+0xdc4
0x22a34e4c8  cbz     w8, 0x22a34e4d8
0x22a34e4cc  strb    w8, [sp, #0x86c]       ; FigIn+0x854  (byte)
0x22a34e4d0  ldr     d0, [x20, #0xdc8]
0x22a34e4d4  str     d0, [sp, #0x870]       ; FigIn+0x858
```
`_sAppleAVDVideoContext + 0xdc4` is written only as a boolean:
- `_AppleAVDInitializeDecoder` @ `0x22a3421a8`:
  ```
  0x22a34224c  ldrb    w8, [x21, #0x35]       ; init-struct+0x35
  0x22a342250  strb    w8, [x19, #0xdc4]      ; videoContext+0xdc4
  ```
  For AVC, `_CreateAVDH264Instance` @ `0x22a471b88` sets init-struct+0x35 (`sp+0x75`) to a **boolean**:
  ```
  0x22a472078  ldr     w8, [x19, #0x10]
  0x22a47207c  cmp     w8, #0x1
  0x22a472080  cset    w8, eq
  0x22a472084  strb    w8, [sp, #0x75]        ; init-struct+0x35 = (*(storage+0x10)==1)
  ```
  (HEVC's `_CreateAVDHEVCInstance` sets its `+0x35` the same way: `*(&var_68 + 0xd) = arg1[2] == 1 ? 1 : 0`.)
- `_AppleAVDSetParameter` @ `0x22a3432dc`, case `0x1b` (selector `0x1c`): `*(arg1 + 0xdc4) = 1;` — constant.

`[this+0x1d36]` ← `createIn+0x13c`. In `_AppleAVDCreateDecodeDeviceInternal`, `createIn = sp+0xe0`, so `+0x13c = sp+0x21c`:
```
0x22a347d20  ldr     w9, [x19, #0xf08]
0x22a347d28  ldrb    w9, [x19, #0xee0]
0x22a347d2c  strb    w9, [sp, #0x21c]       ; createIn+0x13c = videoContext+0xee0
```
`videoContext+0xee0` ← `init-struct+0x34` (`_AppleAVDInitializeDecoder`), which for AVC is `*(&var_88+0xc) = var_50 >> 0xb & 1` (a platform bit) ⇒ **boolean**.

`[this+0xa]` ← `createOut+0x30`. `createOut = sp+0x20` in `_AppleAVDCreateDecodeDeviceInternal`, zero-initialised there and then populated by the out-of-image bridge `0x2300e0b60`. `createDecoder` treats it strictly as a flag:
```c
*(this + 0x1524) = *(arg3 + 0x30) ? 1 : 0;
...
if (*(arg3 + 0x30) == 1) AppleAVDCommandBuilder::updateDecryptionParams(this, *(arg2 + 0x38));
```
```
0x22a349ad4  ldr     w8, [x24]              ; createOut+0x30
0x22a349ad8  cmp     w8, #0x1
0x22a349adc  b.ne    0x22a349aec
0x22a349ae8  bl      AppleAVDCommandBuilder::updateDecryptionParams
...
0x22a349cfc  ldr     w8, [x20, #0x30]       ; createOut+0x30 gates selector 0x20 (-> [0x1d2c])
0x22a349d00  cbz     w8, 0x22a349db0
```
Additionally `[0xa]` is used in decryption logic — `processParserOut`: `if (CAVDDecoder::isADSDecryption(this_1) && !(*(this_1 + 0xa) & 1))` — consistent with `[0xa]` being a config flag, not a resolution flag.

---

## 5. Why REFUTED, and the residual unknown

Kill chain required by the lead: (i) attacker controls `[0xa]` in-band → (ii) sets an odd value ≠1 → (iii) both guards drop → (iv) oversized SPS accepted → (v) OOB.

- (i) is **false**: no bitstream/per-frame path writes `[0xa]` (it writes `[0xb74]`). The only writer is `createDecoder`, i.e. session creation.
- (ii) is **unsupported**: every observable producer of the two guard bytes is a boolean (`?1:0`, `!=0`, `==1`, platform bit). The field is a byte and is consistently normalised.
- `[0x1d36]`'s independent cap-gate is likewise a create-time boolean, so the "second flag" does not open an in-band path either.

**Residual (documented trace stop):** `_sAppleAVDCreateDecoderOut + 0x30` is populated by `0x2300e0b60`, which is **outside the analysed image** (`bn_function_info`/`bn_function_decompile` → `function_not_found`; `bn_symbol_list_at` → 0 symbols). Whether that bridge can emit a non-boolean byte (e.g. 3) cannot be determined from `AVD.videodecoder` alone. If it can, the latent `==1` vs `&1` asymmetry would become reachable; absent evidence, and with no in-band control, the lead as stated does not hold.

**Bottom line:** the `==1`/`&1` asymmetry is a genuine latent inconsistency worth noting, but the "in-band SPS drives `[this+0xa]` to 3" exploit is **REFUTED**.
