> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# WebCore `parseOriginsFromWellKnownList` — Related Origins parser audit

Target: iOS 27.0 RC (24A435, iPhone17,5)
Binaries: `/Users/pauyedin/24A435__iPhone17,5/dylibs/WebCore` (88 MB arm64e), `WebKit` (45 MB)
Entry: `WebCore::parseOriginsFromWellKnownList(std::span<const uint8_t>, WTF::ASCIILiteral, WebCore::WellKnownOriginListPolicy&&)` @ `0x1a29e0eb4`
Tooling: `otool -v -t` dumped once to `/tmp/webcore.dis` / `/tmp/webkit.dis`; cross-image branch islands resolved with `ipsw dyld disass <DSC> --vaddr`.

## Symbols in this feature

| VA | Symbol |
|---|---|
| `0x1a29e0580` | `WebCore::isWellKnownResponseAcceptable(int, WTF::StringView)` |
| `0x1a29e06d0` | `WebCore::isWellKnownRedirectAllowed(WTF::URL const&)` |
| `0x1a29e06f4` | `WebCore::findOriginInWellKnownList(SecurityOriginData const&, span, ASCIILiteral, WellKnownOriginListPolicy&&)` |
| `0x1a29e0c4c` | `WebCore::(anonymous)::parseCandidatesArray(span, ASCIILiteral, unsigned long)` (static) |
| `0x1a29e0eb4` | `WebCore::parseOriginsFromWellKnownList(span, ASCIILiteral, WellKnownOriginListPolicy&&)` |
| `0x1a29dff3c` | `WebCore::wellKnownURL(StringView, StringView)` |
| `0x19d8cbbbc` | `WebKit::WellKnownResourceFetcher::fetch` |
| `0x19d8cebc4` | `WebKit::WellKnownResourceFetcherClient::didReceiveData(API::DataTask&, span<const uint8_t>)` |
| `0x19d99a528` | `WebKit::RelatedOriginsValidation::validate` |
| `0x19d9a1b0c` | `RelatedOriginsValidation::validate::$_0::call(WellKnownFetchResult&&)` (calls the parser) |

Call islands confirmed: `0x1a0113df0` -> `0x1a29e0eb4` (parseOrigins), `0x1a0112d80` -> `0x1a29e06f4` (findOrigin), `0x1a010afd0` -> `0x1a29dff3c` (wellKnownURL).

## ABI notes established (needed to read the code)

* Indirect return is in `x8` for the exported functions (`mov x21, x8` at `0x1a29e0eec`; `SecurityOriginData::fromURL` sret at `0x1a29e0970`). `parseCandidatesArray` is static and uses `x0` for its sret — caller does `add x0, sp, #0x18` / `ldr x23, [sp, #0x18]` (`0x1a29e0ef8`, `0x1a29e0f00`).
* `ASCIILiteral` is passed as **two** registers (ptr, len-with-NUL). Caller in the WebKit lambda: `mov x2, x21 ("origins")`, `mov w3, #0x8` (`0x19d9a1bdc`, `0x19d9a1be0`). `parseCandidatesArray` therefore builds the key as `String(literal, len - 1)` (`0x1a29e0d14 subs x1, x22, #0x1`), i.e. `"origins"`.
* Argument layout of `parseOriginsFromWellKnownList`: `x0` span.data, `x1` span.size, `x2/x3` ASCIILiteral, `x4` policy*, `x8` out (`WTF::Vector<WTF::String>`).
* Policy struct (built at `0x19d9a1bb4`-`0x19d9a1bc8`, constants at `0x19df2c740`): `{ +0x00 = 5, +0x08 = 100, +0x10 = 0x10000 }` = initial dedupe capacity / max origins examined / max body length.

## Q1 — Grammar actually accepted

**It is not a hand-rolled delimiter parser.** No instruction in `parseCandidatesArray` or `parseOriginsFromWellKnownList` ever dereferences the span. Pipeline:

1. `parseCandidatesArray` (`0x1a29e0c4c`): length gate -> `String` from `(data, size)` -> `WTF::JSON::Value::parseJSON(StringView)` (island `0x1a80dcd50` -> `0x19b00ee70`) -> require root type **Object (5)** -> `Object::get("origins")` (island `0x1a80df5f0` -> `0x19b012658`) -> require type **Array (6)**.
2. `parseOriginsFromWellKnownList` (`0x1a29e0eb4`): per array element `asString()` -> `WTF::URL` (must be valid) -> `PublicSuffixStore::topPrivatelyControlledDomain` + `domainWithoutPublicSuffix` (both must be non-empty) -> dedupe by registrable domain -> append to the output `Vector<String>`.

So: **a JSON object whose `"origins"` member is an array of JSON strings, each a valid URL with a non-empty registrable domain.** Delimiters/escapes/whitespace/comments are exactly those of the WTF JSON parser (no comments; `\uXXXX` escapes; no NUL needed). Entry termination is the JSON array element, not a newline.

Type dispatch is on the JSON value type byte at `+0x10`:
```
0x1a29e0ce0  ldrb w8, [x20, #0x10]
0x1a29e0ce4  cmp  w8, #0x5        ; Object
0x1a29e0ce8  b.eq 0x1a29e0d04
0x1a29e0cec  cmp  w8, #0xff
0x1a29e0cf0  b.eq 0x1a29e0eb0     ; throw_bad_variant_access
0x1a29e0cf4  str  xzr, [x19]      ; else -> nullopt
...
0x1a29e0d84  ldrb w8, [x21, #0x10]
0x1a29e0d88  cmp  w8, #0x6        ; Array
```
Non-string array elements are safe: `asString` (`0x19b0111bc`) returns `&m_string` **only** when `type == 4`, else a static empty string:
```
0x19b0111bc  add  x8, x0, #0x8
0x19b0111c0  ldrb w9, [x0, #0x10]
0x19b0111cc  cmp  w9, #0x4
0x19b0111d0  csel x0, x8, x10, eq
```
JSON nesting is bounded: `0x19b00feb0 cmp w4, #0x3e9` / `0x19b00feb4 b.lt` — depth >= 1001 returns null.

**Verdict: REFUTED / CLEAN NEGATIVE** for "hand-rolled parser over attacker bytes".

## Q2 — Is the span length checked before indexing?

The *only* span-derived arithmetic in WebCore:
```
0x1a29e0c6c  sub  x8, x2, #0x1        ; x2 = span.size()
0x1a29e0c70  cmp  x8, x5              ; x5 = policy.maxLength (0x10000)
0x1a29e0c74  b.hs 0x1a29e0cfc         ; unsigned: reject if size-1 >= max  (i.e. size==0 or size>max)
0x1a29e0cfc  str  xzr, [x19]          ; -> nullopt
```
Unsigned 64-bit compare; rejects empty and oversize. Correct.

The data pointer is used exactly once, as an argument:
```
0x1a29e0c80  add  x0, sp, #0x18       ; sret
0x1a29e0c84  bl   0x1a80dca70         ; x1 = span.data, x2 = span.size
```
Island `0x1a80dca70` -> `0x19a7310f4`, a 2-instruction thunk that moves the sret to `x8` and forwards `(ptr, size)`:
```
0x19a731104  mov  x19, x0
0x19a731108  mov  x8,  x0
0x19a73110c  mov  x0,  x1
0x19a731110  mov  x1,  x2
0x19a731114  bl   0x19a4584d0
```
`0x19a4584d0` (byte -> `WTF::String`) is length-bounded and validates:
```
0x19a4584f0  mov  x19, x8             ; sret
0x19a4584f4  lsr  x8,  x1, #0x1f
0x19a4584f8  cbnz x8,  0x19a458918    ; length >= 2^31 -> fail
0x19a458500  cbz  x0,  0x19a458808    ; null data -> fail
0x19a458508  cbz  x1,  0x19a458934    ; zero length -> fail
0x19a45853c  ldr  q1, [x9], #0x10     ; 16-byte scan, bounded by the end pointer
```
Register `x1` (span.data) appears nowhere else in the function body besides that call — verified by scanning every instruction of `parseCandidatesArray` (`0x1a29e0c4c`-`0x1a29e0eb0`): the only other `x1` uses are `bfi x1, x9, #32, #1` (`0x1a29e0ca0`, StringView build), `mov x1, #0x100000000` (`0x1a29e0cac`), `subs x1, x22, #0x1` (`0x1a29e0d14`, key length) and `add x1, sp, #0x8` (`0x1a29e0d50`).

**Verdict: REFUTED / CLEAN NEGATIVE.** Zero loads from the buffer; the one consumer takes an explicit length.

## Q3 — Size cap before parsing

Two independent caps, both correct.

Constant (in `RelatedOriginsValidation::validate`):
```
0x19d99a618  mov  x8, #0x4024000000000000   ; 10.0 (timeout)
0x19d99a61c  mov  w9, #0x10000              ; 65536
0x19d99a620  stp  x8, x9, [sp, #0x10]       ; WellKnownFetchLimits { 10.0s, 64 KiB }
```
Propagated in `fetch`: `0x19d8cbc90 ldr x23, [x21, #0x8]` -> `0x19d8cbcd0 str x23, [x0, #0x10]` (client->maxLength).

Enforced on every chunk in `WellKnownResourceFetcherClient::didReceiveData`:
```
0x19d8cebe0  ldr  w8,  [x0, #0x24]      ; 32-bit accumulated size (zero-extended)
0x19d8cebe4  add  x23, x3, x8           ; x3 = chunk size; 64-bit add -> cannot overflow
0x19d8cebe8  ldr  x9,  [x0, #0x10]      ; 64 KiB limit
0x19d8cebec  cmp  x23, x9
0x19d8cebf0  b.ls 0x19d8cec34           ; UNSIGNED lower-or-same -> ok
0x19d8cebf8  mov  w8, #0x4
0x19d8cebfc  strb w8, [x20, #0x28]      ; status = TooLarge
0x19d8cec08  bl   WTF::Vector<uint8_t>::shrinkCapacity(0)
0x19d8cec30  b    API::DataTask::cancel()
```
Signed/unsigned: correct — `b.ls` is the unsigned condition, the add is 32-bit-zero-extended + 64-bit, and the limit is loaded 64-bit. No truncation, no sign bug.

The bytes handed to the parser are exactly this accumulated buffer: `0x19d9a1bac ldr x0, [x1, #0x8]` (data) / `0x19d9a1bb0 ldr w1, [x1, #0x14]` (size), and the parse-time gate at `0x1a29e0c6c` re-checks <= 64 KiB.

**Verdict: REFUTED / CLEAN NEGATIVE.**

## Q4 — NUL termination

Not required. The span is converted with an explicit `(data, size)` pair (see `0x19a73110c`-`0x19a731114`), and `0x19a4584d0` is length-driven with explicit null/zero/2^31 guards. There is no `strlen`, no `strchr`, no C-string function on the span anywhere in the two functions.

**Verdict: REFUTED / CLEAN NEGATIVE.**

## Q5 — Behaviour on malformed input (the security-critical question)

`parseCandidatesArray` returns nullopt (`str xzr, [x19]` at `0x1a29e0cf4` / `0x1a29e0cfc` / `0x1a29e0d98` / `0x1a29e0da4` / `0x1a29e0e04`) for: size 0, size > 64 KiB, JSON parse failure, root not an Object, missing `"origins"`, `"origins"` not an Array, valueless variant.

`parseOriginsFromWellKnownList` then returns an **empty** output vector:
```
0x1a29e0eec  mov   x21, x8
0x1a29e0ef0  stp   xzr, xzr, [x8]        ; out Vector zeroed
0x1a29e0f00  ldr   x22, [sp, #0x18]
0x1a29e0f04  cbz   x22, 0x1a29e1288      ; null array -> straight to epilogue, empty list
```
`findOriginInWellKnownList` returns a status byte: **0** = target origin found in the list, **1** = not found / empty array (`0x1a29e0b8c mov w19, #0x1`), **2** = malformed (`0x1a29e076c mov w19, #0x2`).

Caller (`0x19d9a1b0c`) maps it:
```
0x19d9a1c14  mov  x20, x0
0x19d9a1c18  cmp  w0,  #0x2
0x19d9a1c1c  b.ne 0x19d9a1c38            ; == 2 -> log "Related origins: well-known resource is malformed."
0x19d9a1c38  cmp  w20, #0x0
0x19d9a1c3c  cset w8, eq                 ; status = (result == 0)  i.e. "found"
0x19d9a1c40  strb w8, [sp, #0x20]
```
Consumer (`0x19d9a29c0`):
```
0x19d9a29c8  ldrb w8, [x1]                ; Result.status
0x19d9a29cc  tbnz w8, #0, 0x19d9a2a04
0x19d9a29e0  stp  xzr, xzr, [sp]          ; status == 0 -> pass an EMPTY Vector<String>
0x19d9a29ec  bl   handleRequest::$_1::operator()(Vector<String>&&)
0x19d9a2a08  add  x1, x1, #0x8            ; status == 1 -> pass Result.list
```
Malformed / fetch-failed / not-listed all end in "no related origins". **Fail-closed, no "no restriction" fallback.**

Residual, non-exploitable: if the array holds more entries than the policy limit, the loop aborts early and returns a **partial** list:
```
0x1a29e0f64  ldr  x9,  [x20, #0x8]        ; 100
0x1a29e0f68  cmp  x22, x9
0x1a29e0f6c  b.hs 0x1a29e1024             ; -> w26 = 2 -> return partial list
```
A partial list is a subset of the true allow-list, so this cannot add an origin. Individually malformed entries are skipped (`w27 = 3`), never wildcarded.

**Verdict: REFUTED / CLEAN NEGATIVE** (lenient-per-entry, strict-overall, fail-closed).

## Q6 — `findOriginInWellKnownList` comparison

Structured equality on `SecurityOriginData`, built with `SecurityOriginData::fromURL` (`0x1a29e0978`), not a string compare:

* protocol: `0x1a29e09ac ldr x0, [sp, #0x68]` / `0x1a29e09b4 ldr x1, [x27]` / `0x1a29e09b8 bl 0x1a80dc920`
* host: `0x1a29e09c0` / `0x1a29e09c4 ldr x1, [x27, #0x8]` / `0x1a29e09c8 bl 0x1a80dc920`
* port as `std::optional<uint16_t>`: engaged flags `0x1a29e0990 ldrb w9, [x9, #0x18]` / `0x1a29e09d0 ldrb w9, [sp, #0x7a]`, values `0x1a29e09ec ldrh w8, [sp, #0x78]` / `0x1a29e09f4 ldrh w9, [x9, #0x10]` / `0x1a29e09f8 cmp w8, w9`

`0x1a80dc920` -> `0x19a732ac0` is `WTF::StringImpl::equal`: pointer fast path, then **length compare before any byte compare**:
```
0x19a732b00  ldr  w10, [x0, #0x4]
0x19a732b04  ldr  w8,  [x1, #0x4]
0x19a732b08  cmp  w10, w8
0x19a732b0c  b.ne 0x19a732af8             ; -> return false
0x19a732b10  cbz  w10, 0x19a73312c        ; both empty -> true
```
No `hasPrefix`/`hasSuffix`/`find`/substring compare anywhere on the path.

**Verdict: REFUTED / CLEAN NEGATIVE.**

## Side observations (not vulnerabilities)

1. **Status / Content-Type gate not observed on this path.** `isWellKnownResponseAcceptable` (`0x1a29e0580`) requires `status == 200` (`0x1a29e0582 cmp w0, #0xc8`) and Content-Type exactly `"application/json"` (length 16 compared case-insensitively, `0x1a29e05a4`-`0x1a29e06c8`) — i.e. no `; charset=` tolerated. It has **no in-image caller** (the symbol string occurs once in `webcore.dis`, at its own label). `isWellKnownRedirectAllowed` (`0x1a29e06d0`, https-only via `URL::protocolIs`) likewise has no in-image caller, and `WellKnownResourceFetcherClient::didCompleteWithError` (`0x19d8ced0c`) only looks at the ResourceError, not the HTTP status. **SPECULATIVE** that they are entirely dead: the extracted WebKit's undefined-symbol table is incomplete (it does not list `WebCore::wellKnownURL` even though `0x1a010afd0` resolves to it), so cross-image calls cannot be enumerated exhaustively. Even if unused, this is defence-in-depth only — the allow-list still governs.
2. `RelatedOriginsValidation::validate` bails before any network I/O when `wellKnownURL` yields no URL: `0x19d99a594`/`0x19d99a598`, logging "Related origins: relying party identifier is not a host." -> empty list.
3. Fetch timeout 10.0 s and 64 KiB cap are the only resource limits; the parse itself is bounded by the 64 KiB input and the 1000-deep JSON limit.
