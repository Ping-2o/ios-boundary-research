> **NOTICE — AI-GENERATED SECURITY RESEARCH.** This document was written 100% by
> autonomous AI agents (no human authoring or line-by-line review pass — expect slop).
> It exists solely for authorized security research and coordinated disclosure to the
> affected vendor. All claims cite checkable artifacts (offsets, receipts, commands);
> re-verify before trusting any of them. PoC files are minimal triage reproducers,
> not weapons. Do not use against systems you do not own or may not test.

# WebKit (iOS 27.0 RC 24A435) — "what WebKit reaches OUT to" audit

Target: `/Users/pauyedin/24A435__iPhone17,5/dylibs/WebKit` (45,178,288 B, arm64e, WebKit 625.1.29.10.29)
Method: `/tmp/ds_audit_method.md`. Tooling: `nm`, `strings -a`, `otool -v -s __TEXT __text`
(this dylib keeps code in `__TEXT,__text` — **not** `__TEXT_EXEC` — so plain `otool -v -s __TEXT __text`
works; dumped once to `/tmp/wk.dis`).
Context: `REPORT_27_0_RC_DIFF.md` §2.4, §4; ipsw-diffs `DYLIBS/.../WebKit.md`,
`SANDBOX/Collection/com.apple.WebKit.*.md`.

---

## 0. Headline

**WebKit opens no IOKit user clients. Not one.** The user-client list for WebKit processes has to be
read off the *sandbox profiles*, because the binary contains no user-client code at all. The
AppleJPEGDriver deny removed a live **developer-mode-only** path that was never open in shipping
WebContent. The genuinely new 27.0 WebKit code is WebAuthn *Related Origins* (a new network fetch +
origin-list parser in the **UI process**) — that is where the new-code risk is, and its size handling
audits **CLEAN**.

---

## 1. IOKit / hardware surface actually reachable from WebKit code

### 1.1 Direct user-client opens: **REFUTED / CLEAN NEGATIVE**

Definitive, three independent ways:

| probe | result |
|---|---|
| `nm -u -m WebKit \| grep -E "_IOService\|_IOConnect\|_IOMasterPort\|_IOIterator\|_IORegistry\|_IOObject"` | **0 hits** (only `_IOSurfaceLookupFromMachPort` matches the loose `_IO` prefix) |
| raw byte grep over the whole 45 MB file for `UserClient` / `IOServiceOpen` / `IOConnectCall` / `IOServiceGetMatchingService` / `IOMasterPort` / `AppleJPEG` / `IOAccelerator` / `AGXDevice` / `IOSurfaceRoot` | **0 / 0 / 0 / 0 / 0 / 0 / 0 / 0 / 0** |
| `__TEXT,__dlsym_cstr` (soft-link strings, 0xb98 B) | only `_nw_parameters_*`, `_wbt_*`, `TCCAccess*`, `HelpERTrackGetDisplayPosition` — no IOKit soft-link |

There is no `IOServiceOpen`, no `IOConnectCall*`, no `IOServiceGetMatchingService`, and **not a single
user-client class name string anywhere in the binary**. The user-client-class list in §1.4 therefore
describes what the *sandbox lets the processes do*, not what WebKit code calls.

### 1.2 What WebKit does import from `IOKit` (23 symbols) — all HID, all UI process

`IOHIDManager{Create,Open,Close,SetDeviceMatching,ScheduleWithRunLoop,UnscheduleFromRunLoop,
RegisterDeviceMatchingCallback,RegisterDeviceRemovalCallback}`,
`IOHIDDevice{Open,Close,SetReport,RegisterInputReportCallback,ScheduleWithRunLoop,
UnscheduleFromRunLoop}`, `IOHIDEvent{CreateDigitizerEvent,CreateDigitizerFingerEvent,
CreateVendorDefinedEvent,AppendEvent,GetType,GetIntegerValue,SetIntegerValue,SetFloatValue}`,
`IOHIDEventSystemClientCreate`.

Attribution is exact because assert strings embed full source paths:

| consumer | process | evidence |
|---|---|---|
| WebAuthn CTAP-over-HID: `WebKit::HidService` (`create` 0x19cf1743c, `deviceAdded` 0x19cf17aa8, `platformStartDiscovery` 0x19cf179e0), `WebKit::HidConnection` (`create` 0x19cf154ec, `send` 0x19cf15d20, `sendSync` 0x19cf15c7c, `receiveReport` 0x19cf16074, `registerDataReceivedCallback` 0x19cf15f44) | **UI process** | `Sources/WebKit/Source/WebKit/UIProcess/WebAuthentication/{AuthenticatorManager.cpp,CtapAuthenticator.cpp,fido/…,Mock/MockHidConnection.cpp}` |
| Gamepad: `WebKit::UIGamepadProvider` | **UI process** | `UIProcess/Gamepad/UIGamepadProvider.cpp` |
| `WebKit::WebGamepadProvider` / `WebGamepad` | **WebContent** — receives `GamepadData` over IPC, makes **no** IOKit call | `WebProcess/Gamepad/WebGamepadProvider.cpp` |
| `-[_WKTouchEventGenerator _createIOHIDEventType:]` 0x19d37e31c | UI process, **test-only** | symbol name |

`IOHIDManager`/`IOHIDDevice` are reached through the HID event system (mach), not by opening a
user client; no `IOKit` user-client class is involved.

### 1.3 IOSurface / shared memory

Only **5** imports from `IOSurface`: `IOSurfaceCreateMachPort`, `IOSurfaceLookupFromMachPort`,
`IOSurfaceLock`, `IOSurfaceUnlock`, `IOSurfaceGetBaseAddress`.
No `IOSurfaceCreate`, no `IOSurfaceAccelerator*`, no `IOAccelerator*`, no `CoreVideo` pixel-buffer
API. `Metal` is 3 symbols (`MTLCreateSystemDefaultDevice`, `MTLSetShaderCachePath`,
`MTLTextureDescriptor`). `mmap`/`munmap` come from libSystem; no `mach_vm_map`,
no `mach_make_memory_entry`.

So WebKit **never creates** an IOSurface and never computes a rowbytes/plane/height for one. It only
maps/locks surfaces handed to it (`-[WKWebView(WKViewInternalIOS) _takeViewSnapshot]`,
`WebKit::ViewSnapshot::setSurface` 0x19d491b38, `-[WKWebView(WKPrivate) _displayCaptureSurfaces]`).

### 1.4 User-client classes, by process, and survival of the RC sandbox rules

(from `SANDBOX/Collection/com.apple.WebKit.*.md` — these are the *allow* lists, i.e. what the
process can reach; WebKit code is not the caller for the GPU/AGX entries)

| user client / service | process | opened by | survives 24A435? |
|---|---|---|---|
| `AppleJPEGDriverUserClient` | WebContent (developer mode only) | not WebKit code (see §2) | **NO — explicitly denied by name, `(with no-report)`** |
| `IOSurfaceRootUserClient` (+ `apply-message-filter (allow iokit-external-trap)`) | GPU | IOSurface framework | **YES** — unchanged |
| `IOSurfaceAcceleratorClient` (`require-all` with `state-flag "local:tested_version_2.0"`) | GPU | IOSurfaceAccelerator | **YES** — unchanged |
| `AGXDeviceUserClient` | GPU | Metal / AGXGLDriver | **YES** — and the rule was *rewritten*: was a flat allow, is now `(allow iokit-open-user-client (require-any (iokit-connection "IOGPU") (iokit-registry-entry-class "AGXDeviceUserClient")))`. Note this is `require-any`, i.e. **any** user client on an IOGPU connection is allowed — a superset of the old flat rule |
| `iokit-open-service`: `AGXAcceleratorG*`, `AppleM2ScalerCSCDriver`, `AppleParavirtGPU`, `(iokit-connection "IOGPU")` | GPU | Metal | **YES** |
| `AppleKeyStoreUserClient` / `AppleKeyStore` | Networking (Development) | Security framework | **YES** |
| *(blanket, any class)* | WebContent.Development | — | **NO — removed** |
| **shipping `com.apple.WebKit.WebContent`** | WebContent | — | **no `iokit-open-user-client` allow at all** (diff contains zero `user-client` lines) → default deny |

The blanket dev-mode allow (`(allow iokit-open-user-client (with report) (system-attribute
developer-mode))`) was deleted from **all three** Development profiles; GPU and Networking had
class-specific allows to fall back on, WebContent did not, which is why WebContent is the only
profile that flipped allow→deny.

### 1.5 Sandbox extensions WebKit *issues* (UI process)

`WebKit::SandboxExtension` (0x19d1fd998 etc.) uses
`sandbox_extension_issue_generic` / `_mach` / `_file`. Generic names with live code xrefs:
`"com.apple.webkit.mach-bootstrap"` (0x19d1fd9b0), `"com.apple.webkit.microphone"`
(0x19d7dd214, 0x19d944d70), `"com.apple.webkit.camera"` (0x19d7dd2c4, 0x19d944c94).

`sandbox_extension_issue_iokit_registry_entry_class[_to_process]` **is imported**, but:
- there is no `WebKit::SandboxExtension::createHandleFor*IOKit*` method in the symbol table, and
- there is **no** IOKit class-name string anywhere in the binary,
- `"com.apple.webkit.extension.iokit"` (0x19e08ccc6) has **no code xref** (adrp/add scan) and **no
  raw 64-bit pointer** referencing it anywhere in the file.
→ **SPECULATIVE / likely dead** in this build. Cannot attribute any IOKit extension grant to WebKit.

---

## 2. AppleJPEGDriverUserClient — what would have opened it

**Verdict: no WebKit-side path exists. The deny closed a developer-mode-only escape hatch; shipping
WebContent never had it.**

Evidence:

1. Zero `AppleJPEG` bytes in WebKit (raw grep). No `ImageDecoder` HW-JPEG symbol
   (`grep -iE "hardware|jpeg"` over 121,899 defined symbols → only `webRTCH264HardwareEncoderEnabled`,
   `MediaContentTypesRequiringHardwareSupport`, `NFHardwareManager`, `RemoteAudioHardwareListener`,
   `-[WKFileUploadPanel _uploadItemForJPEGRepresentationOfImage:…]`, `HardwareKeyboardState`).
2. Shipping `com.apple.WebKit.WebContent` (non-Development) diff: **0** `iokit` lines, **0**
   `user-client` lines. No `iokit-open-user-client` allow ⇒ default deny. So a shipping-profile
   allowance **does not exist** and did not need removing.
3. Exact RC change in `com.apple.WebKit.WebContent.Development.md`:
```
 779 -(allow iokit-open-user-client
 780 -	(with report)
 781 -	(system-attribute developer-mode)
 782 +(deny iokit-open-user-client
 783 +	(with no-report)
 784:+	(iokit-registry-entry-class "AppleJPEGDriverUserClient")
 785- )
 786 +(deny iokit-open-user-client)
```
   `with no-report` on a *named* deny is the signature of an **expected** denial: something inside
   dev-mode WebContent really does try to open it, and Apple silenced the log spam. That is the
   strongest available evidence the path was live.
4. Who opens it, if not WebKit: `VideoToolbox` in the same extraction directory has
   `"com.apple.videotoolbox.videodecoder.jpeg.applejpeg"`,
   `"com.apple.videotoolbox.videodecoder.dmb1.applejpeg"` (OpenDML/MJPEG) and a
   `AppleJPEGVideoDecoder` class. ImageIO (in-process in WebContent for every JPEG) is the other
   candidate. **SPECULATIVE** — ImageIO is not in our dylib set and was not audited.

**Read:** paired with `com.apple.driver.AppleJPEGDriver` growing +0x784 B in the same build
(REPORT §2.4), the most probable story is *WebContent → (media/ImageIO in-process) →
AppleJPEGDriverUserClient → kernel* being fixed, with the WebContent-side reach closed by sandbox
policy and the kext-side bug fixed in code. Whoever owns the kext front should treat
`AppleJPEGDriver` as the CVE target; there is nothing to exploit in WebKit itself.

---

## 3. New 27.0 WebKit surface (from `DYLIBS/…/WebKit.md`, `+` lines = RC-only)

The RC added ~120 non-template symbols. The security-relevant cluster is **WebAuthn Related
Origins** — a brand-new *network fetch + parser* running in the **UI process**:

- `WebKit::RelatedOriginsValidation::validate(WebPageProxy&, SecurityOriginData const&, WTF::String
  const&, CompletionHandler<void(RelatedOriginsValidation::Result&&)>&&)` — **0x19d99a528**
- `WebKit::WellKnownResourceFetcher::fetch(WebPageProxy&, URL&&, WellKnownFetchLimits const&, …)` — **0x19d8cbbbc**
- `WebKit::WellKnownResourceFetcherClient::didReceiveResponse` 0x19d8ceaac, `didReceiveData`
  0x19d8cebc4, `willPerformHTTPRedirection` 0x19d8cea18, `didCompleteWithError` 0x19d8ced0c
- `WebKit::wellKnownFetchStatusDescription`, `WebKit::relatedOriginsCapability`,
  `setRelatedOriginsCapability`, `relyingPartyIdentifierForRequest`
- WebCore side (imported): `WebCore::wellKnownURL`, `parseOriginsFromWellKnownList(span<const
  uint8_t>, ASCIILiteral, WellKnownOriginListPolicy&)`, `findOriginInWellKnownList`,
  `isWellKnownResponseAcceptable(int, StringView)`, `isWellKnownRedirectAllowed(URL const&)`
- URL path string: **`"/.well-known/webauthn"`** at **0x19e117aa0** (referenced from
  `RelatedOriginsValidation::validate` @0x19d99a57c).

Also new: `MockHidService::create`, `MockHidConnection::{initializeExpectedCommands,
validateExpectedCommandsCompleted, C2}`; `NetworkProcess::canPrefetchDNSForTesting`,
`prefetchedDNSHostnameCountForTesting`; `RemoteProgressBasedTimeline`.

**EnhancedSecurity** (new profile name `com.apple.WebKit.WebContent.EnhancedSecurity`, string at
0x19e094090 — no code xref, no raw pointer: it is consumed by the sandbox/process-launch path, not
by a literal reference in this binary) is a large new feature:
`WebProcessPool::createNewWebProcess(..., EnhancedSecurity, …)`,
`WebProcessProxy::create(..., EnhancedSecurity, …)`, `SuspendedPageProxy::findReusableSuspendedPageProcess`,
"Process swap due to EnhancedSecurity change", `EnhancedSecurityTracking::{initializeFrom,trackNavigation,
enableFor,shouldEnableForInsecureResponse}`, `EnhancedSecuritySitesHolder` (+ background work queue),
`EnhancedSecuritySitesPersistence` (**SQLite database**, `closeDatabase`), prefs
`forceEnhancedSecurity`, `enhancedSecurityLinksEnabled`, `enhancedSecurityForceDisabled`,
`enhancedSecurityHeuristicsEnabled`, `BlockEnhancedSecurityLinks`,
`_WKWebsiteDataTypeEnhancedSecurityRecord`.

Also notable: `WebKit::GPUProcessProxy::updateSandboxAccess(bool, bool, bool)` — **0x19d944c50** —
issues `"com.apple.webkit.camera"` and `"com.apple.webkit.microphone"` generic extensions **to the
GPU process** (0x19d944ca4, 0x19d944d80). Media capture in the GPU process is a live, growing surface.

---

## 4. IOSurface / shared-memory candidate bugs

### CAND-1 — well-known response accumulation: **REFUTED / CLEAN NEGATIVE**

`WellKnownResourceFetcherClient::didReceiveData` 0x19d8cebc4:
```
000000019d8cebe0  ldr  w8, [x0, #0x24]      ; m_buffer.size()   (u32 load)
000000019d8cebe4  add  x23, x3, x8          ; newSize = len + size   (64-bit)
000000019d8cebe8  ldr  x9,  [x0, #0x10]     ; m_maxSize               (64-bit)
000000019d8cebec  cmp  x23, x9
000000019d8cebf0  b.ls 0x19d8cec34          ; over limit -> status=4(0x19d8cebfc), shrinkCapacity(0), DataTask::cancel
```
64-bit add, 64-bit compare, enforced branch to `cancel` — no overflow, no missing check.
The `str w23, [x20, #0x24]` at 0x19d8cec88 that stores the new size into the 32-bit field cannot
truncate because the limit is 64 KiB:
```
RelatedOriginsValidation::validate
000000019d99a618  mov  x8, #0x4024000000000000   ; = 10.0 (double) -> timeout
000000019d99a61c  mov  w9, #0x10000              ; = 65536
000000019d99a620  stp  x8, x9, [sp, #0x10]       ; WellKnownFetchLimits
WellKnownResourceFetcher::fetch
000000019d8cbc90  ldr  x23, [x21, #0x8]
000000019d8cbcd0  str  x23, [x0, #0x10]          ; client->m_maxSize = 65536
```
Closed by: 64-bit limit compare + `cancel()`.

### CAND-2 — redirect handling has no counter in WebKit: **SPECULATIVE**

`WellKnownResourceFetcherClient::willPerformHTTPRedirection` 0x19d8cea18:
```
000000019d8cea30  bl   0x1a011a6d0           ; newRequest.url()
000000019d8cea38  bl   0x1a01131e0           ; WebCore::isWellKnownRedirectAllowed(URL const&)
000000019d8cea40  tbnz w0, #0x0, 0x19d8cea4c
000000019d8cea44  mov  w8, #0x3               ; status = redirectNotAllowed
000000019d8cea48  strb w8, [x20, #0x28]
000000019d8cea4c  ... completion(status != 3)  ; allow == true, no counter incremented
```
No redirect count is kept and no depth limit is applied in WebKit's own client; loop protection
rests entirely on the network layer's default redirect cap and the 10 s timeout from
`WellKnownFetchLimits`. Not memory-unsafe; at worst a bounded resource-exhaustion / SSRF-ish
question. **SPECULATIVE**, and it needs the network-layer default to be confirmed.

### CAND-3 — `expectedContentLength` check: **REFUTED / CLEAN NEGATIVE**

`didReceiveResponse` 0x19d8ceaac:
```
000000019d8ceb18  bl   0x1a011a8b0           ; response.expectedContentLength()
000000019d8ceb1c  cmp  x0, #0x1
000000019d8ceb20  b.lt 0x19d8ceb4c           ; < 1 (incl. -1 == NSURLResponseUnknownLength) -> allow
000000019d8ceb24  ldr  x8, [x20, #0x10]      ; m_maxSize
000000019d8ceb28  cmp  x0, x8
000000019d8ceb2c  b.ls 0x19d8ceb4c           ; <= maxSize -> allow
000000019d8ceb34  mov  w8, #0x4               ; else status = tooLarge, cancel
```
Signed `-1` is handled before the unsigned compare (`b.lt` precedes `b.ls`). Clean.

### CAND-4 — IOSurface rowbytes / plane-count arithmetic: **not present in this binary**

`ImageBufferRemoteIOSurfaceBackend::setBackendHandle` (0x19daed73c) and
`ImageBufferShareableMappedIOSurfaceBackend::create` (0x19daed984) do **no** size arithmetic — they
move a `WTF::MachSendRight` into the backend and construct the object:
```
000000019daed99c  ldrb w8, [x1, #0x78]
000000019daed9a0  cmp  w8, #0x1
000000019daed9a4  b.ne 0x19daeda84           ; wrong variant -> null
000000019daed9bc  cbz  x0, 0x19daeda84       ; null send right -> null
000000019daed9cc  bl   0x1a0117340           ; -> IOSurface from send right
```
The size/rowbytes/plane arithmetic lives in **WebCore** — `WebKit` imports
`WebCore::IOSurface::createFromSendRight(MachSendRight&&)` and, notably,
**`WebCore::IOSurface::createFromUntrustedUncompressedWebKitSendRight(MachSendRight&&)`**.
That is the right next front for the "web-content-controlled IOSurface" bug class; it cannot be
audited from this binary (WebCore is not extracted here, and `__auth_stubs` is zero-length in this
extraction so stub→import xrefs are unresolvable).

---

## 5. Verdict table

| # | item | verdict |
|---|---|---|
| 1 | WebKit opens any IOKit user client (`IOServiceOpen`/`IOConnectCall*`/class-name string) | **REFUTED / CLEAN NEGATIVE** — 0 imports, 0 strings, 0 dlsym soft-links |
| 2 | `AppleJPEGDriverUserClient` opened by WebKit code | **REFUTED / CLEAN NEGATIVE** for WebKit; the sandbox flip is a dev-mode-only hardening (see §2) |
| 3 | `sandbox_extension_issue_iokit_registry_entry_class` used by WebKit | **SPECULATIVE** — imported, but no class name and no xref to the extension string |
| 4 | `didReceiveData` accumulation overflow | **REFUTED / CLEAN NEGATIVE** — 64-bit compare vs 65536, enforced cancel |
| 5 | `didReceiveResponse` content-length check | **REFUTED / CLEAN NEGATIVE** — `-1` handled, cancel enforced |
| 6 | Redirect loop / no depth limit in WebKit's well-known fetcher | **SPECULATIVE** — no counter in `willPerformHTTPRedirection` |
| 7 | IOSurface rowbytes/plane/height overflow | **not in this binary** — arithmetic is in WebCore; start at `WebCore::IOSurface::createFromUntrustedUncompressedWebKitSendRight` |
| 8 | GPU `AGXDeviceUserClient` rule rewritten to `require-any (iokit-connection "IOGPU")` | **live surface, unchanged in reach** — noted, not a bug claim |
