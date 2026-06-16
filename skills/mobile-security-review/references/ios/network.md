# iOS — MASVS-NETWORK (static)

Static checks for secure data-in-transit on an iOS artifact (`.ipa` / `.app` bundle / Mach-O): ATS configuration, cleartext, TLS settings, endpoint trust, pinning, and low-level/embedded networking that bypasses ATS.

Anchor each finding to the exact control in SKILL.md (read it); verify MASWE/MASTG IDs against the live guide.

> **Two iOS-specific caveats that decide whether these checks are even valid:**
> - **FairPlay encryption.** Against an App Store binary (`cryptid=1`) `otool`/`nm`/strings read **ciphertext** for `__TEXT` — any symbol/string conclusion about networking code is invalid until you decrypt (see the static methodology / extraction reference). Info.plist ATS keys live in cleartext and stay readable.
> - **ATS scope.** App Transport Security governs only the URL Loading System (`URLSession`/`NSURLConnection`/`WKWebView`). It does **not** apply to `Network.framework`, `CFNetwork` streams, BSD sockets, or any embedded TLS stack (OpenSSL/BoringSSL/mbedTLS/curl/gRPC), and **cross-platform runtimes ignore it entirely** — Flutter ships its own BoringSSL and ignores ATS/system proxy, so Dart traffic must be assessed in the Dart snapshot, and React Native trust-all native modules sit outside ATS too. A clean `Info.plist` is **not** proof traffic is protected. (See `references/cross-platform-static.md`.)

## Group controls (MASVS v2.0.0, verbatim)
- **MASVS-NETWORK-1** — The app secures all network traffic according to the current best practices. *(cleartext, disabled TLS/hostname/cert validation, outdated TLS, low-level/embedded sockets)*
- **MASVS-NETWORK-2** — The app performs identity pinning for all remote endpoints under the developer's control. *(missing/weak pinning — profile-dependent: expected at L2/R)*

Everything below is a **candidate generator** — promote to a finding only after the anti-false-positive gate in SKILL.md. The MASTG is mid-refactor: legacy umbrella tests (`MASTG-TEST-0067` endpoint identity, `-0068` pinning) coexist with atomic, MASWE-mapped successors (`0321`/`0322`/`0323`/`0342`–`0345`). Prefer the atomic test; note the legacy umbrella. Live URL: `https://mas.owasp.org/MASTG/tests/ios/MASVS-NETWORK/<ID>/`.

## Checks

### ATS configuration (Info.plist)
- **Global ATS disabled** — `NSAppTransportSecurity` → `NSAllowsArbitraryLoads=true` turns ATS off app-wide. Reachable cleartext to a real endpoint = finding; a blanket exception with no actual cleartext endpoint is weaker/Info. → **MASVS-NETWORK-1**, MASWE-0050, **MASTG-TEST-0322** (App Transport Security Configurations Allowing Cleartext Traffic; static); legacy umbrella `MASTG-TEST-0065`.
- **Per-domain insecure HTTP** — `NSExceptionDomains` entries with `NSExceptionAllowsInsecureHTTPLoads=true` (or `NSThirdPartyExceptionAllowsInsecureHTTPLoads`); scope-widening `NSIncludesSubdomains=true`. → **MASVS-NETWORK-1**, MASWE-0050, **MASTG-TEST-0322**.
- **WebView-content cleartext** — `NSAllowsArbitraryLoadsInWebContent=true` (and `NSAllowsLocalNetworking`) permit cleartext inside `WKWebView` even when top-level ATS is on. → **MASVS-NETWORK-1**, MASWE-0050, **MASTG-TEST-0322**/**-0342**.
- **Weak ATS TLS exception** — `NSExceptionMinimumTLSVersion` set to `TLSv1.0`/`TLSv1.1`, or `NSExceptionRequiresForwardSecrecy=false` (disables FS / re-permits weak cipher suites). → **MASVS-NETWORK-1**, MASWE-0050, **MASTG-TEST-0342** (References to Weak ATS TLS Policy Exceptions in Info.plist; static).

### Cleartext in code
- **Hardcoded `http://` URLs** — literal cleartext endpoints in the binary/resources (after decryption). Confirm the host is a real, reached endpoint, not a comment/dead string. → **MASVS-NETWORK-1**, MASWE-0050, **MASTG-TEST-0321** (Hardcoded HTTP URLs; static).
- **Low-level networking cleartext (ATS does NOT apply)** — BSD sockets (`socket`/`connect`/`send`/`recv`), CFNetwork streams (`CFStreamCreatePairWithSocketToHost`), `Network.framework` (`NWConnection`/`nw_connection_create`): verify TLS is actually layered on (`NWParameters` built with `.tls`/`NWProtocolTLS`, not `.tcp`). A plain TCP connection to a remote host = cleartext finding even with a pristine ATS dict. → **MASVS-NETWORK-1**, MASWE-0050, **MASTG-TEST-0323** (Uses of Low-Level Networking APIs for Cleartext Traffic; static).

### TLS configuration
- **Outdated TLS via URLSession** — `URLSessionConfiguration.tlsMinimumSupportedProtocolVersion` (or deprecated `tlsMinimumSupportedProtocol`) set to `.TLSv10`/`.TLSv11` (`tls_protocol_version_TLSv10`/`kTLSProtocol1`/`kTLSProtocol11`). Bad practice even though ATS still applies to URLSession. → **MASVS-NETWORK-1**, MASWE-0050, **MASTG-TEST-0343** (URLSession TLS Protocol Configuration; static).
- **Outdated TLS via Network.framework** — `sec_protocol_options_set_min_tls_protocol_version` / `...set_max...` with TLS 1.0 (`0x0301`) or TLS 1.1 (`0x0302`). Network.framework is outside ATS, so this is the dev's sole control. → **MASVS-NETWORK-1**, MASWE-0050, **MASTG-TEST-0344** (Network.framework TLS Protocol Configuration; static).
- **Embedded / third-party TLS stack** — OpenSSL/BoringSSL/mbedTLS/curl/gRPC bundled in `Frameworks/`: grep for verification-disabling and downgrade knobs — `SSL_VERIFY_NONE`, `CURLOPT_SSL_VERIFYPEER=0`/`CURLOPT_SSL_VERIFYHOST=0`, `CURLOPT_SSLVERSION` (SSLv3/TLS1.0), `SSL_CTX_set_min_proto_version`, `mbedtls_ssl_conf_authmode(...NONE)`/`mbedtls_ssl_conf_min_version`. Its own line, not buried under "outdated TLS"; these stacks ignore ATS. → **MASVS-NETWORK-1**, MASWE-0050 (rel. MASWE-0049 *Proven Networking APIs Not Used* / MASWE-0052 *Insecure Certificate Validation*), **MASTG-TEST-0345** (Embedded or Third-party TLS Stack Configuration; static). *(Runtime observation of negotiated TLS: MASTG-TEST-0348 Insecure TLS Protocols in Network Traffic — confirm dynamically, not static.)*

### Endpoint trust / certificate validation
- **Custom `URLSessionDelegate` accepting any trust** — `urlSession(_:didReceiveChallenge:completionHandler:)` calling `completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))` unconditionally → full MITM. Also flag the subtler variants: host-name-only checks, `.performDefaultHandling` while a custom `SecTrustEvaluate(WithError)` ignores its own result, and trust-on-pin-failure fallbacks. → **MASVS-NETWORK-1**, MASWE-0052 (Insecure Certificate Validation), **MASTG-TEST-0067** (Testing Endpoint Identity Verification; legacy umbrella) + atomic successor not yet published (ID to confirm).

### Pinning (NETWORK-2)
- **Pinning present? for which endpoints?** — enumerate every pinning mechanism a pentester must locate and bypass: `URLSession` delegate pin comparison in `didReceiveChallenge` (public-key/cert hash), **TrustKit** (`TSKConfiguration`/`kTSKPublicKeyHashes`), AFNetworking `AFSecurityPolicy` (`SSLPinningMode`/`setPinnedCertificates`), Alamofire `ServerTrustManager`/`PinnedCertificatesTrustEvaluator`, and cross-platform plugin pinning (Flutter `SecurityContext`/pinning packages in the Dart snapshot, RN `react-native-ssl-pinning`/TrustKit, Cordova plugin) — plus native `.so`/embedded-stack pinning. → **MASVS-NETWORK-2**, MASWE-0047 (Insecure Identity Pinning), **MASTG-TEST-0068** (Testing Custom Certificate Stores and Certificate Pinning; legacy umbrella).
- **Pinning weak / partial** — pins present but not applied to all developer-controlled endpoints, pinning the CA/whole chain instead of leaf/intermediate, or trivially bypassable single-point checks. "Missing pinning" is profile-dependent (acceptable under L1; expected & a finding under L2/R or for high-value data). → **MASVS-NETWORK-2**, MASWE-0047, **MASTG-TEST-0068**.

### Open ports / embedded listeners
- **App listening on a socket** — embedded HTTP servers (GCDWebServer/CocoaHTTPServer/Swifter/Telegraph), `bind()`/`listen()`, `NWListener`, or framework debug ports left enabled in release (RN Metro `8081`, Dart VM service). Flag non-loopback binds and release-enabled listeners. → **MASVS-NETWORK-1**, MASWE-0051 (Unprotected Open Ports; static discovery — confirm reachability/binding dynamically → ID to confirm).

### Cross-cuts (one-line, do not duplicate)
- **Auth material over insecure channels** — tokens/credentials on a cleartext or ATS-excepted path, or in URL query strings (logged/cached), instead of headers/body over TLS. This is the AUTH×NETWORK cross-cut: anchor the secret-handling to **MASVS-AUTH-1**/MASWE-0037 and the transport to NETWORK-1 above; lean on MASTG-TEST-0321/-0322/-0323. Do not write a separate NETWORK check for it.

## Classic false positives
Consult before promoting a candidate. Each below is **usually NOT a finding** absent extra evidence:

| Candidate | Why it's usually a false positive | When it *is* real |
|---|---|---|
| `NSAllowsArbitraryLoads=true` ("ATS disabled") | Sometimes set but no cleartext endpoint is actually used; or scoped only to a WebView-content / local-networking exception | a real `http://` endpoint is reached, or it's a blanket production exception |
| Clean `Info.plist` ATS dict ⇒ "traffic is safe" | ATS doesn't cover `Network.framework`/CFNetwork/BSD sockets/embedded TLS, and Flutter/RN ignore ATS entirely | low-level or framework traffic re-derived from code (or the Dart snapshot) shows cleartext / disabled validation |
| Hardcoded `http://` string in the binary | A comment, doc URL, namespace, or dead/unreached string | the URL is an actual reached endpoint carrying app data |
| Strings/symbols "showing trust-all / no pinning" | If the binary is **FairPlay-encrypted** (`cryptid=1`), tool output is ciphertext — the read is invalid, not a finding | binary is decrypted (`cryptid=0`) and the code path is genuinely present |
| Missing pinning | Acceptable under **L1** | expected & absent under **L2/R**, or high-value data |
| `URLSessionDelegate` overriding `didReceiveChallenge` | Override may still call `SecTrustEvaluateWithError` / default handling correctly | it returns a credential unconditionally, ignores the evaluation result, or falls back to trust on pin failure |

When you dismiss a candidate, record it (and the reason) in the report's "candidates not promoted" appendix.
