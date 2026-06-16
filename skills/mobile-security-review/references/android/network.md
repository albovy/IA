# Android — MASVS-NETWORK (static)

Scope: secure data in transit for an Android artifact — cleartext, TLS/cert/hostname validation, user trust anchors, and identity pinning — analyzed statically from the manifest, the Network Security Config (`res/xml/*`), and decompiled code (no device).

Anchor each finding to the exact control in SKILL.md (read it); verify MASWE/MASTG IDs against the live guide.

## Group controls (MASVS v2.0.0, verbatim)
- **MASVS-NETWORK-1** — The app secures all network traffic according to the current best practices. *(cleartext, disabled TLS/hostname/cert validation, user trust anchors)*
- **MASVS-NETWORK-2** — The app performs identity pinning for all remote endpoints under the developer's control. *(missing/weak pinning)*

> The manifest `usesCleartextTraffic` / `networkSecurityConfig` attributes and the referenced `res/xml/*.xml` are first read in the static **Pre-pass** (manifest & build). This file is where you analyze them. **Profile note:** pinning is profile-dependent — expected at **L2/R**, optional at **L1**; "permitted but unused" cleartext is a weak/Info signal, not a finding.
>
> **Cross-platform caveat (check the framework first):** the NSC and `usesCleartextTraffic` govern only the **platform HTTP stack** (`HttpURLConnection`/OkHttp/Retrofit/Volley/system-WebView). **Flutter ships its own BoringSSL and ignores the NSC and the system proxy** — for a Flutter app, cleartext/pinning/validation live in Dart (`HttpClient.badCertificateCallback` returning `true` = validation disabled; `SecurityContext`/pinning packages), so NSC-based conclusions are invalid for Flutter traffic. React Native uses the platform OkHttp stack (NSC applies) plus any JS `fetch`/pinning module. Detect the framework before trusting any conclusion drawn from the NSC alone.

## Checks (each = static check + MASVS anchor + MASWE + MASTG id)

### Cleartext (HTTP) traffic
- **Manifest + NSC cleartext flag.** `usesCleartextTraffic="true"` on `<application>` and/or `cleartextTrafficPermitted="true"` on the NSC `<base-config>` / `<domain-config>`. **Caveat:** `usesCleartextTraffic` is deprecated and **ignored for apps targeting API ≥ 28** (the NSC becomes authoritative on modern targets) — inspect **both**, and note the `targetSdk`. Reachable cleartext to a real endpoint = finding; "permitted" with no actual cleartext endpoint in the app is a weak/Info signal. → **MASVS-NETWORK-1** / **MASWE-0050** / **MASTG-TEST-0235** (Android App Configurations Allowing Cleartext Traffic — static).
- **Platform-default cleartext on low `minSdk`.** Cleartext is allowed by the platform default pre-API-28; an app with `minSdk < 28` and **no** NSC `cleartextTrafficPermitted="false"` inherits the permissive default on old devices. → **MASVS-NETWORK-1** / **MASWE-0050** / **MASTG-TEST-0235** (static; live counterpart MASTG-TEST-0236 "Cleartext Traffic Observed on the Network" — dynamic, do not claim without a device).
- **Hardcoded `http://` URLs.** Plaintext endpoints in code/resources/`assets/` (string literals, Retrofit `baseUrl`, OkHttp, `WebView.loadUrl`). A reachable `http://` to an app endpoint is a real cleartext channel. → **MASVS-NETWORK-1** / **MASWE-0050** / **MASTG-TEST-0233** (Hardcoded HTTP URLs — static & dynamic).
- **NSC nuances to read precisely** (decide whether the finding is real per domain, not just "an `http` exists"):
  - Default-deny base `<base-config cleartextTrafficPermitted="false">` with a narrower `<domain-config cleartextTrafficPermitted="true">` carve-out → only those domains are exposed.
  - Per-domain `includeSubdomains="true"` widens the carve-out — enumerate the affected hosts.

### TLS configuration
- **Outdated TLS explicitly allowed in code.** `SSLContext.getInstance("TLSv1"/"SSLv3")`, `setEnabledProtocols(...)`/`setEnabledCipherSuites(...)` re-enabling weak protocols/suites, OkHttp `ConnectionSpec` permitting `TLS_1_0`/`TLS_1_1` or weak ciphers. This is the programmatic-downgrade case (not just a literal SSLv3 string). → **MASVS-NETWORK-1** / **MASWE-0050** / **MASTG-TEST-0217** (Insecure TLS Protocols Explicitly Allowed in Code — static). *(Live negotiated-protocol check is MASTG-TEST-0218 "Insecure TLS Protocols in Network Traffic" — dynamic; mark Needs dynamic verification.)*
- **GMS Security Provider not updated.** App relies on the system TLS provider on old devices without calling `ProviderInstaller.installIfNeeded()` / `installIfNeededAsync()` before establishing TLS → stuck with the device's outdated provider (e.g. no TLS 1.2 pre-API-20, historical OpenSSL CVEs). Confirm the install call exists **and** runs before any connection. → **MASVS-NETWORK-1** / **MASWE-0052** / **MASTG-TEST-0295** (GMS Security Provider Not Updated — static, with a runtime ordering aspect). *(Legacy umbrella: MASTG-TEST-0023 "Testing the Security Provider".)*

### Endpoint identity verification (cert + hostname)
- **Unsafe custom trust evaluation (accept-all `TrustManager`).** A custom `X509TrustManager` whose `checkServerTrusted()` is empty / never throws, or an `SSLSocketFactory`/`SSLContext` initialized with such a manager → all certificates accepted (full MITM). Grep for `checkServerTrusted`, `TrustManager`, `X509TrustManagerExtensions`, `SSLContext.init`. → **MASVS-NETWORK-1** / **MASWE-0052** / **MASTG-TEST-0282** (Unsafe Custom Trust Evaluation — static/manual). *(Legacy umbrella: MASTG-TEST-0021 "Testing Endpoint Identify Verification".)*
- **Permissive `HostnameVerifier`.** A `HostnameVerifier.verify()` that `return true`, or `ALLOW_ALL_HOSTNAME_VERIFIER`/`NullHostnameVerifier` wired into an `HttpsURLConnection`/OkHttp client → connects to any host regardless of CN/SAN. → **MASVS-NETWORK-1** / **MASWE-0052** / **MASTG-TEST-0283** (Incorrect Implementation of Server Hostname Verification — static).
- **Raw `SSLSocket` hostname-verification gap.** `SSLSocketFactory.createSocket()` / raw `SSLSocket` verifies the chain but **does not verify the hostname** unless the code explicitly calls a `HostnameVerifier.verify()` or sets `SSLParameters.setEndpointIdentificationAlgorithm("HTTPS")`. Flag raw-socket TLS that omits this step. → **MASVS-NETWORK-1** / **MASWE-0052** / **MASTG-TEST-0234** (Missing Implementation of Server Hostname Verification with SSLSockets — static).

### User trust anchors (interception CAs)
- **NSC explicitly trusts user CAs.** `<trust-anchors>` containing `<certificates src="user"/>` in the production config lets user-installed CAs (interception proxies) MITM the app. Acceptable **only** inside a `<debug-overrides>` block (which applies only to debuggable builds — confirm it is not the base/production config). → **MASVS-NETWORK-1** / **MASWE-0052** / **MASTG-TEST-0286** (Network Security Configuration Allowing Trust in User-Provided CAs — static).
- **Implicit user-CA trust from low `minSdk`.** Apps targeting **API ≤ 23** trust user-added CAs **by default** (no NSC needed) — distinct from the explicit `src="user"` case above. Flag when `targetSdk ≤ 23` and no NSC overrides the default. → **MASVS-NETWORK-1** / **MASWE-0052** / **MASTG-TEST-0285** (Outdated Android Version Allowing Trust in User-Provided CAs — static).

### Identity pinning (MASVS-NETWORK-2)
- **Pinning presence + variant enumeration.** Determine whether pinning exists, where, and for which domains — and which mechanism a pentester would need to bypass. Check **all** of: NSC `<pin-set>` (+ its `<domain>` scope), OkHttp `CertificatePinner`, manual `TrustManager`/`X509TrustManagerExtensions` pin comparison, Conscrypt, Volley/Retrofit custom `SSLSocketFactory`, Flutter/Cordova pinning plugins, and native `.so` pinning. **Missing pinning is profile-dependent** (expected at L2/R, optional at L1). → **MASVS-NETWORK-2** / **MASWE-0047** / **MASTG-TEST-0242** (Missing Certificate Pinning in Network Security Configuration — static). *(The MITM-based dynamic confirmation is MASTG-TEST-0244 "Missing Certificate Pinning in Network Traffic"; bypass technique MASTG-TECH-0012 — do not claim a dynamic bypass result without a device.)*
- **Pinning present but bypassable / partial.** Pin set covering only some `<domain>`s (other endpoints unpinned), pinning applied to one client but not others, or a single leaf pin with **no backup pin** (robustness/availability note). → **MASVS-NETWORK-2** / **MASWE-0047** / **MASTG-TEST-0242** (static).
- **Expired NSC pins.** `<pin-set expiration="YYYY-MM-DD">` with a date in the past → Android silently **stops enforcing** the pin and falls back to normal CA validation (pinning is effectively off). → **MASVS-NETWORK-2** / **MASWE-0047** / **MASTG-TEST-0243** (Expired Certificate Pins in the Network Security Configuration — static).

### WebView TLS-error suppression (MITM-in-WebView)
- **`onReceivedSslError` → `handler.proceed()`.** A custom `WebViewClient.onReceivedSslError()` that calls `handler.proceed()` (instead of `handler.cancel()`) ignores certificate errors for content loaded in the WebView. **The WebView HTTP stack does not honor the NSC `<pin-set>`**, so this is a full MITM-in-WebView independent of the rest of the network config — high impact when the WebView loads anything sensitive. → **MASVS-NETWORK-1** / **MASWE-0052** / **MASTG-TEST-0284** (Incorrect SSL Error Handling in WebViews — static). *(The WebView component itself also touches MASVS-PLATFORM-2; anchor the TLS-bypass weakness in NETWORK.)*

### Open ports / listening sockets / embedded servers
- **App-side listeners shipped in the artifact** — `ServerSocket`/`bind()`/`listen()`, an embedded HTTP server (NanoHTTPD, Ktor `embeddedServer`, Jetty), or a debug/dev listener left enabled in release (RN Metro `8081`, Flutter Dart VM service, exposed debug bridges). A listening port is reachable by other apps on-device and often over the LAN → an unauthenticated control/data surface. Grep `ServerSocket`, `bind(`, `listen(`, `NanoHTTPD`, `embeddedServer`, and hardcoded port literals; confirm it isn't gated to debug builds. → **MASVS-NETWORK-1** · MASWE-0051 (Unprotected Open Ports) · **MASTG-TEST-0239** (low-level networking APIs for cleartext / raw-socket traffic — static; dedicated open-ports atomic test ID to confirm).

> **Legacy ID map (for older references / cross-checks):** MASTG-TEST-0019 (Data Encryption on the Network), MASTG-TEST-0021 (Endpoint Identify Verification), MASTG-TEST-0023 (Security Provider), MASTG-TEST-0020/0024 (TLS settings) are the legacy narrative umbrellas now split into the atomic 02xx tests cited above. Prefer the atomic id; note "(legacy, superseded by MASTG-TEST-02xx)" if you must cite a low ID. KNOW-0014 (Network Security Configuration) is reference background, not a test.

## Classic false positives
Consult before promoting a candidate. Each below is **usually NOT a finding** absent extra evidence:

| Candidate | Why it's usually a false positive | When it *is* real |
|---|---|---|
| Cleartext "permitted" | NSC / `usesCleartextTraffic` allows it but the app makes **no** cleartext request to a real endpoint | a reachable `http://` endpoint is actually used |
| `usesCleartextTraffic="true"` on a modern target | Ignored for `targetSdk ≥ 28`; the NSC is authoritative there | the NSC also permits cleartext, **or** the artifact targets/runs on API < 28 |
| Missing pinning | Acceptable under **L1** | expected and absent under **L2/R**, or the app handles high-value data |
| Accept-all `TrustManager` / `verify(){return true}` | Lives in a `<debug-overrides>` block or a `BuildConfig.DEBUG`-gated path that ships disabled in release | reachable in the **release** build / not gated by build type |
| User trust anchor `src="user"` | Inside a `<debug-overrides>` block (debuggable builds only) | in the **base/production** config |
| Single leaf pin, no backup | Robustness/availability note, not a security MITM gap on its own | combined with no failover and a real outage/lockout risk worth flagging |
| Expired `<pin-set>` written off as "still present" | — (this is a real finding) | expiration date is in the past → enforcement is off, treat as missing pinning |
| `onReceivedSslError`/trust-all in a Cordova/hybrid WebView | Some frameworks gate it on `android:debuggable` | the bypass executes in a release (non-debuggable) build |

When you dismiss a candidate, record it (and the reason) in the report's "candidates not promoted" appendix — that transparency is part of an honest deliverable.
