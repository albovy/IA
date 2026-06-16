# Android — MASVS-PLATFORM (static)

Static analysis of an Android artifact (`.apk` / `.aab` / extracted APK / smali / jadx output) for safe interaction with the OS and other apps: IPC/exported components, deep links, WebViews, and UI exposure. Reuse the **exported-components list** built in the pre-pass (`AndroidManifest.xml`).

Anchor each finding to the exact control in SKILL.md (read it); verify MASWE/MASTG IDs against the live guide.

> Every check here is a **candidate generator** — promote to a finding only after the SKILL.md gate (real evidence? reachable in this build under this profile? honest confidence?). Cite the MASVS control by **statement match**, not group alone. IDs verified against `mas.owasp.org` and the `OWASP/owasp-mastg` + `OWASP/maswe` repos (June 2026); atomic tests (0200+/0300+) currently live under `/tests-beta/` in the repo and resolve under `/tests/` on the site. Legacy narrative tests and atomic successors coexist.

## Group controls (verbatim, MASVS v2.0.0)
- **MASVS-PLATFORM-1** — *The app uses IPC mechanisms securely.* (exported activities/services/receivers/providers, intents, deep links, PendingIntents)
- **MASVS-PLATFORM-2** — *The app uses WebViews securely.* (JS bridges, file/content access, remote/mixed content)
- **MASVS-PLATFORM-3** — *The app uses the user interface securely.* (screenshots, clipboard, notifications, tapjacking, keyboard cache, shoulder-surfing)

---

## Checks

### IPC — exported components (the #1 Android attack surface) · PLATFORM-1
For each exported component from the pre-pass (`android:exported="true"`, OR pre-31 implicit export via an `<intent-filter>` with no explicit `exported`):
1. **Intentional?** Many are exported by accident (an `<intent-filter>` added for a launcher icon, a debug activity left exported).
2. **Protected?** Check `android:permission` and that permission's `protectionLevel` (`signature` = only same-signer apps → usually safe; `normal`/`dangerous`/none = any app can invoke).
3. **What does the handler do?** Read `onCreate`/`onReceive`/`onBind`/`onStartCommand`/`onHandleIntent`. A finding only if the handler does something sensitive with attacker-controlled Intent extras (state change, file/DB access, privileged action, returns secrets). Exported + inert = not a finding.

- **Exported & unprotected activity** that reaches sensitive functionality without the app's intended flow. → **MASVS-PLATFORM-1** · MASWE-0119 (Insecure Activities — exposure of sensitive functionality through exported activities) · **MASTG-TEST-0364** *Exported And Unprotected Activities That Expose Sensitive Functionality*; enumeration MASTG-TECH-0160 (ID to confirm); supersedes legacy **MASTG-TEST-0029** (Sensitive Functionality Exposure Through IPC).
- **Exported & unprotected service.** → **MASVS-PLATFORM-1** · MASWE-0062 (Insecure Services — exposure through services) · **MASTG-TEST-0365** *Exported And Unprotected Services That Expose Sensitive Functionality*; legacy MASTG-TEST-0029.
- **Exported & unprotected broadcast receiver.** → **MASVS-PLATFORM-1** · MASWE-0063 (Insecure Broadcast Receivers — exposure through receivers) · **MASTG-TEST-0366** *Exported And Unprotected Broadcast Receivers That Expose Sensitive Functionality*; legacy MASTG-TEST-0029.

### ContentProviders (high impact — they front data) · PLATFORM-1
- **Exported provider** or `grantUriPermissions="true"` → check `<path-permission>` / `<grant-uri-permission>` scope. → **MASVS-PLATFORM-1** · MASWE-0064 (Insecure Content Providers) · **MASTG-TEST-0355 / MASTG-TEST-0356** (content-provider DB access; one is runtime) (titles to confirm); legacy MASTG-TEST-0029.
- **Path traversal**: provider that maps a URI/`openFile` path into the filesystem without canonicalizing (`../` escapes the intended dir → read arbitrary app files). → **MASVS-PLATFORM-1** · MASWE-0064 · MASTG-TEST-0356 (ID to confirm).
- **FileProvider / grant-URI oversharing**: broad `filepaths.xml` roots (root path / empty path), `openFile` returning URIs outside the intended dir → other apps open private files via `content://`. → **MASVS-PLATFORM-1** · MASWE-0064 · **MASTG-TEST-0357** *References to Oversharing of File-Based Content Providers*; technique MASTG-TECH-0159 (ID to confirm).
- **SQL injection** in `query()`/`update()` building SQL from `selection`/`projection`/`sortOrder` via string concatenation instead of `selectionArgs`: this anchors to **MASVS-CODE-4** (MASWE-0086, MASTG-TEST-0339), not PLATFORM — see the CODE reference. Flag the provider here as the entry point.

### Intents — redirection & implicit-intent egress · PLATFORM-1
- **Intent redirection / nested-Intent extraction (confused deputy)**: an exported component reading `getParcelableExtra(..., Intent.class)` / `EXTRA_INTENT` and then `startActivity/startService`, `sendBroadcast`, `setResult`, or `grantUriPermission` with the *inner* attacker-supplied Intent. → **MASVS-PLATFORM-1** · MASWE-0066 (Insecure Intents) · descriptive test "Intent redirection / nested Intent" (ID to confirm — no confirmed atomic test).
- **Implicit-intent egress (sending side)**: sensitive extras on an implicit `startActivity`/`sendBroadcast` (action set, no `setComponent`/`setPackage`) — any installed app can receive them. → **MASVS-PLATFORM-1** · MASWE-0066 · **MASTG-TEST-0372** *Implicit Intents Used for Internal App Communication*, **MASTG-TEST-0374** *References to Implicit Intents Carrying Sensitive Extras* (both filed under `tests-beta/android/MASVS-CODE/` in the repo but anchor to PLATFORM-1 by statement — the weakness is insecure IPC); legacy **MASTG-TEST-0026** (Testing Implicit Intents).
- **Unprotected `sendBroadcast`** (no `receiverPermission`) and **missing validation of returned data**: data from an implicit-intent response (e.g. `onActivityResult`) used in a sensitive sink without sanitizing (`file://` / `../`, malicious URI). → **MASVS-CODE-4** for the returned-data validation gap · MASWE-0083 (Improper handling of returned data) · **MASTG-TEST-0375** *Missing Validation of Data Returned from Implicit Intents* — cross-reference here as the egress/return surface.

### Deep links / App Links · PLATFORM-1
- Enumerate `<data>` schemes/hosts in intent-filters. For `http(s)` App Links check `android:autoVerify="true"` **and** that `assetlinks.json` is actually hosted — unverified links can be hijacked by another app claiming the same scheme. Pre-31, one non-verifiable link can disable verification for *all* the app's App Links.
- Trace where the link's parameters flow: into a WebView `loadUrl`? an OAuth **redirect_uri** capture (→ AUTH)? a file/SQL sink (→ CODE-4)? a nested Intent (→ MASWE-0066)? The handler must treat all deep-link input as untrusted.
- → **MASVS-PLATFORM-1** · MASWE-0058 (Insecure Deep Links) · legacy **MASTG-TEST-0028** *Testing Deep Links* (atomic successor to confirm).

### Mutable PendingIntents · PLATFORM-1
- `PendingIntent.get*` created without `FLAG_IMMUTABLE` (must be explicit on API ≥ 31) and handed to another component/app → the base Intent can be mutated/redirected ("PendingIntent hijacking"). **The exploitable case is an implicit base Intent** (no explicit component/package set) — that's what an attacker can fill in. Find `PendingIntent.get*` calls and check both the flags and whether the base Intent is explicit. → **MASVS-PLATFORM-1** · MASWE-0066 (Insecure Intents) · **MASTG-TEST-0030** *Testing for Vulnerable Implementation of PendingIntent*.

### Task hijacking (StrandHogg v1/v2) · PLATFORM-3
- Parse every `<activity>`/`<activity-alias>` for `taskAffinity`, `allowTaskReparenting`, `launchMode`. Flag non-default/empty `taskAffinity` + `allowTaskReparenting="true"` on entry/sensitive activities when `launchMode` ≠ `singleInstance`/`singleTask` → a malicious app can insert itself into the task and phish. Hardening: `singleInstance` + `taskAffinity=""`. → **MASVS-PLATFORM-3** · MASWE-0057 (StrandHogg Attack / Task Affinity Vulnerability) · descriptive test "task-affinity / StrandHogg" (ID to confirm — no confirmed atomic test).

### Custom permissions / sharedUserId · PLATFORM-1
- **Custom-permission squatting / downgrade**: enumerate the app's *declared* `<permission>` and their `protectionLevel`. Flag `normal`/`dangerous`/none-level custom permissions gating exported components, and the pre-API-29 first-installer-wins squatting race. A signature-*looking* guard backed by a `normal`-level custom permission is trivially defeated. → **MASVS-PLATFORM-1** · MASWE-0059 (Use Of Unauthenticated Platform IPC) · related legacy MASTG-TEST-0024 (Testing for App Permissions); technique MASTG-TECH-0117 (Obtaining Information from the AndroidManifest).
- **`sharedUserId` / `sharedUserLabel`** (record in pre-pass): merges UID/sandbox with same-signing-key apps. Deprecated API ≥ 29 but still shipped. → **MASVS-PLATFORM-1** · MASWE-0059 (or `MASWE: unmapped`) · technique MASTG-TECH-0117 (ID for a dedicated test to confirm).

### WebViews — JS bridge & content/file access · PLATFORM-2
Read each WebView's settings, what URL is loaded, and where its input comes from. A hardcoded `https://` to a trusted host is fine; loading attacker-influenceable URLs (from a deep link/Intent extra into `loadUrl`/`loadDataWithBaseURL`) is the recurring real bug.
- **`addJavascriptInterface(obj, "name")`** exposes Java methods (annotated `@JavascriptInterface`, required API ≥ 17) to JS. Combined with remote/untrusted content = RCE-class; the bridge is reachable by *any* page the WebView navigates to. → **MASVS-PLATFORM-2** · MASWE-0069 (WebViews Allows Access to Local Resources) · **MASTG-TEST-0334** *Native Code Exposed Through WebViews*; legacy **MASTG-TEST-0033** (Java Objects Exposed Through WebViews). Knowledge: MASTG-KNOW-0018.
- **`setJavaScriptEnabled(true)`** with remote or mixed content (`setMixedContentMode` allowing HTTP). → **MASVS-PLATFORM-2** · MASWE-0069 · legacy MASTG-TEST-0031 (JavaScript Execution in WebViews).
- **File access**: `setAllowFileAccess(true)` / `setAllowFileAccessFromFileURLs` / `setAllowUniversalAccessFromFileURLs(true)` — `file://` + JS can read local/cross-origin files. **`setAllowFileAccess` defaults to `false` on API ≥ 30**, so a finding only if explicitly enabled. → **MASVS-PLATFORM-2** · MASWE-0069 · **MASTG-TEST-0252** *References to Local File Access in WebViews* (+ MASTG-TEST-0253, file-access combos) (ID to confirm); supersedes legacy MASTG-TEST-0032.
- **Content access**: `setAllowContentAccess(true)` combined with JS + universal file-URL access; `loadUrl("file:///android_asset|res")`; WebViewAssetLoader misconfig. → **MASVS-PLATFORM-2** · MASWE-0069 · **MASTG-TEST-0250** *References to Content Provider Access in WebViews* + **MASTG-TEST-0251** *Runtime Use of Content Provider Access APIs in WebViews* (0251 is runtime).
- **Unsafe `shouldInterceptRequest` / `WebResourceResponse`**: a custom `WebViewClient.shouldInterceptRequest`/`shouldOverrideUrlLoading` building responses from attacker-controlled paths (traversal into the web origin) or skipping URL validation → UXSS-class. → **MASVS-PLATFORM-2** · MASWE-0073 (Insecure WebResourceResponse Implementations) · descriptive test (ID to confirm).
- **WebView sensitive-data cleanup on logout** *(low priority)*: missing `clearCache`/`clearHistory`/`clearFormData` / `CookieManager.removeAllCookies` / `WebStorage.deleteAllData` / WebViewDatabase clear after using storage-backed features. → **MASVS-PLATFORM-2** · MASWE-0118 (Sensitive Data Not Removed After Use) · **MASTG-TEST-0320** *WebViews Not Cleaning Up Sensitive Data*; legacy MASTG-TEST-0037.
- **WebView HTTP-auth credential handling** *(niche)*: `onReceivedHttpAuthRequest` + `get/setHttpAuthUsernamePassword` persisting/auto-submitting Basic/Digest creds → these anchor to **MASVS-AUTH-1** (MASWE-0040, ID to confirm), not PLATFORM; note in passing.

> **WebView remote debugging** (`WebView.setWebContentsDebuggingEnabled(true)`) is **independent of the manifest `debuggable` flag** and anchors to **MASVS-RESILIENCE-4** (MASWE-0067, **MASTG-TEST-0227** *Debugging Enabled for WebViews*) — assessed under the **R** profile, not here. Cross-reference only.

### UI exposure · PLATFORM-3
Surfaces other apps or onlookers can capture; easy to miss because they aren't IPC. Assess for any screen showing sensitive data (credentials, tokens, PAN, OTP, balances).
- **Screenshots / task snapshots**: no `FLAG_SECURE` on windows showing sensitive data → captured in the app-switcher thumbnail and by screenshot/screen-record. Also check the granular APIs — `setRecentsScreenshotEnabled(false)`, `SurfaceView.setSecure(true)`, Compose `SecureFlagPolicy` — since `FLAG_SECURE` alone misses SurfaceView/recents. → **MASVS-PLATFORM-3** · MASWE-0055 (Screenshots/recents leakage) · **MASTG-TEST-0291** *References to Screen Capturing Prevention APIs* (static); runtime counterparts MASTG-TEST-0289/-0292/-0293/-0294; legacy MASTG-TEST-0010.
- **Keyboard cache**: sensitive `EditText` without `inputType` `textNoSuggestions`/`textPassword`/`textVisiblePassword` (and `IME_FLAG_NO_PERSONALIZED_LEARNING`) → typed data is cached/learned by the IME. Check `res/layout/*` + code. → **MASVS-PLATFORM-3** · MASWE-0053 (Sensitive Data Leaked via the User Interface) · **MASTG-TEST-0258** *References to Keyboard Caching Attributes in UI Elements*; auth-fields variant MASTG-TEST-0316 (ID to confirm).
- **Clipboard / pasteboard**: sensitive fields copied to the global clipboard (`ClipboardManager.setPrimaryClip` or a copy button) — any app can read it. Note absence of auto-clear and the `EXTRA_IS_SENSITIVE` flag (API 33+); paste access is restricted on API 29+/Android 12. → **MASVS-PLATFORM-3** · MASWE-0053 (rel. IPC framing MASWE-0059) · descriptive test (ID to confirm).
- **Tapjacking / overlay**: sensitive UI lacking `android:filterTouchesWhenObscured="true"` / `setFilterTouchesWhenObscured(true)` / `onFilterTouchEventForSecurity` → an overlay can steal taps. → **MASVS-PLATFORM-3** · MASWE-0053 (the test links the UI-leak umbrella; specific weakness MASWE-0056 *Tapjacking Attacks*) · **MASTG-TEST-0340** *References to Overlay Attack Protections*; legacy MASTG-TEST-0035.
- **Notifications**: secrets in `NotificationCompat` content with `VISIBILITY_PUBLIC` and no `VISIBILITY_PRIVATE`/`SECRET`/`setPublicVersion` → shown on the lock screen. → **MASVS-PLATFORM-3** · MASWE-0054 (Sensitive Data Exposed via Notifications) · **MASTG-TEST-0315** *Sensitive Data Exposed via Notifications*. (Also STORAGE-2 cross-ref for the underlying leak.)
- **Autofill**: sensitive values exposed via the Autofill framework. → **MASVS-PLATFORM-3** · MASWE-0053 · descriptive test (ID to confirm).

---

## Classic false positives
Consult before promoting a candidate. Each is **usually NOT a finding** absent the extra evidence in the right column.

| Candidate | Why it's usually a false positive | When it *is* real |
|---|---|---|
| Exported receiver/service/activity "unprotected" | Protected by an `android:permission` with `signature` protectionLevel → only same-signer apps reach it | permission is `normal`/`dangerous`/absent **and** the handler does something sensitive with attacker-controlled extras |
| `setAllowFileAccess` "enabled" in a WebView | Default `true` on API ≤ 29; default is `false` on API ≥ 30 | explicitly set `true` with `file://` + JS / remote content |
| `addJavascriptInterface` present | Bridge only loads bundled, trusted, same-origin content and exposes nothing sensitive | reachable from remote/untrusted/mixed content, or a deep-link param reaches `loadUrl` |
| Deep link / custom scheme declared | Scheme is inert or the handler validates and does nothing sensitive | params flow unvalidated into `loadUrl`/SQL/file/nested-Intent or an OAuth redirect capture; or an `autoVerify` App Link with no hosted `assetlinks.json` |
| `taskAffinity` / `allowTaskReparenting` set | Default affinity, or `launchMode` already `singleInstance`/`singleTask` (StrandHogg mitigated) | non-default/empty affinity + `allowTaskReparenting=true` on a sensitive activity with a hijackable launchMode |
| Mutable `PendingIntent` | Base Intent is **explicit** (component/package set) — nothing for an attacker to fill in | mutable + **implicit** base Intent handed to another app/component |
| Custom permission "protects" a component | `protectionLevel="signature"` — only same-signer apps hold it | `normal`/`dangerous` custom permission (squattable / grantable to any app), masquerading as a real guard |
| Missing `FLAG_SECURE` / clipboard / keyboard cache | The screen/field shows **no** sensitive data | screen shows credentials/tokens/PAN/OTP/balances and the protection is absent |
| WebView debugging enabled | Gated behind a debug-only flag, or it's a **debug** build | `setWebContentsDebuggingEnabled(true)` unconditional in the **release** artifact (→ RESILIENCE-4, not PLATFORM) |

When you dismiss a candidate, record it (and the reason) in the report's "candidates not promoted" appendix.
