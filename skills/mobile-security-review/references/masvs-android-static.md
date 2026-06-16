# Android — Static Analysis by MASVS Group

Static checks for an Android artifact (`.apk` / `.aab` / extracted APK). Fully automated, no device required.
Work **group by group**. Everything here is a **candidate generator** — promote to a finding only after the
anti-false-positive gate in `SKILL.md` (real evidence? reachable here? honest confidence?). Cite the MASVS
control as the anchor — **pick the exact control number from the MASVS control list in `SKILL.md`, don't guess
the sub-number** — and **verify MASWE/MASTG IDs against the live guide**. IDs below are current at time of
writing but the catalogs are mid-refactor (MASWE Beta; MASTG splitting into atomic tests).

> ID format note: legacy narrative MASTG tests (low IDs) and atomic tests (higher IDs, e.g. 0200+) coexist
> today. Live URL: `https://mas.owasp.org/MASTG/tests/android/<MASVS-CATEGORY>/<ID>/`.

## Contents
- [Tools & unpacking](#tools--unpacking)
- [Pre-pass — manifest & build](#pre-pass--manifest--build)
- [MASVS-PLATFORM](#masvs-platform)
- [MASVS-STORAGE](#masvs-storage)
- [MASVS-CRYPTO](#masvs-crypto)
- [MASVS-NETWORK](#masvs-network)
- [MASVS-AUTH (client side)](#masvs-auth-client-side)
- [MASVS-CODE](#masvs-code)
- [MASVS-RESILIENCE (R profile only)](#masvs-resilience-r-profile-only)
- [MASVS-PRIVACY](#masvs-privacy)
- [Classic false positives](#classic-false-positives)

---

## Tools & unpacking

| Tool | Use |
|---|---|
| **aapt2** | `aapt2 dump badging app.apk` → package, version, min/target SDK, permissions, launchable activities. Fast triage. |
| **apktool** | `apktool d app.apk -o out/` → decodes resources to near-original form + disassembles DEX to **smali**. Decodes the binary `AndroidManifest.xml` to readable XML and unpacks `res/`, `assets/`, `res/xml/*`. |
| **jadx** | `jadx -d out_src/ app.apk` (or `jadx-gui`) → decompiles DEX to readable **Java**. Best for reading logic, finding secrets, tracing handlers. |
| **apksigner** | `apksigner verify --print-certs app.apk` → signature schemes (v1/v2/v3), signer certificate, debug-cert detection. |
| **MobSF** *(optional)* | Automated static triage (manifest, secrets, insecure API patterns). **Treat every MobSF item as a candidate**, then confirm by reading the decompiled code — MobSF over-reports. |
| **androguard** *(pure-Python)* | JVM-less alternative (pip-installable). Parses the binary manifest, components, permissions, certificate/signing, and DEX (strings, classes, methods) and can decompile — covers manifest + code analysis without Java. Best when no JVM/SDK is available (CI, restricted hosts). |

`.aab`: it's a publishing bundle, not directly installable. Generate the universal APK (`bundletool
build-apks --mode=universal`) and analyze that; note in the report which APK you derived.

Baseline commands (JVM toolchain):
```bash
sha256sum app.apk                              # record THIS hash in the report
aapt2 dump badging app.apk                     # quick metadata
apksigner verify --print-certs --verbose app.apk
apktool d app.apk -o apktool_out               # manifest + smali + resources
jadx -d jadx_out app.apk                        # Java source for reading logic
```

**No JVM? Use androguard (pure-Python).** An APK is a ZIP — `unzip`/`hashlib` get you the file list and
SHA-256; androguard reads the *binary* `AndroidManifest.xml`, signing, and DEX that plain unzip can't.
```python
import hashlib
from androguard.core.apk import APK
print(hashlib.sha256(open("app.apk","rb").read()).hexdigest())   # fingerprint for the report
a = APK("app.apk")
print(a.get_package(), a.get_androidversion_name(), a.get_min_sdk_version(), a.get_target_sdk_version())
print("debuggable:", a.get_attribute_value("application", "debuggable"))   # release-build check
print("allowBackup:", a.get_attribute_value("application", "allowBackup"))
print("netSecConfig:", a.get_attribute_value("application", "networkSecurityConfig"))
for tag in ("activity","activity-alias","service","receiver","provider"):
    for item in a.find_tags(tag):
        name = item.get(a._ns("name")); exported = a.get_value_from_tag(item, "exported")
        perm = a.get_value_from_tag(item, "permission")
        print(tag, name, "exported=", exported, "perm=", perm)
a.get_certificates()                              # signer cert(s); detect debug cert (CN=Android Debug)
```
For code/strings/secrets, work over the decompiled output (`jadx`) **or** the DEX via androgsuard:
`from androguard.misc import AnalyzeAPK` (full xref — heavier), or load `androguard.core.dex.DEX` and scan
strings/method bodies. For large APKs, prefer reading the binary manifest with `APK(...)` (fast) and doing
**targeted** decompilation of suspect classes rather than full-app cross-referencing.

---

## Pre-pass — manifest & build

Read the decoded `AndroidManifest.xml` and Gradle/build hints first; it frames everything else. Build the
**list of exported components** here — later groups reuse it.

- **`android:debuggable`** — `="true"` on a release build is serious (JDWP attach, runtime inspection).
  In a *debug* build it is expected → not a finding. Confirm build type before reporting. **Anchor:
  `MASVS-RESILIENCE-4`** (weakness `MASWE-0067`), not MASVS-CODE. No clean atomic MASTG test covers the manifest
  flag itself → cite the control + descriptive name + "ID to confirm" (don't borrow an unrelated test ID).
- **`android:allowBackup`** — `="true"` (the historical default) may let `adb backup` / cloud backup exfiltrate
  app data on some devices/versions. Severity depends on what STORAGE actually writes. **Anchor:
  `MASVS-STORAGE-2`**, weakness `MASWE-0003` (Backup Unencrypted) — verify live; same "ID to confirm" note applies.
- **`android:usesCleartextTraffic`** — `="true"` permits plaintext HTTP. **Caveat:** this attribute is being
  deprecated (ignored for apps targeting API ≥ 38); on modern targets the **Network Security Config is
  authoritative**. Inspect both. (MASVS-NETWORK)
- **`android:networkSecurityConfig`** — note the referenced `res/xml/*.xml`; analyze it in MASVS-NETWORK.
- **`minSdkVersion` / `targetSdkVersion`** — a low `minSdk` keeps the app exposed to old-OS weaknesses
  (weaker defaults: cleartext allowed pre-28, file access defaults, backup). Low `targetSdk` opts out of
  newer platform hardening. (MASVS-CODE-1 — "requires an up-to-date platform version".)
- **Exported components** — enumerate every `<activity>`/`<service>`/`<receiver>`/`<provider>` that is
  reachable by other apps: `android:exported="true"`, OR (pre-31 implicit export) has an `<intent-filter>`
  with no explicit `exported`. Record each one's `permission` / `protectionLevel`. Drives MASVS-PLATFORM.
- **Confirm it's a RELEASE build** — debug certificate (CN=Android Debug), `debuggable`, test-only flag,
  `BuildConfig.DEBUG` leftovers. Debug-only issues are not shipped-artifact findings.

Reference: MASTG-TECH-0117 (Obtaining Information from the AndroidManifest); MASTG-TECH-0014 / -0025
(static analysis, manual & automated).

---

## MASVS-PLATFORM
*Safe interaction with the OS and other apps.* (Tests: MASTG-TEST-0029 IPC/exported; -0031/-0032/-0033 WebView; KNOW-0018 WebViews.)

**Exported components (the #1 Android attack surface).** For each exported component from the pre-pass:
1. Is the export **intentional**? Many are exported by accident (an `<intent-filter>` added for a launcher
   icon, debug activity left exported).
2. Is it **protected**? Check `android:permission` and that permission's `protectionLevel`
   (`signature` = only same-signer apps → usually safe; `normal`/`dangerous`/none = any app can invoke).
3. **What does the handler actually do?** Read the `onCreate`/`onReceive`/`onBind`/`onStartCommand`. An
   exported component is only a finding if its handler does something sensitive with attacker-controlled
   Intent extras (state change, file/DB access, privileged action, returns secrets). Exported + inert = not a finding.

**ContentProviders** (high impact — they front data):
- Exported provider or `grantUriPermissions="true"` → check `<path-permission>` / `<grant-uri-permission>` scope.
- **Path traversal**: provider that maps a URI/`openFile` path into the filesystem without canonicalizing
  (`../` escapes the intended dir → read arbitrary app files).
- **SQL injection**: `query()`/`update()` building SQL from `selection`/`projection`/`sortOrder` via string
  concatenation instead of `selectionArgs`.

**Deep links / App Links**: `<data>` schemes/hosts in intent-filters. For `http(s)` App Links check
`android:autoVerify="true"` and that `assetlinks.json` is actually hosted (unverified links can be hijacked
by another app claiming the same scheme). Trace where the link's parameters flow (into a WebView? a
WebView `loadUrl`? auth token capture?).

**WebViews** (read each WebView's settings + how it's loaded):
- `addJavascriptInterface(obj, "name")` — exposes Java methods to JS. On `minSdk` where it applies, combined
  with remote/untrusted content = RCE-class. (MASTG-TEST-0033)
- `setJavaScriptEnabled(true)` with **remote or mixed content** (`setMixedContentMode` allowing HTTP).
- `setAllowFileAccess(true)` / `setAllowFileAccessFromFileURLs` / `setAllowUniversalAccessFromFileURLs(true)`
  — `file://` + JS can read local files / cross-origin. Note `setAllowFileAccess` defaults changed to
  `false` on API ≥ 30, so the default is safe on modern targets — only a finding if explicitly enabled.
- What URL is loaded? Hardcoded `https://` to a trusted host is fine; loading attacker-influenceable URLs is not.

**Mutable PendingIntents**: `PendingIntent` created without `FLAG_IMMUTABLE` (required to be explicit on
API ≥ 31) and handed to another component/app → the base Intent can be mutated/redirected ("PendingIntent
hijacking"). Find `PendingIntent.get*` calls and check the flags.

**UI exposure (MASVS-PLATFORM-3)** — surfaces other apps or onlookers can capture; easy to miss because they
aren't IPC. For any screen showing sensitive data (credentials, tokens, PAN, OTP):
- **Clipboard / pasteboard** — sensitive fields copied to the global clipboard (`ClipboardManager.setPrimaryClip`
  or a copy button); any app can read it. Note absence of auto-clear / the `EXTRA_IS_SENSITIVE` flag (API 33+).
- **Keyboard cache** — sensitive `EditText` without `inputType` `textNoSuggestions`/`textPassword`/`textVisiblePassword`
  (and `IME_FLAG_NO_PERSONALIZED_LEARNING`) → typed data is cached/learned by the IME. Check `res/layout/*` + code.
- **Screenshots / task snapshots** — no `FLAG_SECURE` on windows showing sensitive data → captured in the
  app-switcher thumbnail and by screenshot/screen-record.
- **Autofill & notifications** — sensitive values exposed via the Autofill framework, or shown in notifications
  on the lock screen.

---

## MASVS-STORAGE
*Sensitive data at rest, and leakage.* (Tests: MASTG-TEST-0001 local storage; -0202 external storage. Weaknesses incl. `MASWE-0001` logs, `MASWE-0002` internal access, `MASWE-0003` backup — verify live.)

First answer: **what counts as sensitive in THIS app?** (credentials, tokens, PII, health/financial, keys,
session). Storage of non-sensitive data is not a finding.

- **SharedPreferences** — sensitive values written to plain XML (`getSharedPreferences`, `MODE_PRIVATE` is
  still plaintext on disk). `MODE_WORLD_READABLE/WRITEABLE` (deprecated) is worse.
- **SQLite / Room** — unencrypted DBs holding sensitive data; check for SQLCipher if encryption is claimed.
- **Internal vs external files** — internal (`getFilesDir`) is sandboxed; **external** (`getExternalFilesDir`,
  legacy `WRITE_EXTERNAL_STORAGE`, `MediaStore`) is world-readable on older models / shared → sensitive data
  there is exposed. (MASTG-TEST-0202)
- **Secure storage in use?** — `EncryptedSharedPreferences` / `EncryptedFile` (Jetpack Security) and
  Android **Keystore**-backed keys are the expected controls. Note their presence as *mitigations*; check
  they're used for the sensitive data, not just declared.
- **Logs** — sensitive data passed to `Log.d/v/i/e`, `System.out`, `printStackTrace`. (`MASWE-0001`)
- **Keys/secrets in `res/` or `assets/`** — keystores, `.pem`, config with secrets bundled in the package.
- **Exposure paths** — does `allowBackup` (pre-pass) or an exported provider expose any of the above off-device?

---

## MASVS-CRYPTO
*Strong crypto, used correctly; sound key management.* (Tests: MASTG-TEST-0013 symmetric; -0014 algorithm config; -0232 broken symmetric modes / `MASWE-0020`; key-gen `MASWE-0009` — verify live.)

- **Weak/broken primitives** — DES, 3DES, RC4, Blowfish; **MD5/SHA-1 used for a security purpose** (signatures,
  password hashing, integrity of trusted data). MD5/SHA-1 for a non-security checksum/cache key is **not** a finding.
- **Insecure modes/padding** — `Cipher.getInstance("AES/ECB/...")` (ECB leaks structure); `AES/CBC` with a
  static/zero IV; calling `Cipher.getInstance("AES")` (defaults to ECB on Android) — flag the missing explicit
  secure mode. (MASTG-TEST-0232)
- **Hardcoded IVs/keys/salts** — symmetric key, IV, or PBKDF salt as a literal in code/resources.
- **Bad RNG for crypto** — `java.util.Random`/`Math.random()` used to generate keys/IVs/tokens (use
  `SecureRandom`). The deprecated `Crypto`/`SHA1PRNG` provider must not be used.
- **Key management** — keys derived from weak/static material; not stored in the Android Keystore when they
  should be; `KeyGenParameterSpec` misuse (e.g. `setUserAuthenticationRequired(false)` for high-value keys,
  no `setUnlockedDeviceRequired`, purposes too broad). (`MASWE-0009`)
- **Provider pinning** — don't hardcode a security `provider` except for Keystore code; let the platform pick.

---

## MASVS-NETWORK
*Secure data in transit.* (Tests: MASTG-TEST-0019 encryption; -0021 endpoint verification; -0023 security provider; -0235 cleartext config (static); -0244 missing pinning; -0218 insecure TLS; KNOW-0014 Network Security Config. `MASWE-0050` Cleartext — verify live.)

Analyze `res/xml/<network_security_config>.xml` (from the pre-pass) plus the manifest cleartext attribute:
- **Cleartext** — `usesCleartextTraffic="true"` and/or NSC `cleartextTrafficPermitted="true"` on
  `<base-config>` / `<domain-config>`. Reachable cleartext to a real endpoint = finding; "permitted" with no
  actual cleartext endpoint in the app is a weak/Info signal. (MASTG-TEST-0235, `MASWE-0050`)
- **User trust anchors** — NSC `<trust-anchors>` including `<certificates src="user"/>` lets user-installed
  CAs (and thus interception proxies) MITM the app. Acceptable in a *debug-overrides* block; in production config it's a finding.
- **`<debug-overrides>`** — fine *if* it only applies to debuggable builds; confirm it isn't the base config.
- **Pinning** — is certificate/public-key pinning present (NSC `<pin-set>`, OkHttp `CertificatePinner`,
  TrustManager)? For which domains? Missing pinning is profile-dependent: expected at **L2/R**, optional at L1.
  (MASTG-TEST-0244) Pinning to a single leaf cert with no backup pin is a robustness note.
- **Endpoint verification disabled** — custom `TrustManager`/`HostnameVerifier` that accepts all certs
  (`checkServerTrusted(){}`, `verify(){return true}`), `SSLSocketFactory` allowing all. (MASTG-TEST-0021)
- **Outdated TLS** — explicit use of SSLv3/TLS 1.0/1.1, weak cipher suites. (MASTG-TEST-0218)

---

## MASVS-AUTH (client side)
*Client-side handling of auth/authz.* (Test: MASTG-TEST family for AUTH; control MASVS-AUTH-1.)

The server owns authentication; statically you assess the **client's** handling:
- **Token/session handling** — where are tokens stored (→ STORAGE), logged (→ STORAGE logs), or sent
  (→ NETWORK)? Long-lived tokens in plain SharedPreferences are an AUTH+STORAGE finding.
- **Client-side authorization logic** — decisions that should be server-side enforced only in the client
  (feature gating, "isAdmin" flags, price/role checks). Trivially bypassable by tampering → finding (severity
  rises under R / for sensitive functions).
- **Biometrics** — `BiometricPrompt` used purely as a UI gate (returns a boolean) **without** unlocking a
  Keystore key (`CryptoObject` tied to `setUserAuthenticationRequired(true)`) → bypassable by hooking/patching.
  The secure pattern binds the biometric to a cryptographic operation.

---

## MASVS-CODE
*Up-to-date platform, secure data processing, dependencies, input validation.* (Tests: MASTG-TEST-0027 URL loading in WebViews (lives under MASVS-CODE); control MASVS-CODE-1 platform version. `MASWE-0079` unsafe network-data handling — verify live.)

> **Anchor note.** This is where you *look* for several things, but they anchor to other groups: hardcoded
> **API keys/tokens** → `MASVS-AUTH-1` (MASWE-0005); hardcoded **crypto keys/IVs** → `MASVS-CRYPTO`; the
> **`debuggable` flag / debug leftovers that aid reversing** → `MASVS-RESILIENCE`; sensitive data in **logs** →
> `MASVS-STORAGE-2`. True MASVS-CODE findings are: outdated platform (CODE-1), update enforcement (CODE-2),
> known-vulnerable libs (CODE-3), and injection/unsafe-input handling (CODE-4).

- **Hardcoded secrets — strict FP gate.** Distinguish a *real* secret from things that are meant to be public
  or are not exploitable alone:
  - Real secret: server API key/private key/signing key/symmetric key granting access → finding (**anchor
    `MASVS-AUTH-1`** for API keys/tokens, **`MASVS-CRYPTO-2`** for crypto keys/IVs — not MASVS-CODE).
  - **Not** (by itself): OAuth **client_id**, Google **public** API keys that are package/SHA-restricted,
    Firebase config, a **certificate pin / public key**, public base64 of a cert. Confirm what the value
    unlocks before flagging. (See classic FPs.) Weakness ~ `MASWE-0005` (API keys in package) — verify live.
- **Third-party libraries + CVEs** — identify bundled libs and **versions** (smali package paths,
  `META-INF`, embedded `.properties`/`BuildConfig`). A known CVE is a finding only if the **vulnerable code
  path is reachable** in this app — a CVE in a bundled-but-unused library is not. State the version and the reachability basis.
- **Endpoints** — enumerate hardcoded URLs/hosts (attack surface map; flag staging/internal/debug endpoints).
- **Debug leftovers** — `BuildConfig.DEBUG` branches, verbose logging, test menus, `StrictMode` off, debug
  flags, dev backdoors.
- **`Runtime.exec` / `ProcessBuilder`** with externally-influenced input → command injection. Also `DexClassLoader`
  loading code from writable/remote locations (dynamic code loading → anchor `MASVS-CODE-4`; the dynamic-load
  mechanism itself also maps to RESILIENCE / `MASWE-0085`).
- **Unsafe deserialization** — `ObjectInputStream.readObject` / `Serializable`, `Parcelable`, or JSON/XML parsers
  fed attacker-influenced data — *including data arriving via IPC extras or deep links* → object injection. Grep
  `readObject`/`readSerializable`/`getSerializableExtra` and trace the source. (`MASVS-CODE-4`)
- **Unsafe handling of network data** — parsing untrusted responses into sensitive sinks. (`MASWE-0079`)
- **Native libraries (`.so`)** — enumerate JNI exports (`nm -D` / androguard / `strings`) and scan for hardcoded
  secrets and obviously unsafe calls (`strcpy`/`strcat`/`sprintf`/`memcpy` on external input). Deep native
  memory-safety (buffer overflows) is largely **beyond static reach** — name the function and mark
  **Needs dynamic verification** / native review rather than asserting a crash or silently skipping it.

---

## MASVS-RESILIENCE (R profile only)
*Resistance to reverse engineering & tampering.* **Assess only under the R profile.** (Tests: MASTG-TEST-0045 root detection; -0046 anti-debugging; KNOW-0027.)

Under R, *absence* of these is the finding (they're defense-in-depth, never a substitute for L1/L2 controls):
- **Root detection** — checks for `su`/Magisk/known root packages/`test-keys`. Present? Easily bypassed (single point)?
- **Anti-tampering / integrity** — signature/APK-hash self-check; detection of repackaging.
- **Anti-debugging** — `Debug.isDebuggerConnected`, ptrace, timing checks.
- **Anti-hooking / emulator detection** — Frida/Xposed/Substrate detection; emulator fingerprints.
- **Obfuscation** — is the DEX obfuscated (R8/ProGuard/commercial)? If logic and strings are fully readable in
  jadx, RESILIENCE is weak. Under L1/L2, lack of obfuscation is **not** a finding — only under R.

---

## MASVS-PRIVACY
*Minimize/protect personal data; transparency.* (Control MASVS-PRIVACY-1 — minimize access.)

- **Permissions vs actual use** — declared permissions with no corresponding API use (over-permissioning),
  or sensitive permissions (location, contacts, mic, camera) not justified by features.
- **Tracking/analytics SDKs** — identify bundled trackers (ads/analytics/attribution); what do they collect?
- **Persistent identifiers** — collection of IMEI/serial/MAC/Advertising-ID/`ANDROID_ID`, fingerprinting.
- **Exfiltration** — sensitive data sent to third-party or unexpected endpoints (correlate with NETWORK endpoints).

---

## Classic false positives
Consult before promoting a candidate. Each below is **usually NOT a finding** absent extra evidence:

| Candidate | Why it's usually a false positive | When it *is* real |
|---|---|---|
| Exported receiver/service "unprotected" | Protected by an `android:permission` with `signature` protectionLevel → only same-signer apps reach it | permission is `normal`/`dangerous`/absent **and** handler does something sensitive |
| `android:debuggable="true"` | Expected in a **debug** build | present in the **release**/shipped artifact |
| Cleartext "permitted" | NSC/`usesCleartextTraffic` allows it but the app makes **no** cleartext request | a real `http://` endpoint is actually used |
| MD5 / SHA-1 detected | Used for a checksum, cache key, ETag, non-security hash | used for signatures, password hashing, integrity of trusted data |
| "Hardcoded API key" | It's an OAuth **client_id**, a package/SHA-restricted public key, Firebase config, or a **cert pin / public key** | it's a server secret / private key granting access |
| CVE in a bundled library | The vulnerable code path is **not reachable** / lib is dead weight | the vulnerable API is actually invoked with attacker-influenced input |
| `setAllowFileAccess` "enabled" | Default on API ≤ 29; on API ≥ 30 default is `false` | explicitly set `true` with `file://` + JS/remote content |
| Missing pinning | Acceptable under **L1** | expected and absent under **L2/R**, or app handles high-value data |
| No obfuscation / root detection | Not required under L1/L2 | required and absent under the **R** profile |

When you dismiss a candidate, record it (and the reason) in the report's "candidates not promoted" appendix —
that's part of an honest deliverable.
