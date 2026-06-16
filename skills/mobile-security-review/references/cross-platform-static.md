# Cross-platform / hybrid frameworks — MASVS-ALL (static)

Scope: **fingerprint the framework FIRST, then route to the layer where the logic, secrets and security controls actually live.** This file is consulted immediately after triage and **before** native (jadx / class-dump / Ghidra) decompilation — a thin Java/Kotlin or Mach-O wrapper around a JS bundle / Dart snapshot / .NET assemblies / IL2CPP metadata is the norm for these apps, and analysing only the native shell produces false negatives ("little code, no secrets") on every downstream MASVS group. Covers detection + static analysis for React Native, Flutter, Cordova/Ionic/Capacitor, Xamarin/.NET MAUI, Unity, and a short Kotlin Multiplatform note. Android (`.apk`/`.aab`) and iOS (`.ipa`/`.app`) artifacts both.

Anchor each finding to the exact control in SKILL.md (read it); verify MASWE/MASTG IDs against the live guide.

## Group controls this file routes into (MASVS v2.0.0, verbatim)
Cross-platform findings do not get a new MASVS group — they anchor to the **same** controls as native, just discovered in a different layer. The ones this file most often routes to:
- **MASVS-STORAGE-1** — The app securely stores sensitive data. *(framework plaintext stores: AsyncStorage, shared_preferences, localStorage/WebSQL/IndexedDB)*
- **MASVS-STORAGE-2** — The app prevents leakage of sensitive data.
- **MASVS-CRYPTO-2** — The app performs key management according to industry best practices. *(crypto keys/IVs as literals in the JS bundle / Dart snapshot / DLLs)*
- **MASVS-AUTH-1** — The app uses secure authentication and authorization protocols and follows the relevant best practices. *(hardcoded API keys/tokens/credentials in the framework layer — MASWE-0005)*
- **MASVS-NETWORK-1** — The app secures all network traffic according to the current best practices. *(cleartext / disabled validation re-derived from the framework's own HTTP stack, not the NSC/ATS)*
- **MASVS-NETWORK-2** — The app performs identity pinning for all remote endpoints under the developer's control.
- **MASVS-PLATFORM-1** — The app uses IPC mechanisms securely. *(deep-link / platform-channel entry into the framework handler)*
- **MASVS-PLATFORM-2** — The app uses WebViews securely. *(for Cordova/Ionic/Capacitor the **whole app** is a WebView)*
- **MASVS-CODE-3** — The app only uses software components without known vulnerabilities. *(JS/Dart/.NET dependency trees — where most cross-platform CVEs live)*
- **MASVS-RESILIENCE-3** — The app implements anti-static analysis mechanisms. *(obfuscation must be assessed on the **framework artifact**, not the native DEX/Mach-O)*

> **The cardinal rule:** a conclusion drawn against the wrong layer is invalid. R8-obfuscated DEX over a plaintext Hermes bundle is not obfuscated. A clean NSC/ATS says nothing about Flutter traffic. "No hardcoded secrets in smali" is meaningless if the keys are in `index.android.bundle` or `libapp.so`. Detect the framework, then re-run STORAGE / CRYPTO / NETWORK / CODE-3 / RESILIENCE against the layer named below.

---

## Step 0 — Fingerprint the framework (run before any group)

Unzip the package (`.apk`/`.aab` is a ZIP; `.ipa` is a ZIP whose payload is `Payload/<App>.app`) and look for these markers. Run **APKiD** (`MASTG-TOOL-0009`) over the APK in parallel — it fingerprints compilers, packers, obfuscators and anti-debug, and frequently flags the framework's compiler (Hermes, IL2CPP, Mono/Xamarin) directly. Technique for unpacking/exploring: **`MASTG-TECH-0007`** (Exploring the App Package, Android).

| Framework | Android markers | iOS markers (`.app` bundle) |
|---|---|---|
| **React Native** | `assets/index.android.bundle` (JS) **or** a Hermes bytecode bundle (magic `0xC61FBC03`, `.hbc`, often still named `index.android.bundle`); `libhermes.so`/`libhermes_executor.so`; `libjsc.so`; `com.facebook.react` / `com.facebook.hermes` classes | `main.jsbundle` (or Hermes `.hbc`); `hermes.framework`/`libhermes`; `RCTBridge`/`React` framework refs |
| **Flutter** | `lib/<abi>/libflutter.so` **and** `lib/<abi>/libapp.so`; `assets/flutter_assets/` with `kernel_blob.bin` (debug) or AOT `isolate_snapshot_data`/`vm_snapshot_data` | `Frameworks/Flutter.framework`; `Frameworks/App.framework/App` (the AOT Dart snapshot); `flutter_assets/` |
| **Cordova / Ionic / Capacitor** | `assets/www/` (the real app), `assets/www/cordova.js` / `cordova_plugins.js`, `res/xml/config.xml`; Capacitor: `capacitor.config.json`/`.plist`, `assets/public/`, `assets/capacitor.plugins.json` | `www/` inside the `.app`, `config.xml`, `cordova.js`; Capacitor `capacitor.config.json` |
| **Xamarin / .NET MAUI** | `assemblies/*.dll` (or compressed `assemblies.blob`/`libassemblies.blob` with `XALZ` LZ4 magic on each entry); `lib/<abi>/libmonodroid.so`, `libmonosgen-*.so`; MAUI adds `libxamarin-app.so` | `<App>.app/*.dll` or `Data/Managed/*.dll`; `libmonosgen`/`libxamarin`; `.aotdata` files |
| **Unity** | IL2CPP: `assets/bin/Data/Managed/Metadata/global-metadata.dat` **and** `lib/<abi>/libil2cpp.so`; Mono: `assets/bin/Data/Managed/*.dll` + `libmono*.so`; `libunity.so` either way | `Data/il2cpp_metadata/global-metadata.dat` + `UnityFramework`/`libil2cpp`; or `Data/Managed/*.dll` (Mono) |
| **Kotlin Multiplatform** | a shared module as Kotlin/Native `.so` (`kfun:`/`kclass:` symbols in `rabin2 -z`/`nm`) **or** as ordinary JVM bytecode in `classes*.dex` (jadx works) | shared `.framework` (Kotlin/Native, `kfun:` symbols) embedded in `Frameworks/` |

If none match, treat the app as native and route to `masvs-android-static.md` / `masvs-ios-static.md`. If two match (e.g. a Cordova plugin inside a mostly-native app), analyse both layers. Record the detected framework + the marker that proved it in the report — it justifies the analysis path you took.

- *(detection itself has no dedicated atomic test — cite the relevant **MASVS** control + "framework fingerprinting (ID to confirm)"; the offensive technique is `MASTG-TECH-0007` for the package and `MASTG-TOOL-0009` (APKiD) for the compiler/packer fingerprint.)*

---

## React Native

Logic and secrets live in the **JavaScript bundle**, not in smali/Mach-O. The native side is a thin host plus any custom native modules (the "bridge").

- **Extract & analyse the JS bundle.** If it's plain JS (`assets/index.android.bundle` / `main.jsbundle`), beautify it (`js-beautify`) and read it directly. If it's **Hermes bytecode** (magic `0xC61FBC03`), **decompile it with hermes-dec before grepping** — raw `strings` on a `.hbc` recovers string literals but loses control flow, so logic-bearing findings (which branch checks the receipt, where the token is built) are missed without decompilation. → routing step; tool **`MASTG-TOOL-0104`** (hermes-dec), technique `MASTG-TECH-0018` (Disassembling Native Code) for `libhermes`-adjacent native modules.
- **Secrets in the bundle.** Provider-format regex + entropy over the bundle and `assets/`: API keys/tokens/credentials → **MASVS-AUTH-1** / **MASWE-0005** / hardcoded-secret review (ID to confirm). Crypto key/IV literals re-anchor → **MASVS-CRYPTO-2** / **MASWE-0014**.
- **Plaintext storage.** `AsyncStorage` writes to an **unencrypted** SQLite DB / file in the app's private dir; flag any sensitive value stored via `AsyncStorage.setItem`. Secure alternatives are `react-native-keychain` and `react-native-encrypted-storage` (EncryptedStorage) — their presence is the pass condition. → **MASVS-STORAGE-1** / **MASWE-0006** / `MASTG-TEST-0001` (Testing Local Storage for Sensitive Data — umbrella).
- **Network (re-derive, do not trust the NSC).** RN uses the platform OkHttp stack on Android (so the NSC **does** apply there) plus the JS `fetch`/`XMLHttpRequest` layer. Check the bundle for `http://` endpoints, and for pinning look for `react-native-ssl-pinning` / `react-native-cert-pinner` / TrustKit usage in the bundle **and** any custom native OkHttp module that installs a trust-all `TrustManager`. Cleartext/disabled-validation → **MASVS-NETWORK-1** / **MASWE-0050** (cleartext) or **MASWE-0052** (cert validation); missing/weak pinning → **MASVS-NETWORK-2** / **MASWE-0047** / `MASTG-TEST-0242` (Android, static).
- **Native bridge = an attack surface like a WebView bridge.** Inspect every `@ReactMethod` (Android) / `RCT_EXPORT_METHOD` (iOS) exposed to JS: any that does privileged work (file access, exec, crypto, returns secrets) driven by untrusted JS is a confused-deputy / RCE primitive. → **MASVS-PLATFORM-2** / **MASWE-0068** (JavaScript Bridges in WebViews — closest weakness) / `MASTG-TEST-0033` (Java Objects Exposed Through WebViews; atomic successor ID to confirm).
- **Deep-link entry into JS.** Trace inbound URLs from the native intent-filter / URL-scheme handler into RN `Linking` (`getInitialURL`/`addEventListener('url')`) where validation actually happens (or doesn't) — open-redirect / OAuth redirect-URI capture / nested navigation. → **MASVS-PLATFORM-1** / **MASWE-0058** (Insecure Deep Links) / Android `MASTG-TEST-0028` (deep-link handling — legacy), `MASTG-KNOW-0019` (Deep Links).
- **RESILIENCE (R only).** A **plaintext JS bundle or an un-decompiled-but-readable Hermes bundle is effectively unobfuscated**, regardless of R8 on the DEX. Check for Hermes (raises the bar) + a JS minifier/obfuscator (`metro` minify, `react-native-obfuscating-transformer`, jscrambler). → **MASVS-RESILIENCE-3** / **MASWE-0089** (Code Obfuscation Not Implemented — draft; cite control + "obfuscation on framework artifact (ID to confirm)").
- **CODE-3 (SBOM).** The JS dependency tree (`package.json` + `yarn.lock`/`package-lock.json`, often shipped or reconstructable from the bundle's module map) is where the CVEs are. → **MASVS-CODE-3** / **MASWE-0076** (see `static-tooling-and-methodology.md` for the SBOM/CVE pass).

## Flutter

Dart business logic is **AOT-compiled into a custom snapshot inside `libapp.so`** (Android) / `App.framework/App` (iOS) with no standard symbols — `strings`/jadx/Ghidra see almost nothing useful by default.

- **Recover the Dart code.** Use **blutter** (`MASTG-TOOL-0116`) to parse `libapp.so` statically (no device needed) and reconstruct classes/methods, or **reFlutter** (`MASTG-TOOL-0100`) which patches the engine for instrumentation. Overall technique: **`MASTG-TECH-0156`** (Reverse Engineering Flutter Applications). Snapshot version must match the engine; mismatches reduce recovery — note partial recovery as a limitation rather than concluding "no findings".
- **Network — the Flutter caveat that breaks every NSC/ATS conclusion.** Flutter **ships its own BoringSSL and ignores the Android Network Security Config, iOS ATS, and the system HTTP proxy.** Therefore: (a) NSC/ATS analysis is **invalid** for Flutter traffic — do not pass or fail Flutter network behaviour on it; (b) cleartext, validation and pinning all live in **Dart**. In the recovered Dart, look for `HttpClient.badCertificateCallback` returning `true` (validation disabled → full MITM), custom `SecurityContext`, and pinning packages (`http_certificate_pinning`, `ssl_pinning_plugin`, Dio + `badCertificateCallback`). Disabled validation → **MASVS-NETWORK-1** / **MASWE-0052**; cleartext (`http://` via `HttpClient`/`dart:io`) → **MASWE-0050**; missing pinning → **MASVS-NETWORK-2** / **MASWE-0047**. *(This is also why the dynamic side needs `reFlutter`/Frame-hooking rather than a system proxy + CA — note it for the dynamic phase.)*
- **Secrets.** Hunt recovered Dart strings + `assets/flutter_assets/` for API keys/tokens (→ **MASVS-AUTH-1** / **MASWE-0005**) and crypto key/IV literals (→ **MASVS-CRYPTO-2** / **MASWE-0014**).
- **Plaintext storage.** `shared_preferences` is **unencrypted** (XML on Android, plist on iOS) — flag sensitive values stored there; the secure alternative is `flutter_secure_storage` (Keystore/Keychain-backed). → **MASVS-STORAGE-1** / **MASWE-0006** / `MASTG-TEST-0001` (umbrella).
- **Platform-channel entry.** Inbound deep links arrive via plugins (`uni_links`, `app_links`, `go_router` deep-link config) and reach Dart over a `MethodChannel`/`EventChannel`; validation happens (or not) in the Dart handler. → **MASVS-PLATFORM-1** / **MASWE-0058**.
- **RESILIENCE (R only).** An AOT `libapp.so` is *not* obfuscated unless built with `--obfuscate --split-debug-info`; blutter recovering clean class/method names is the evidence it was not. → **MASVS-RESILIENCE-3** / **MASWE-0089** (draft; cite control + descriptive name).
- **CODE-3 (SBOM).** `pubspec.lock` (pinned pub.dev versions) is the dependency manifest. → **MASVS-CODE-3** / **MASWE-0076**.

## Cordova / Ionic / Capacitor

The entire app is HTML/CSS/JS in **`assets/www/`** (Capacitor: `assets/public/`) rendered in a system WebView. **MASVS-PLATFORM-2 WebView analysis applies to the whole app**, and all logic/secrets sit in plain JS on disk.

- **`config.xml` allowlist (the central control).** Read `res/xml/config.xml`:
  - `<access origin="*">` / `<allow-navigation href="*">` — the WebView may navigate to / load **any** origin → attacker content runs in the app's privileged web context. Wildcards or overly broad hosts are the finding.
  - `<allow-intent href="*">` — controls which external URLs the app may launch (intent egress).
  - Absence of a Content-Security-Policy `<meta http-equiv="Content-Security-Policy">` in the HTML → no defence-in-depth against injected script.
  → **MASVS-PLATFORM-2** / **MASWE-0069** (WebViews Allows Access to Local Resources — draft) and navigation/redirect → **MASVS-PLATFORM-1** / **MASWE-0058**. WebView analysis tests: `MASTG-TEST-0033` (exposed objects), local/file access tests (atomic ids to confirm).
- **Plugin allowlist & remote loads.** Enumerate installed plugins (`cordova_plugins.js`, `assets/www/cordova_plugins.js`, Capacitor `capacitor.plugins.json`); plugins expose native capability to JS — same bridge confused-deputy concern as RN. `InAppBrowser` / `cordova-plugin-inappbrowser` opening **remote** URLs with `_blank`/JS injection is a common exposure. → **MASVS-PLATFORM-2** / **MASWE-0068**.
- **Secrets in JS.** API keys/tokens/credentials are in plain `www/` JS → **MASVS-AUTH-1** / **MASWE-0005**; crypto literals → **MASVS-CRYPTO-2** / **MASWE-0014**.
- **Plaintext WebView storage.** `localStorage` / `WebSQL` / `IndexedDB` / cookies are **unencrypted** in the WebView data dir — flag sensitive values stored there. → **MASVS-STORAGE-1** / **MASWE-0006** / `MASTG-TEST-0001`.
- **Network.** The WebView HTTP stack honours the NSC for `https` fetches but **does not honour NSC `<pin-set>`** — a Cordova `onReceivedSslError → handler.proceed()` (in a custom WebViewClient or a trust-all plugin) is full MITM-in-WebView **independent of the NSC**, and frequently ships in release. → **MASVS-NETWORK-1** / **MASWE-0052** / `MASTG-TEST-0284` (Incorrect SSL Error Handling in WebViews — see `android/network.md`). Plaintext `http://` endpoints in JS → **MASWE-0050**.
- **RESILIENCE (R only).** Plaintext `www/` JS is unobfuscated unless a JS obfuscator was applied. → **MASVS-RESILIENCE-3** / **MASWE-0089** (draft).

## Xamarin / .NET MAUI

C# logic compiles to **.NET assemblies (`*.dll`)** shipped in `assemblies/` (Android) or the `.app`/`Data/Managed` (iOS) — invisible to jadx. A trust-all TLS callback here is one of the most common, highest-impact, and easiest-to-miss bugs in this stack because it never appears without decompiling.

- **Extract & decompile.** If the DLLs are bundled into a compressed `assemblies.blob`/`libassemblies.blob` (each entry prefixed with the `XALZ` LZ4 magic), decompress them first (e.g. `xamarin-decompress` — descriptive tool, no MASTG-TOOL id), then decompile with **ILSpy** / **dnSpy** / **dotPeek** to C#. Technique: `MASTG-TECH-0018` / `MASTG-TECH-0024` (Disassembling / Reviewing native code — closest catalog technique; cite control + ".NET assembly decompilation" where no exact id exists). *(`MASTG-TECH-0125` "Intercepting Xamarin Traffic" exists but is a deprecated dynamic technique — do not cite it for static.)*
- **Trust-all certificate validation (signature bug to grep for).** In the decompiled C#/IL: `ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => true;` or an `HttpClientHandler.ServerCertificateCustomValidationCallback` / `WebRequestHandler` returning `true` unconditionally → all certificates accepted, full MITM. → **MASVS-NETWORK-1** / **MASWE-0052** / `MASTG-TEST-0282` (Unsafe Custom Trust Evaluation — analogous; cite control + descriptive name for the .NET variant).
- **Secrets, endpoints, weak crypto in the DLLs.** Grep decompiled IL/C# for API keys/credentials (→ **MASVS-AUTH-1** / **MASWE-0005**), `http://` endpoints (→ **MASWE-0050**), and weak crypto (`DESCryptoServiceProvider`, `MD5`/`SHA1` for security, ECB `CipherMode.ECB`, hardcoded `Key`/`IV` byte arrays → **MASVS-CRYPTO-1**/`-2` / **MASWE-0014**).
- **CODE-3 (SBOM).** NuGet package versions (assembly versions / `*.deps.json`) are the dependency inventory. → **MASVS-CODE-3** / **MASWE-0076**.
- **RESILIENCE (R only).** Decompilable IL with intact names = unobfuscated; check for a .NET obfuscator (Dotfuscator, Babel, Obfuscar — renamed types/`<Module>` markers). → **MASVS-RESILIENCE-3** / **MASWE-0089** (draft).

## Unity

Game/app logic is C# compiled either to **IL2CPP** (native `libil2cpp.so` + `global-metadata.dat`) or, less commonly, **Mono** (`Managed/*.dll`).

- **IL2CPP recovery.** `global-metadata.dat` holds the method/type metadata that re-symbolises the otherwise-stripped `libil2cpp.so`. Recover with **Il2CppDumper** or **Il2CppInspector** (feed both the binary and `global-metadata.dat`), then load the produced symbols into **Ghidra**/IDA. Descriptive tools (no MASTG-TOOL id); technique `MASTG-TECH-0018` (Disassembling Native Code) → `MASTG-TECH-0024` (Reviewing Disassembled Native Code).
- **Mono recovery.** If `Managed/*.dll` is present (no IL2CPP), decompile directly with ILSpy/dnSpy as for Xamarin.
- **What to hunt.** Client-side **IAP / license / receipt validation** done locally (trivially patchable → unlock/piracy), embedded API keys / signing keys / shared secrets in metadata or C# (→ **MASVS-AUTH-1** / **MASWE-0005**; crypto keys → **MASVS-CRYPTO-2** / **MASWE-0014**), and `http://` endpoints (→ **MASWE-0050**). Local-only trust decisions are **MASVS-CODE-4** input-validation / integrity concerns (`MASWE-0082` local-storage integrity) and, under R, **MASVS-RESILIENCE-2** anti-tamper.
- **RESILIENCE (R only).** A **readable `global-metadata.dat`** (not encrypted/obfuscated by an anti-cheat such as IL2CPP metadata encryption) means full symbol recovery → effectively unobfuscated. Note whether the metadata header is intact (Il2CppDumper succeeds) vs encrypted. → **MASVS-RESILIENCE-3** / **MASWE-0089** (draft).

## Kotlin Multiplatform (short note)

KMP ships shared business logic as **either** a Kotlin/Native `.so`/`.framework` (analyse as native — `rabin2 -z`/`nm` shows `kfun:`/`kclass:` symbols, route to native disasm `MASTG-TECH-0018`) **or** ordinary JVM bytecode in `classes*.dex` (jadx works as for any Android app). **Confirm which target the shared module is before concluding the logic "isn't there"** — opening jadx, seeing a thin UI layer, and missing a Kotlin/Native `.so` is the classic KMP false negative. No KMP-specific workflow beyond that today; route each group to the native or DEX reference as appropriate. Anchors are the same native controls (AUTH-1/MASWE-0005 for secrets, etc.).

---

## Cross-cutting routing summary
- **STORAGE:** RN AsyncStorage / Flutter shared_preferences / Cordova localStorage·WebSQL·IndexedDB are all **plaintext** → **MASVS-STORAGE-1 / MASWE-0006**; secure homes are react-native-keychain·EncryptedStorage / flutter_secure_storage / Keystore-Keychain. (Shared/external-storage writes shift to **MASWE-0007**.)
- **NETWORK:** re-derive from the framework's own stack — **Flutter ignores NSC/ATS+proxy (Dart only)**; RN = OkHttp + JS fetch + JS/native pinning module; Cordova = WebView + `onReceivedSslError`; Xamarin = `ServerCertificateValidationCallback`. → MASVS-NETWORK-1 (MASWE-0050/-0052), NETWORK-2 (MASWE-0047).
- **CODE-3:** read the framework lockfiles — `package.json`/`yarn.lock`, `pubspec.lock`, plugin lists, NuGet/assembly versions — most cross-platform CVEs are here, not in native `.so`s. → MASWE-0076 (see `static-tooling-and-methodology.md`).
- **RESILIENCE (R):** assess obfuscation on the **framework artifact** (plaintext JS bundle, un-stripped/decompilable Hermes, decompilable DLLs, readable `global-metadata.dat`, un-obfuscated `libapp.so`) — R8/ProGuard on the DEX is **not** sufficient. → MASWE-0089.
- **PLATFORM (deep links):** trace the inbound URL/IPC from the native shim INTO the framework handler (RN `Linking`, Flutter platform channels/`uni_links`, Cordova deeplink plugin) — validation lives there. → MASWE-0058.

## Classic false positives
Consult before promoting a candidate. Each below is **usually NOT a finding** absent extra evidence:

| Candidate | Why it's usually a false positive | When it *is* real |
|---|---|---|
| "No hardcoded secrets" after grepping smali / Mach-O only | The secrets are in the JS bundle / Dart snapshot / DLLs / IL2CPP metadata — you searched the wrong layer | re-run secret scanning on the framework artifact and a key/token is present |
| Clean NSC/ATS ⇒ "network is safe" on a **Flutter** app | Flutter ships its own BoringSSL and ignores NSC/ATS + proxy entirely | cleartext/disabled-validation/no-pinning re-derived from the recovered **Dart** code |
| R8/ProGuard-obfuscated DEX ⇒ "app is obfuscated" (R) | The logic isn't in the DEX; a plaintext JS bundle / readable `global-metadata.dat` / decompilable DLLs sit underneath | the framework artifact itself is plaintext/decompilable with intact names |
| `strings` on a Hermes `.hbc` / Flutter `libapp.so` shows "nothing interesting" | Hermes/AOT lose control flow to raw `strings`; you must decompile (hermes-dec) / recover (blutter) first | post-decompilation review reveals logic-bearing secrets/validation gaps |
| Firebase/Google `api_key` (`AIza…`) found in the bundle/config | A Firebase config `api_key` / SHA-restricted public key is **not** a server secret on its own | it unlocks an open Realtime DB/Firestore/Storage backend (probe the rules — see `static-tooling-and-methodology.md`) — that's **MASVS-STORAGE-2** |
| `AsyncStorage`/`shared_preferences`/`localStorage` usage flagged wholesale | Storing **non-sensitive** UI state/flags in a plaintext store is fine | a token/PII/credential/key is written to the plaintext store |
| Native module / Cordova plugin "exposed to JS" | The exposed method does nothing privileged | it performs file/exec/crypto/secret-returning work driven by untrusted JS |
| Bundled JS/Dart/NuGet dependency with a CVE | The vulnerable code path is not reachable in this build | the vulnerable API is invoked with attacker-influenced input (do the reachability pass) |
| KMP app "has no logic" in jadx | The shared module is a Kotlin/Native `.so`/`.framework`, not DEX | confirm the target; analyse the `.so`/`.framework` as native |

When you dismiss a candidate, record it (and the reason) in the report's "candidates not promoted" appendix — that transparency is part of an honest deliverable.
