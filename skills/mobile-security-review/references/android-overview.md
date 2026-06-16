# Android — Static Analysis: overview, tools & pre-pass

Read this **first** for an `.apk` / `.aab` / extracted APK. It covers tooling, the manifest/build pre-pass, and
**which per-group file to open next**. Everything is a **candidate generator** — promote to a finding only after
the anti-false-positive gate in `SKILL.md`. Anchor each finding to the exact MASVS control (control list in
`SKILL.md`, don't guess the sub-number) and **verify MASWE/MASTG IDs against the live guide** (catalogs are
mid-refactor: MASWE Beta; MASTG splitting into atomic tests).

## 0. Fingerprint the framework FIRST
Before native decompilation, determine whether this is a **native** (Java/Kotlin) app or a **cross-platform**
one (React Native, Flutter, Cordova/Ionic, Unity, Xamarin, KMP). If cross-platform, the real logic + secrets
are **not** in the DEX flow below → go to `references/cross-platform-static.md` first, then return here for the
manifest/platform checks. APKiD detects the framework (and packers/obfuscators) fast.

## Tools & unpacking

| Tool | Use |
|---|---|
| **aapt2** | `aapt2 dump badging app.apk` → package, version, min/target SDK, permissions, launchable activities. |
| **apktool** | `apktool d app.apk -o out/` → decodes resources + disassembles DEX to **smali**; decodes the binary `AndroidManifest.xml` and unpacks `res/`, `assets/`, `res/xml/*`. |
| **jadx** | `jadx -d out_src/ app.apk` → decompiles DEX to readable **Java**. Best for logic, secrets, tracing handlers. |
| **apksigner** | `apksigner verify --print-certs app.apk` → signature schemes (v1/v2/v3), signer cert, debug-cert detection. |
| **APKiD** | Framework + packer/obfuscator/anti-analysis detection — run early (drives §0). |
| **MobSF / mobsfscan / semgrep** | Automated static triage — **every hit is a candidate**; confirm in decompiled code. See `references/static-tooling-and-methodology.md`. |
| **androguard** *(pure-Python)* | JVM-less alternative: parses binary manifest, components, permissions, signing, and DEX; can decompile. Best with no JVM/SDK (CI, restricted hosts). |

`.aab`: a publishing bundle, not directly installable. Generate the universal APK
(`bundletool build-apks --mode=universal`) and analyze that; record which APK you derived.

**No JVM? Use androguard.** An APK is a ZIP — `unzip`/`hashlib` get the file list + SHA-256; androguard reads
the *binary* manifest, signing, and DEX that plain unzip can't:
```python
import hashlib
from androguard.core.apk import APK
print(hashlib.sha256(open("app.apk","rb").read()).hexdigest())   # fingerprint for the report
a = APK("app.apk")
print(a.get_package(), a.get_androidversion_name(), a.get_min_sdk_version(), a.get_target_sdk_version())
print("debuggable:", a.get_attribute_value("application","debuggable"))
print("allowBackup:", a.get_attribute_value("application","allowBackup"))
print("netSecConfig:", a.get_attribute_value("application","networkSecurityConfig"))
for tag in ("activity","activity-alias","service","receiver","provider"):
    for item in a.find_tags(tag):
        print(tag, item.get(a._ns("name")),
              "exported=", a.get_value_from_tag(item,"exported"),
              "perm=", a.get_value_from_tag(item,"permission"))
a.get_certificates()   # signer cert(s); detect debug cert (CN=Android Debug)
```
For large APKs prefer `APK(...)` for the manifest (fast) + **targeted** decompilation of suspect classes over
full-app cross-referencing.

## Pre-pass — manifest & build
Read the decoded `AndroidManifest.xml` + Gradle/build hints first; build the **list of exported components**
here (later groups reuse it). (Technique: `MASTG-TECH-0117` Obtaining Information from the AndroidManifest.)

- **`android:debuggable="true"`** on a release build → serious (JDWP attach). Expected in a *debug* build → not
  a finding. Confirm build type. Anchor `MASVS-RESILIENCE-4` (`MASWE-0067`), not CODE; no clean atomic test → cite control + "ID to confirm".
- **`android:allowBackup="true"`** → possible `adb backup`/cloud exfiltration. Anchor `MASVS-STORAGE-2` (`MASWE-0003`); also check `fullBackupContent` / `dataExtractionRules`. → `android/storage.md`.
- **`android:usesCleartextTraffic`** + **`android:networkSecurityConfig`** → analyze in `android/network.md` (NSC is authoritative on modern targets; the attribute is deprecated for targetSdk ≥ 28 (Android 9; cleartext off by default from there)).
- **`minSdkVersion` / `targetSdkVersion`** — low values keep weak old-OS defaults / opt out of new hardening. Anchor `MASVS-CODE-1`.
- **Exported components** — every `<activity>`/`<service>`/`<receiver>`/`<provider>` reachable by other apps
  (`exported="true"`, or pre-31 implicit via `<intent-filter>`); record each one's `permission`/`protectionLevel`. Drives `android/platform.md`.
- **Confirm RELEASE build** — debug cert (CN=Android Debug), `debuggable`, test-only flag, `BuildConfig.DEBUG` leftovers.

## Router — open the group file for what you're checking
| Checking… | File |
|---|---|
| Storage at rest / leakage / backups | `references/android/storage.md` |
| Cryptography / key management | `references/android/crypto.md` |
| Auth / tokens / biometrics (client side) | `references/android/auth.md` |
| Network / TLS / pinning / cleartext | `references/android/network.md` |
| Exported components / IPC / WebView / deep links / UI exposure | `references/android/platform.md` |
| Dependencies+CVEs / injection / deserialization / native `.so` | `references/android/code.md` |
| Anti-RE / root / tamper / obfuscation (**R profile only**) | `references/android/resilience.md` |
| Permissions / trackers / identifiers / data sharing | `references/android/privacy.md` |
| Cross-platform app (RN/Flutter/Cordova/Unity/Xamarin) | `references/cross-platform-static.md` |
| Tooling, SBOM/SCA, reachability, secrets, Firebase | `references/static-tooling-and-methodology.md` |

For a **full autonomous review**, walk all applicable group files (skip N/A groups, e.g. RESILIENCE outside R).
For a **targeted assist**, open just the one relevant file.
