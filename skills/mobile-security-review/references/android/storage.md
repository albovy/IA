# Android — MASVS-STORAGE (static)

Static checks for sensitive data **at rest** and its **leakage** in an Android artifact (`.apk` / `.aab` / extracted APK). Fully automated, no device required.
Anchor each finding to the exact control in SKILL.md (read it); verify MASWE/MASTG IDs against the live guide.

> Every check below is a **candidate generator** — promote to a finding only after the anti-false-positive gate in SKILL.md (real evidence? reachable here? honest confidence?). Storage of **non-sensitive** data is never a finding — first decide what counts as sensitive in THIS app (credentials, tokens, PII, health/financial, keys, session). Pick the control number by **statement match**, not by group alone. IDs verified against the live catalog at time of writing; legacy narrative tests (low IDs) and atomic tests (0200+) coexist (MASTG mid-refactor, MASWE Beta) — re-verify per finding.
> Live URLs: `https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/<ID>/` · `https://mas.owasp.org/MASWE/MASVS-STORAGE/<ID>/`. Atomic tests live under `/tests-beta/` in the repo but resolve under `/tests/` on the site.

## Group controls (verbatim, MASVS v2.0.0)
- **MASVS-STORAGE-1** — The app securely stores sensitive data. *(SharedPreferences/DB/files/DataStore holding secrets unencrypted)*
- **MASVS-STORAGE-2** — The app prevents leakage of sensitive data. *(logs, backups/allowBackup, IPC, external/shared storage)*

The split is **confidentiality at rest (STORAGE-1)** vs **leakage off the intended store (STORAGE-2)**. Choose by statement: "stored unencrypted in a private place" → STORAGE-1; "escapes via logs/backup/shared storage/another app" → STORAGE-2.

---

## Checks

### Confidentiality at rest — STORAGE-1

- **Sensitive values in SharedPreferences (plain XML).** `getSharedPreferences(...)`/`edit().putString(...)`. `MODE_PRIVATE` is still **plaintext on disk** (`/data/data/<pkg>/shared_prefs/*.xml`) — only protects against other apps' UID, not root/backup/data-dir access. `MODE_WORLD_READABLE`/`MODE_WORLD_WRITEABLE` (deprecated) is worse. → MASVS-STORAGE-1 · MASWE-0006 (Sensitive Data Stored Unencrypted in Private Storage Locations) · static via the local-storage umbrella MASTG-TEST-0001 (Testing Local Storage for Sensitive Data); runtime sibling **MASTG-TEST-0287** (Runtime Storage of Unencrypted Data via the SharedPreferences API). No dedicated *static* SharedPreferences atomic test in the live catalog → cite the umbrella + descriptive name "(static SharedPreferences scan — ID to confirm)".
- **Jetpack DataStore (Preferences/Proto) — no built-in encryption.** Add to the storage inventory alongside SharedPreferences; presence does **not** imply protection. `DataStore`/`createDataStore`/`preferencesDataStore`/`*.preferences_pb`. → MASVS-STORAGE-1 · MASWE-0006 · **MASTG-TEST-0305** (Sensitive Data Stored Unencrypted via DataStore).
- **SQLite / Room DB unencrypted.** DBs at `/data/data/<pkg>/databases/*` holding sensitive data; check for **SQLCipher** if encryption is claimed (`net.sqlcipher`, `SupportFactory`, `PRAGMA key`). Room with no encryption layer = plaintext. → MASVS-STORAGE-1 · MASWE-0006 · **MASTG-TEST-0304 / MASTG-TEST-0306** (References to Sensitive Data Unencrypted via Android Room Database); umbrella MASTG-TEST-0001. Runtime sibling: **MASTG-TEST-0207** (Runtime Storage of Unencrypted Data in the App Sandbox).
- **Internal files written plaintext.** `getFilesDir`/`openFileOutput`/`File(...)` in the sandbox holding secrets, with no encrypt-before-write. Internal is sandboxed (mitigates app-to-app), but not root/backup → still STORAGE-1 for sensitive data. → MASVS-STORAGE-1 · MASWE-0006 · MASTG-TEST-0001 (umbrella); runtime **MASTG-TEST-0207**.
- **Weak / DIY "encryption" of stored data.** XOR, static-key obfuscation, Base64-as-"encryption", or a hardcoded `SecretKeySpec` protecting the at-rest store. The store counts as unencrypted. (The crypto defect itself anchors MASVS-CRYPTO — see `references/android/crypto.md`; the *exposed at-rest data* stays STORAGE-1.) → MASVS-STORAGE-1 · MASWE-0006 · MASTG-TEST-0001.
- **Secure storage claimed — verify it actually covers the sensitive data.** `EncryptedSharedPreferences` / `EncryptedFile` (Jetpack Security `androidx.security:security-crypto`) and Android **Keystore**-backed keys are the expected controls; note their presence as *mitigations*, but confirm the sensitive item is routed through them (not just that the lib is declared). **Caveat:** Jetpack Security `EncryptedSharedPreferences`/`EncryptedFile` are **deprecated (Apr 2025)** — presence is not an automatic pass; note the deprecation and check what replaced it (or whether unmaintained crypto is shipping). → MASVS-STORAGE-1 · MASWE-0006 · MASTG-TEST-0001; deprecation status "(verify against live guidance)".
- **Profile note.** Under **L1**, sensitive data may remain unencrypted inside the app's internal sandbox; under **L2** encryption is mandatory (Android Keystore with proper key management). Severity scales with profile + data sensitivity.

### Leakage off the intended store — STORAGE-2

- **Sensitive data in logs.** Sensitive values passed to `Log.d/v/i/e/w`, `System.out`/`System.err.println`, `printStackTrace()`, Timber, or `Slf4j`. logcat is a shared buffer readable by privileged/sibling components; release builds should strip verbose/debug logging. → MASVS-STORAGE-2 · MASWE-0001 (Insertion of Sensitive Data into Logs) · **MASTG-TEST-0003** (legacy, Testing Logs for Sensitive Data) and atomic **MASTG-TEST-0231** (References to Logging APIs); runtime sibling **MASTG-TEST-0203** (Runtime Use of Logging APIs).
- **`allowBackup="true"` (backup data unencrypted).** Historical default; may let `adb backup` / cloud backup exfiltrate app data on some devices/OS versions. Severity depends on what STORAGE-1 actually writes. → MASVS-STORAGE-2 · MASWE-0003 (Backup Unencrypted) · no clean atomic test covers the manifest flag itself → cite the control + descriptive name **"(allowBackup manifest flag — ID to confirm)"** (do NOT borrow an unrelated test ID). Confirm in the pre-pass manifest read.
- **Sensitive data not excluded from backup (Android 12+ rules).** Beyond `allowBackup`: check `android:fullBackupContent` (`<full-backup-content>` rules) and `android:dataExtractionRules` (API 31+, `cloud-backup` + `device-transfer` blocks). Sensitive files/prefs/DBs not placed in `<exclude>` ride backups/device transfer off-device. → MASVS-STORAGE-2 · MASWE-0004 (Sensitive Data Not Excluded From Backup) · **MASTG-TEST-0262** (References to Backup Configurations Not Excluding Sensitive Data) + **MASTG-TEST-0216** (Sensitive Data Not Excluded From Backup).
- **External / shared storage.** `getExternalFilesDir`, `getExternalStoragePublicDirectory`, `Environment.getExternalStorage*`, `MediaStore`, legacy `WRITE_EXTERNAL_STORAGE`/`READ_EXTERNAL_STORAGE`, `requestLegacyExternalStorage`. World-readable on older models / shared across apps → sensitive data there is exposed (no user interaction needed). → MASVS-STORAGE-2 · MASWE-0007 (Sensitive Data Stored Unencrypted in Shared Storage Requiring No User Interaction) · **MASTG-TEST-0202** (References to APIs and Permissions for Accessing External Storage) + **MASTG-TEST-0200** (Files Written to External Storage); runtime sibling **MASTG-TEST-0201** (Runtime Use of APIs to Access External Storage). Legacy umbrella MASTG-TEST-0001.
- **Insufficient access restrictions in *internal* locations.** Files/prefs/DBs created world-readable/writeable (`MODE_WORLD_READABLE/WRITEABLE`), or a file/dir made group/other-readable, lets sibling apps read sandbox data. → MASVS-STORAGE-2 · MASWE-0002 (Sensitive Data Stored With Insufficient Access Restrictions in Internal Locations) · MASTG-TEST-0001 (umbrella) → atomic "(internal access-restriction scan — ID to confirm)".
- **Keys / secrets bundled in `res/` or `assets/`.** Keystores (`.bks`/`.jks`/`.p12`), `.pem`/`.key`, config files with secrets, embedded credentials in `strings.xml`. (Whether it's a *real* secret — server key/private key vs OAuth client_id / public cert pin — gates the finding; access tokens/API keys anchor MASVS-AUTH-1, crypto key material anchors MASVS-CRYPTO-2. The unauthenticated *backend* exposed by a Firebase/cloud config anchors MASVS-STORAGE-2.) → MASVS-STORAGE-2 (data-at-rest-in-package leakage) / re-anchor per what the value unlocks · MASWE: verify per case · static discovery via MASTG-TECH-0117 (Obtaining Information from the AndroidManifest) + resource/string scan.
- **Exposure paths into the above.** Cross-reference: does `allowBackup`/backup rules (this section), an **exported `ContentProvider`** or **`FileProvider`/grant-URI** (→ `references/android/platform.md`, MASVS-PLATFORM-1), or world-readable mode expose any STORAGE-1 data off-device or to another app? The leak path, not just the at-rest write, is what makes it STORAGE-2.

### Tooling note
Drive these with: decoded `AndroidManifest.xml` (apktool/androguard) for backup attributes; **jadx** to read storage call sites and trace what data reaches them; **semgrep/mobsfscan** mobile packs over decompiled Java/Kotlin as candidate generators (every hit is a candidate — confirm in code). Cross-reference the SHA-256-pinned artifact recorded in triage. See the shared tooling/methodology reference for the automated layer.

---

## Classic false positives (STORAGE)
Consult before promoting a candidate. Each below is **usually NOT a finding** absent extra evidence:

| Candidate | Why it's usually a false positive | When it *is* real |
|---|---|---|
| Data in SharedPreferences / SQLite / DataStore | The stored values are **non-sensitive** (UI prefs, feature flags, cache, non-PII state) | the values are credentials/tokens/PII/keys/session and stored unencrypted |
| `MODE_PRIVATE` "plaintext" flagged | `MODE_PRIVATE` is the correct sandbox mode; plaintext-in-sandbox is acceptable for **non-sensitive** data under L1 | sensitive data, or under **L2** where encryption is mandatory |
| `EncryptedSharedPreferences`/`EncryptedFile` present | A mitigation, not a defect — secure storage is in use | it's **declared but not used** for the sensitive item, or relied on as a pass despite the Apr-2025 deprecation with no migration |
| `android:allowBackup="true"` | Default historically; only matters if STORAGE-1 writes something sensitive **and** it isn't excluded | sensitive data is written and not in `<exclude>`/`dataExtractionRules`, and backup is reachable |
| External-storage API used | Writes only **non-sensitive / already-public** media or user-chosen exports | sensitive/private data written to shared/external storage with no encryption |
| MD5/XOR/Base64 "encryption" of stored data | If the data is non-sensitive, the weak transform is moot | sensitive data "protected" by reversible/keyless transform → treat store as plaintext |
| Hardcoded value in `res`/`assets` | It's an OAuth **client_id**, a package/SHA-restricted public key, Firebase config, or a **cert pin / public key** | it's a server secret / private key / symmetric key granting access (re-anchor: API key→AUTH-1, crypto key→CRYPTO-2) |

When you dismiss a candidate, record it (and the reason) in the report's "candidates not promoted" appendix — that transparency is part of an honest deliverable.
