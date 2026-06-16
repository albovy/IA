# Android — MASVS-CODE (static)

Scope: secure software supply chain and data processing for an Android artifact — platform currency, update enforcement, third-party dependencies with known CVEs, and validation/sanitization of all untrusted input (injection, unsafe deserialization, dynamic code loading, native-binary hardening) — analyzed statically from the manifest, build metadata, decompiled Java/Kotlin (jadx), smali, and native `.so` libraries (no device).

Anchor each finding to the exact control in SKILL.md (read it); verify MASWE/MASTG IDs against the live guide.

## Group controls (MASVS v2.0.0, verbatim)
- **MASVS-CODE-1** — The app requires an up-to-date platform version. *(low minSdk/targetSdk)*
- **MASVS-CODE-2** — The app has a mechanism for enforcing app updates.
- **MASVS-CODE-3** — The app only uses software components without known vulnerabilities. *(vulnerable libraries / reachable CVEs)*
- **MASVS-CODE-4** — The app validates and sanitizes all untrusted inputs. *(SQL/command injection, unsafe deserialization, unsafe handling of network data)*

> **Anchor note — this group is where you *look*, but several things anchor elsewhere.** MASVS-CODE is the natural place to hunt for secrets and reversing aids during code review, but by *statement* they anchor to other groups (let the MASWE choose the group, then the statement chooses the number):
> - Hardcoded **server API keys / access tokens / credentials** → **MASVS-AUTH-1** / **MASWE-0005** (API Keys Hardcoded in the App Package). *Not* MASVS-CODE.
> - Hardcoded **crypto keys / IVs / salts** → **MASVS-CRYPTO-2** / **MASWE-0014** (Cryptographic Keys Not Properly Protected at Rest; legacy -0013 merged into -0014).
> - The **`debuggable` flag** and **debug leftovers that aid reversing** → **MASVS-RESILIENCE** (RESILIENCE-4 for `debuggable`/anti-debug).
> - Sensitive data in **logs** → **MASVS-STORAGE-2**.
>
> True MASVS-CODE findings are only: outdated platform (CODE-1), update enforcement (CODE-2), known-vulnerable libs (CODE-3), and injection / unsafe-input handling / compiler hardening (CODE-4).

## Checks (each = static check + MASVS anchor + MASWE + MASTG id)

### Platform currency (MASVS-CODE-1)
- **Low `minSdkVersion`.** A low `minSdk` keeps the app installable on old Android with weaker defaults (cleartext allowed pre-28, implicit user-CA trust ≤ 23, looser file/backup defaults), inheriting OS-level weaknesses the newer platform fixed. Read it from the manifest/Gradle (recorded in the Pre-pass). → **MASVS-CODE-1** / **MASWE-0077** (Running on a recent Platform Version Not Ensured) / **MASTG-TEST-0245** (References to Platform Version APIs — static; flags `Build.VERSION.SDK_INT` runtime gating and the declared floor).
- **Low `targetSdkVersion`.** A low `targetSdk` opts the app out of newer platform hardening (scoped storage, restricted implicit intents, mutable-PendingIntent rules, foreground-service limits). → **MASVS-CODE-1** / **MASWE-0078** (Latest Platform Version Not Targeted) / **MASTG-TEST-0245** (static). *(SDK_INT runtime-check nuance: a half-line — confirm runtime checks back the declared floor, don't expand into a sub-taxonomy.)*

### Update enforcement (MASVS-CODE-2)
- **No forced-update / kill-switch mechanism.** For an app that must be able to push a security fix (handles money/PII, or under R), look for a server-driven minimum-version check + in-app forced upgrade (e.g. Play In-App Updates `AppUpdateManager` IMMEDIATE flow, or a custom "version too old → block" gate). Absence means a known-vulnerable client version stays in the field. Profile-dependent; usually Info at L1. → **MASVS-CODE-2** / **MASWE-0075** (Enforced Updating Not Implemented) / MASTG-TEST-0036 "Testing Enforced Updating" (legacy narrative test, MASTG v2 atomic successor to confirm — cite control + descriptive name).

### Third-party dependencies with known vulnerabilities (MASVS-CODE-3)
- **Enumerate bundled libraries + exact versions.** Identify components from smali package paths, `META-INF/*.version`, embedded `.properties`/`BuildConfig`, native `.so` names/versions. A library is only a finding if a **known-vulnerable version is present**. → **MASVS-CODE-3** / **MASWE-0076** (Dependencies with Known Vulnerabilities) / **MASTG-TEST-0272** (Identify Dependencies with Known Vulnerabilities in the Android Project — Gradle/project-level scan, technique **MASTG-TECH-0131** SCA at build time).
- **Generate a CycloneDX SBOM and diff against advisories.** Produce an SBOM (e.g. cdxgen, MASTG-TOOL-0134) for the APK/project, enumerate every component **+ version**, and diff against NVD / OSV / GitHub Advisories (dependency-check MASTG-TOOL-0131, dependency-track MASTG-TOOL-0132). Report the SBOM as a deliverable. → **MASVS-CODE-3** / **MASWE-0076** / **MASTG-TEST-0274** (Dependencies with Known Vulnerabilities in the App's SBOM — static; technique **MASTG-TECH-0130** SCA by creating an SBOM).
- **Reachability gate (operationalizes "reachable here?").** A CVE is a finding only if the **vulnerable code path is reachable** in this build — a CVE in a bundled-but-unused library is not. Confirm reachability with androguard `AnalyzeAPK` XREFs (`get_xref_from`/`get_xref_to`) or jadx "Find Usage", tracing from manifest entry points (exported components, `Application.onCreate`, deep-link handlers) to the vulnerable API. State the version **and** the reachability basis; record unreachable candidates in the dismissed-candidates appendix. → **MASVS-CODE-3** / **MASWE-0076** / reachability via **MASTG-TECH-0020** (Retrieving Cross References, Android). *(Legacy umbrella: MASTG-TEST-0042 "Checking for Weaknesses in Third Party Libraries" — superseded by the atomic 0272/0274.)*

### Untrusted-input handling — taxonomy by source (MASVS-CODE-4)
- **Name the taint source.** MASVS-CODE-4 covers unsafe handling of input from every channel; classify which source feeds the sink, because the source frames exploitability: network **MASWE-0079**, backups **MASWE-0080**, external interfaces **MASWE-0081**, local storage **MASWE-0082**, UI **MASWE-0083**, IPC **MASWE-0084**. At minimum trace **IPC extras / deep-link params** and **backup-restored data** as attacker-controlled sources, not just network responses. → **MASVS-CODE-4** / one of MASWE-0079–0084 by channel / **MASTG-TECH-0020** (Retrieving Cross References, Android) for the source→sink trace.
- **Unsafe handling of network data.** Untrusted server/peer responses parsed straight into sensitive sinks (object construction, SQL, file paths, reflection) without validation. → **MASVS-CODE-4** / **MASWE-0079** (Unsafe Handling of Data from the Network) / MASTG technique MASTG-TECH-0014 (no clean atomic test for the network-source case → cite control + descriptive name).

### Injection (MASVS-CODE-4)
- **SQL injection in ContentProviders / SQLite.** `query()`/`update()`/`delete()` or `SQLiteQueryBuilder.appendWhere()` building SQL by **string concatenation** from `selection`/`projection`/`sortOrder`/`Uri.getPathSegments()` instead of `selectionArgs` parameterization. **Anchor correction:** this is **MASVS-CODE-4** (untrusted-input handling), even though the exported provider that exposes it is enumerated under PLATFORM-1. → **MASVS-CODE-4** / **MASWE-0086** (SQL Injection) / **MASTG-TEST-0339** (SQL Injection in Content Providers — static). *(Legacy umbrella: MASTG-TEST-0025 "Testing for Injection Flaws".)*
- **Command injection / `Runtime.exec` / `ProcessBuilder`.** Shell or binary invocation built from externally-influenced input (Intent extras, deep-link params, network data). → **MASVS-CODE-4** / **MASWE-0087** (Insecure Parsing and Escaping) or MASWE by source / MASTG technique MASTG-TECH-0014 (no atomic command-injection test → cite control + descriptive name).
- **Insecure parsing / escaping.** XML/JSON/HTML parsers fed attacker data with unsafe settings (XXE-enabled parsers, format-string sinks, path building without canonicalization). → **MASVS-CODE-4** / **MASWE-0087** (Insecure Parsing and Escaping) / MASTG-TECH-0014 (atomic id to confirm).

### Unsafe object deserialization (MASVS-CODE-4)
- **Deserialization of untrusted data without class filtering.** `ObjectInputStream.readObject`, `readSerializable`, `getSerializableExtra`/`getParcelableExtra` from Intent/Bundle, or JSON/XML deserializers fed attacker-influenced bytes — *including data arriving via IPC extras, deep links, backups, or the network* → object injection. The atomic test specifically wants an **allow-list of permitted classes** (validate/restrict classes before reconstructing); flag the missing class filter, not merely the API call. Grep `readObject`/`readSerializable`/`getSerializableExtra` and trace the source. → **MASVS-CODE-4** / **MASWE-0088** (Insecure Object Deserialization) / **MASTG-TEST-0337** (References to Object Deserialization of Untrusted Data — static).

### Local-storage integrity (MASVS-CODE-4)
- **Trusting tamperable local values for auth/authz/feature-gating.** SharedPreferences / file / DB values that drive client decisions (`isPremium`, `isAdmin`, role, price, license) **without** a nearby HMAC/MAC/signature integrity check → trivially flipped on a rooted device, via `adb backup`/restore, or by writing the app data dir. This is treating local storage as a trusted input. → **MASVS-CODE-4** / **MASWE-0082** (Unsafe Handling of Data From Local Storage) / **MASTG-TEST-0338** (Integrity and Authenticity Validation of Local Storage Data — static).

### Unsafe dynamic code loading (MASVS-CODE-4)
- **Loading code from writable / external / remote locations.** `DexClassLoader`/`PathClassLoader`/`InMemoryDexClassLoader` over a path in external/writable storage or downloaded at runtime, `dlopen` of a writable path, or reflection-loaded downloaded code → an attacker who can write the source executes code in the app. Verify the source is read-only/app-internal. → **MASVS-CODE-4** / **MASWE-0085** (Unsafe Dynamic Code Loading) / MASTG technique MASTG-TECH-0014 (atomic test id to confirm — cite control + descriptive name). *(The dynamic-load **mechanism itself** is also a RESILIENCE-3/-4 concern under the R profile; anchor the injection weakness in CODE-4.)*

### Native-binary hardening (MASVS-CODE-4)
- **Missing compiler-provided security features on `.so`.** Binary-hardening flags **are** statically detectable (contra the older "beyond static reach" framing): per `.so`, run `rabin2 -I` / checksec for missing **PIE/PIC**, **stack canary**, RELRO, NX, FORTIFY_SOURCE. No canary + no PIE = a soft ROP target that turns a memory bug into reliable exploitation. → **MASVS-CODE-4** / **MASWE-0116** (Compiler-Provided Security Features Not Used) / **MASTG-TEST-0222** (Position Independent Code (PIC) Not Enabled — static) + **MASTG-TEST-0223** (Stack Canaries Not Enabled — static), via technique MASTG-TECH-0014. *(Legacy umbrella: MASTG-TEST-0044 "Make Sure That Free Security Features Are Activated" — **deprecated**; use the atomic 0222/0223.)*
- **Native `.so` secrets and unsafe calls.** Enumerate JNI exports (`nm -D` / androguard / `strings`) and scan for hardcoded secrets (re-anchor: server key → AUTH-1, crypto key → CRYPTO-2) and obviously unsafe calls (`strcpy`/`strcat`/`sprintf`/`memcpy` on external input). **Deep native memory-safety (buffer overflows) is largely beyond static reach** — name the function and mark **Needs dynamic verification** / native review rather than asserting a crash. → secret-bearing native string anchors per its type; memory-safety unsafe-call candidate → MASVS-CODE-4 / MASWE by source (atomic id to confirm).

### Endpoint / attack-surface mapping (supporting)
- **Enumerate hardcoded URLs/hosts.** Not a finding by itself; build the attack-surface map and flag staging/internal/debug endpoints shipped in a release artifact (also relevant to RESILIENCE-3 non-prod resources under R). Feeds NETWORK (cleartext) and AUTH (token endpoints). → supporting analysis; promote only when an endpoint is itself the weakness.

> **Legacy ID map (for older references / cross-checks):** MASTG-TEST-0042 (Checking for Weaknesses in Third Party Libraries → atomic 0272/0274), MASTG-TEST-0044 (Free Security Features → **deprecated**, atomic 0222/0223), MASTG-TEST-0025 (Testing for Injection Flaws → atomic 0339 for provider SQLi), MASTG-TEST-0036 (Testing Enforced Updating, CODE-2 — narrative, MASTG v2 successor pending). Prefer the atomic id; note "(legacy, superseded by MASTG-TEST-0xxx)" if you must cite a low ID. **Repo placement note:** the OWASP repo files MASTG-TEST-0372/-0373/-0374/-0375 (implicit-intent / unintentionally-exported, MASWE-0066/-0083) under the `MASVS-CODE` folder, but by *statement* they are **MASVS-PLATFORM-1** IPC findings — analyze them in the PLATFORM reference, not here.

## Classic false positives
Consult before promoting a candidate. Each below is **usually NOT a finding** absent extra evidence:

| Candidate | Why it's usually a false positive | When it *is* real |
|---|---|---|
| CVE in a bundled library | The vulnerable code path is **not reachable** / the lib is dead weight | the vulnerable API is actually invoked with attacker-influenced input (state the reachability basis) |
| "Hardcoded API key" found during code review | It's an OAuth **client_id**, a package/SHA-restricted public Google (`AIza…`) key, Firebase config, or a **cert pin / public key** | it's a server secret / private key granting access → re-anchor **MASVS-AUTH-1 / MASWE-0005** (crypto key → CRYPTO-2 / MASWE-0014), not CODE |
| `Runtime.exec` / `ProcessBuilder` present | Argument is a fixed literal / not influenced by external input | an external value (Intent extra, deep link, network) reaches the command string |
| `getSerializableExtra` / `readObject` present | Type is constrained / data comes only from a trusted same-process source | fed attacker-influenced bytes (IPC, deep link, backup, network) with **no class allow-list** |
| Missing PIE/canary on a `.dylib`/helper `.so` | Some support libs build without it and are non-executable surface; PIE applies to the main loaded modules | a loaded native lib that processes external input lacks canary **and** PIE (ROP-friendly) |
| Low `minSdk`/`targetSdk` flagged generically | The declared floor is justified by the install base and no weaker-default weakness is actually inherited | the low floor concretely re-enables a weakness (pre-28 cleartext default, ≤23 user-CA trust) the app relies on |
| `DexClassLoader` usage | Loads a read-only, app-internal/bundled DEX | source path is external/writable/remote (attacker-writable) |
| SQLi flagged in a ContentProvider | Query uses `selectionArgs` parameterization, or the provider is not exported / not reachable | `selection`/`sortOrder`/`appendWhere` concatenates untrusted input on a reachable provider |
| `debuggable` / debug leftovers spotted during code review | Anchor is **MASVS-RESILIENCE**, not CODE; and a debug build is not the shipped artifact | present in the **release** artifact (RESILIENCE finding, not a CODE one) |

When you dismiss a candidate, record it (and the reason) in the report's "candidates not promoted" appendix — that transparency is part of an honest deliverable.
