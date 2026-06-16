# Cross-platform — MASVS (static): automated tooling & analysis methodology

Scope: the shared, platform-agnostic static layer both native references link to — automated scanners (semgrep / mobsfscan / MobSF / APKiD), SBOM/SCA dependency-CVE process with a reachability gate, secrets-detection methodology beyond grep, and Firebase/backend cloud-config exposure. This file is **method, not a control group**: every tool hit and every match here is a **candidate**, never a finding, until it clears the anti-false-positive gate in `SKILL.md` (real evidence? reachable here? honest confidence?) and is anchored to the correct MASVS control by *statement match*.

Anchor each finding to the exact control in SKILL.md (read it); verify MASWE/MASTG IDs against the live guide.

This methodology routes findings into several groups; the controls it most often lands on, verbatim from MASVS v2.0.0:

- **MASVS-CODE-3** — "The app only uses software components without known vulnerabilities." *(SBOM/SCA, reachable CVEs)*
- **MASVS-AUTH-1** — "The app uses secure authentication and authorization protocols and follows the relevant best practices." *(hardcoded API keys / tokens / credentials — MASWE-0005)*
- **MASVS-CRYPTO-2** — "The app performs key management according to industry best practices." *(hardcoded crypto keys / IVs / salts — MASWE-0014)*
- **MASVS-STORAGE-2** — "The app prevents leakage of sensitive data." *(open/unauthenticated Firebase / cloud backend exposing app data)*

A scanner hit maps to **whatever sink it lands on** — these four are the common homes, but a semgrep SQLi hit is MASVS-CODE-4, a deserialization hit MASVS-CODE-4, a cleartext hit MASVS-NETWORK-1, etc. Always re-anchor by statement.

---

## 1. Automated scanners — every hit is a CANDIDATE

Run these to surface low-hanging fruit fast and focus manual effort on business logic; the official techniques explicitly warn of false positives/negatives, so **confirm each hit in the decompiled code/config before it becomes a finding**.

- **semgrep with mobile rule packs** — scan decompiled Java/Kotlin (jadx output) and Swift/Obj-C with MASTG/`mobile`/`mobsfscan` rulesets and the OWASP MASVS rules. semgrep reads source, so it depends on a clean decompile (R8/obfuscation degrades it; FairPlay-encrypted iOS binaries must be decrypted first). Each rule hit = candidate; trace the match to a reachable sink.
  → method, anchors to the hit's sink (e.g. MASWE-0086 SQLi, MASWE-0088 deserialization, MASWE-0050 cleartext) · tool **MASTG-TOOL-0110** (semgrep) · technique **MASTG-TECH-0025** (Automated Static Analysis, Android) / **MASTG-TECH-0078** (Automated Static Analysis, iOS).
- **mobsfscan** — static-pattern scanner for Android/iOS source (Java/Kotlin/Swift/Obj-C); fast triage for insecure-API patterns, hardcoded values, weak crypto, insecure network config. Standalone MASTG-TOOL id **(ID to confirm)** — it is the CLI scanner from the MobSF project (**MASTG-TOOL-0035**, MobSF). Treat as candidate-generator; MobSF/mobsfscan over-report.
  → anchors to the hit's sink · tool **MASTG-TOOL-0035** (MobSF) · technique **MASTG-TECH-0025** / **MASTG-TECH-0078**.
- **MobSF static** — automated all-in-one static triage (manifest/Info.plist parse, permissions, secrets, insecure-API patterns, NSC/ATS, exported components, SBOM-ish library list). **Every MobSF item is a candidate** — confirm by reading decompiled code; MobSF over-reports and infers some items it cannot prove statically.
  → anchors to the hit's group · tool **MASTG-TOOL-0035** (MobSF) · technique **MASTG-TECH-0025** / **MASTG-TECH-0078**.
- **APKiD (framework + packer detection)** — fingerprints how an APK was built: **compiler** (dx/d8/r8/dexlib — dexlib often signals repackaging), **packer/protector** (Jiagu, SecNeo, DexProtector, etc.), **obfuscator**, and **anti-debug/anti-VM** markers. This is the cheapest way to learn *before* you decompile that (a) the DEX is packed (your jadx read will be incomplete — note it, don't conclude "no logic/no secrets") and (b) a resilience layer exists. Pair with the framework fingerprint in `cross-platform-static.md` (APKiD won't name RN/Flutter/Xamarin — that's the framework step).
  → packer/obfuscator presence routes to **MASVS-RESILIENCE-3** (MASWE-0089/-0090) under the **R** profile; repackaging-compiler signal relates **MASVS-RESILIENCE-2** (MASWE-0104). Tool **MASTG-TOOL-0009** (APKiD). Atomic test for packer detection: descriptive "APKiD compiler/packer fingerprint" **(ID to confirm)**.

**Gate reminder:** a grep hit, a semgrep rule, an APKiD packer flag, or a MobSF item is a **candidate**. Record dismissed candidates (and why) in the report appendix — that transparency is part of the deliverable.

---

## 2. SBOM / SCA for vulnerable dependencies + the REACHABILITY gate

Known-vulnerable dependencies are the highest-yield finding *class*, but a CVE in a bundled-but-unused library is **not** a finding — the gate's "reachable here?" decides. Two phases: enumerate components precisely, then prove (or disprove) reachability with a call-graph/xref pass.

### 2a. Build the SBOM and correlate CVEs (CODE-3 / MASWE-0076)

- **Generate a CycloneDX SBOM** with **cdxgen** (MASTG-TOOL-0134) — from the build tree when available (Gradle for Android; CocoaPods / SwiftPM / Carthage for iOS) or against the package. Enumerate **every component + its exact version**; for a shipped artifact recover versions from smali package paths, `META-INF/`, embedded `.properties`/`BuildConfig`, `Payload/<App>.app/Frameworks/*` and embedded `.dylib`/`.framework`. Note the limitation the live guide states: version strings are often stripped at compile time, so build-time SBOM is more reliable than scanning the IPA/APK.
- **Correlate against NVD / OSV / GitHub Advisories** — feed the SBOM to **dependency-check** (MASTG-TOOL-0131) and/or upload to **dependency-track** (MASTG-TOOL-0132); output is component → CVE.
- **Report the SBOM as a deliverable**, not just the CVE list.
  → **MASVS-CODE-3** / **MASWE-0076** ("Dependencies with Known Vulnerabilities").
  → **Android atomic:** **MASTG-TEST-0272** (Identify Dependencies with Known Vulnerabilities in the Android Project) + **MASTG-TEST-0274** (Dependencies with Known Vulnerabilities in the App's SBOM); techniques **MASTG-TECH-0130** (SCA by creating a SBOM) / **MASTG-TECH-0131** (SCA of Android Dependencies at Build Time). Legacy umbrella **MASTG-TEST-0042** (Checking for Weaknesses in Third Party Libraries).
  → **iOS atomic:** **MASTG-TEST-0273** (Identify Dependencies with Known Vulnerabilities) + **MASTG-TEST-0275** (Dependencies with Known Vulnerabilities in the App's SBOM); techniques **MASTG-TECH-0132** (SCA by creating a SBOM) / **MASTG-TECH-0133** (SCA by scanning package-manager artifacts). Legacy umbrella **MASTG-TEST-0085**.
  > Cross-platform note: most RN/Flutter/Xamarin CVEs live in the JS/Dart/.NET tree, not native `.so`/`.dylib` — also read `package.json`/`yarn.lock`, `pubspec.lock`, NuGet/assembly versions (see `cross-platform-static.md`).

### 2b. REACHABILITY / xref — operationalize "reachable here?"

A CVE (or any candidate sink) only stands if a call path reaches it in *this* build from a real entry point. Prove it with a call-graph/cross-reference pass; mark unreachable candidates **dismissed** with the xref evidence (defensible in the appendix).

- **Android — androguard XREFs:** `AnalyzeAPK("app.apk")` then walk `MethodAnalysis.get_xref_from()` / `get_xref_to()` (and `ClassAnalysis` xrefs) from manifest entry points — exported components' `onCreate`/`onReceive`/`onBind`, `Application.onCreate`, deep-link/`Linking` handlers — toward the vulnerable API or sink. Or in **jadx** use **"Find Usage"** from the same entry points. Entry points come from the manifest (technique **MASTG-TECH-0117**, Obtaining Information from the AndroidManifest).
  → reachability technique **MASTG-TECH-0020** (Retrieving Cross References, Android); tools **MASTG-TOOL-0018** (jadx), androguard. *(MASTG-TECH-0014 "Static Analysis on Android" is the general static-analysis umbrella; -0020 is specifically cross-references/reachability.)*
- **iOS — class-dump + Ghidra/radare2:** recover the class/method surface (class-dump / dsdump), then trace xrefs in **Ghidra** ("Show References to") or **radare2/rabin2** (`axt <addr>` = analyze xrefs-to) from reachable entries — custom URL-scheme handlers, Universal-Link / `continueUserActivity`, app-delegate launch — to the sink. Requires a **decrypted** binary (FairPlay `cryptid=0`).
  → reachability technique **MASTG-TECH-0072** (Retrieving Cross References, iOS). *(TECH-0070/-0075/-0076 are binary-extraction/review techniques, not the xref/reachability one.)*

> **Honesty:** static reachability via xref is strong evidence the path *exists*, but data-flow feasibility (attacker actually controls the input that reaches the sink) often needs dynamic confirmation — set confidence accordingly (`Likely` vs `Needs dynamic verification`), never `Confirmed` on xref alone.

---

## 3. Secrets methodology beyond grep — with the strict FP gate

Grep for fixed strings misses high-entropy blobs and base64/hex-encoded keys; pattern-only scanners over-report public values. Combine **provider-format regex** + **entropy** to detect, then apply the **"what does it unlock"** triage to classify and anchor.

### 3a. Detect (broad, candidate-generating)

Run **trufflehog** / **gitleaks** / **semgrep-secrets** / **MobSF** over code **+ `res/` + `assets/` + native `strings`** (and the JS/Dart/.NET artifact for cross-platform apps — see `cross-platform-static.md`):
- **(a) Provider-format regex** — AWS `AKIA[0-9A-Z]{16}`, Google `AIza[0-9A-Za-z_\-]{35}`, Stripe `sk_live_`, GitHub `ghp_`/`github_pat_`, Slack `xox[baprs]-`, JWT `eyJ...`, PEM/PKCS (`-----BEGIN ... PRIVATE KEY-----`), Twilio `SK...`, generic `bearer`/`api[_-]?key=`.
- **(b) Shannon-entropy** on string literals and resource values to catch keys that match no known prefix (high-entropy base64/hex above a threshold = candidate).
  → tools: trufflehog **(MASTG-TOOL id to confirm)**, gitleaks **(MASTG-TOOL id to confirm)**, semgrep **MASTG-TOOL-0110**, MobSF **MASTG-TOOL-0035**. Resource/manifest/strings discovery via **MASTG-TECH-0117** (Android, AndroidManifest/resources) and **MASTG-TECH-0058** (iOS, Exploring the App Package / Info.plist).

### 3b. Triage — "what does it unlock" decides finding vs dismissed AND the anchor

Classification is **mandatory** and sets both the verdict and the MASVS control:

| Value | Verdict | Anchor |
|---|---|---|
| Server secret / private key / signing key / symmetric **access** key | **Finding** | access token / API key → **MASVS-AUTH-1** / **MASWE-0005**; crypto key/IV/salt → **MASVS-CRYPTO-2** / **MASWE-0014** |
| OAuth **`client_id`** | Dismissed (public by design) | — |
| Google **API key restricted by package + SHA-1** (incl. Firebase config `api_key`) | Dismissed (public, scoped) | — |
| Certificate **pin / public key**, public base64 of a cert | Dismissed (public) | — |
| Firebase config block as a whole (`project_id`, `storage_bucket`, `database_url`) | Dismissed *as a secret* — but **feeds §4** (open-backend probe) | open backend → MASVS-STORAGE-2 |

> The single most common secrets false positive is flagging a public `client_id` / SHA-restricted Google key / Firebase `api_key` / cert pin as a "hardcoded secret." Always confirm **what the value unlocks** before flagging, and **anchor by statement** — API keys/tokens are AUTH-1 (MASWE-0005), crypto keys are CRYPTO-2 (MASWE-0014); neither anchors to MASVS-CODE even though you *find* them during code review.

---

## 4. Firebase / backend cloud-config exposure (MASVS-STORAGE-2)

Cloud-backend config is **100% statically discoverable**, and the open-rules check is a trivial *unauthenticated* call you flag for testing. The config itself is not the secret (see §3b); the risk is an **open backend exposing app data without authentication** — which is leakage of sensitive data, so it anchors to **MASVS-STORAGE-2**, *not* crypto.

> **Anchor note:** open/unauthenticated backend data is *leakage* → anchor **MASVS-STORAGE-2** ("prevents leakage of sensitive data"), **not** MASVS-CRYPTO (MASWE-0010 is a CRYPTO/KDF weakness — the wrong home for an open backend). The precise MASWE under STORAGE-2 for open cloud backends is **(MASWE id to confirm)** — anchor by the control statement.

**Static discovery:**
- **Android:** parse `res/values/strings.xml` and **`google-services.json`** for `firebase_database_url`/`project_id`/`storage_bucket`/`google_api_key`; grep code for `*.firebaseio.com`, `*.firebasedatabase.app`, `firestore.googleapis.com`, `*.appspot.com` / `firebasestorage.googleapis.com`. Discovery technique **MASTG-TECH-0117** (manifest/resources) + **MASTG-TECH-0007** (Exploring the App Package).
- **iOS:** parse **`GoogleService-Info.plist`** for the same keys; grep the (decrypted) binary/strings for the same URLs. Discovery via **MASTG-TECH-0058** (Exploring the App Package) + **MASTG-TECH-0153**/`-0154` (Info.plist).
- **Other clouds:** AWS Amplify `amplifyconfiguration.json` / `awsconfiguration.json` (Cognito identity/user-pool ids), Azure connection strings, Supabase URL + `anon` key, Sentry/Mapbox DSNs.

**Open-rules probe (flag for the dynamic phase — do not fabricate the result):**
- Realtime DB: `GET https://<project>.firebaseio.com/.json` (or `.firebasedatabase.app`) returning data = world-readable rules.
- Firestore: unauthenticated REST `GET https://firestore.googleapis.com/v1/projects/<project>/databases/(default)/documents/<collection>`.
- Storage: unauthenticated object listing/read on the `*.appspot.com` / `firebasestorage` bucket.
  → **MASVS-STORAGE-2**; the Firebase open-rules probe is documented in the knowledge items **MASTG-KNOW-0039** (Android) / **MASTG-KNOW-0095** (iOS) *Firebase Real-time Databases* (+ demo **MASTG-DEMO-0081**); the legacy umbrella **MASTG-TEST-0001** also carries the `.json` check in its narrative. **No dedicated atomic *test* for open-backend rules exists → cite the control + these knowledge refs + descriptive name "Firebase/cloud open-rules exposure"**, never invent a test id. The world-readable verdict requires the unauthenticated probe (dynamic) — mark static-only **Needs dynamic verification**.

> **Honesty:** static analysis can only *flag* the endpoint and that the probe is worth running. The actual "data is world-readable" verdict requires the unauthenticated call (dynamic) — mark static-only findings **Needs dynamic verification** and describe the exact probe a tester would run.

---

## Classic false positives (this methodology layer)

| Candidate | Likely false positive when… | Promote to finding when… |
|---|---|---|
| semgrep / mobsfscan / MobSF rule hit | Pattern match only; sink unreachable, in dead code, or the "secret" is a public value | Confirmed in decompiled code, reachable from an entry point (xref), with realistic preconditions |
| APKiD "packer/obfuscator detected" | Only meaningful under the **R** profile; an L1 utility isn't required to obfuscate | Under **R** and the protector is absent/weak (RESILIENCE-3), or compiler signal indicates repackaging (RESILIENCE-2) |
| CVE in a bundled library (SBOM hit) | The vulnerable code path is **not reachable** (no xref from any entry point) / lib is dead weight / wrong sub-component | The vulnerable API is actually invoked with attacker-influenced input (xref + data-flow) |
| "Hardcoded API key / secret" | OAuth `client_id`, package+SHA-restricted Google/Firebase `api_key`, a cert pin / public key, public cert base64 | A server secret / private / signing / access key that grants real access (→ AUTH-1 or CRYPTO-2 by statement) |
| Firebase config present | The config block alone (it's meant to ship in the client) | The Realtime DB / Firestore / Storage **open-rules probe** returns data unauthenticated (→ STORAGE-2) |
| High-entropy string flagged | It's a public key, a UUID, a hash, a minified/obfuscated identifier, or test data | It decodes to / is a usable credential or private key |
| mobsfscan "weak crypto / insecure" | Used for a non-security purpose (checksum, cache key) or in unreachable code | Used to protect trusted data and reachable (re-anchor to CRYPTO/CODE by statement) |
