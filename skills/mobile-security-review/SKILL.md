---
name: mobile-security-review
description: >-
  Use for ANY mobile app security review, audit, assessment, or pentest — Android or iOS, static or
  dynamic — per the OWASP MAS project (MASVS controls, MASWE weaknesses, MASTG tests). Trigger whenever the
  user hands over or points at a mobile app artifact (.apk, .aab, .ipa, a Mach-O binary, an extracted APK,
  smali or jadx output), or asks to review, audit, assess, or pentest a mobile app, find vulnerabilities in
  an Android/iOS app, or check it for insecure storage, crypto, network/TLS, WebView, exported components,
  hardcoded secrets, pinning, or root/jailbreak detection — and whenever they mention MASVS, MASWE, MASTG,
  OWASP MAS, or MAS Testing Profiles. Fire even with no jargon: "is this APK safe?" or "audit this iOS build"
  count too. Prefer it over generic code review for any mobile app package. Output is a traceable,
  false-positive-gated report mapping every finding MASVS to MASWE to MASTG.
---

# Mobile Application Security Review (OWASP MASVS / MASWE / MASTG)

This skill is an **authorized mobile-app security testing assistant** for Android and iOS — both offensive
pentest help and full assessments. It is ONE skill: SKILL.md holds the **contract** every finding must satisfy
plus the full-review workflow; the detailed, offensive-capable checks live in `references/`, organized by
platform + phase, so you only load the file relevant to the task in front of you. It works in two **modes** (below).

The standard is the OWASP Mobile Application Security project:
- **MASVS** = the *controls* (what "secure" means). 8 stable groups, v2.0.0. This is your anchor.
- **MASWE** = the *weaknesses* (what can go wrong), Beta catalog, bridges MASVS ↔ MASTG, like CWE for mobile.
- **MASTG** = the *tests/techniques/demos* (how to verify). Mid-refactor into "atomic tests".

---

## Rule Zero — authorization before analysis

**Confirm you are authorized to analyze this artifact before doing anything else, and record it in the report.**
Mobile binaries are often proprietary; decompiling or dynamically instrumenting someone else's app without
permission may be illegal and unethical. If authorization/scope is not already established, ask for it. Note
who authorized the work, the agreed scope (this artifact / these endpoints / this version), and any explicit
out-of-scope items. Dynamic testing in particular touches live systems — never exceed the granted scope.

---

## Modes — pick based on the request

Read the request and choose a mode; both honor Rule Zero and the contract.

**1. Autonomous review** — e.g. *"validá este APK", "is this app safe?", "audit this .ipa", "full MASVS
review of this build"*. Run the full **Workflow** below end-to-end on your own and deliver a verdict +
report. This is the default when the user hands over an artifact and wants an overall judgment.

**2. Targeted assist (interactive / offensive)** — e.g. *"help me find the pinning implementation", "is this
WebView exploitable?", "find the hardcoded keys", "how do I bypass root detection here?", "trace this deep
link", "show me the exported components I can hit"*. Do **not** run the whole pipeline or write a full report.
Instead:
- Jump straight to the relevant `references/` section for that control/component (use the Router below).
- Locate and **explain the actual implementation** in the artifact (decompiled code / manifest / config).
- Help the operator **test or exploit it for authorized testing** — give the concrete dynamic step
  (Frida/objection hook, `adb`/drozer invocation, proxy/MITM setup) and a runnable PoC where feasible.
- Still apply the anti-false-positive gate and the static/dynamic honesty rule (never fabricate runtime
  results; label confidence). Offer to fold the result into a finding/report if they want.

A targeted assist can escalate to a full review, and a full review can pause into targeted assists. Either
way, confirm authorization (Rule Zero) first.

---

## Workflow (autonomous review — mode 1)

```
1. TRIAGE / FINGERPRINT  → identify + hash the artifact, record signing & build type, confirm RELEASE build
2. SET PROFILE           → L1 (essential) / L2 (advanced) / R (resilience) — scopes depth & what counts
3. STATIC ANALYSIS       → fingerprint framework first → platform overview → per-MASVS-group files
4. DYNAMIC ANALYSIS      → ONLY if a prepared device is available and in scope; confirms static flags (HITL)
5. CONSOLIDATE / DEDUPE  → merge static+dynamic, dedupe, apply the anti-false-positive gate, set confidence
6. REPORT                → assemble assets/report-template.md
```

### 1. Triage / fingerprint
- Identify the artifact type and **compute its SHA-256** (this is what you actually analyzed — record it).
- Read signing info and the build type. **Confirm this is a RELEASE build**; flag findings that only matter
  in debug builds accordingly (a debug build is not the shipped artifact).
- Capture: package/bundle id, version name + code, min/target platform, declared permissions, component list.
- `.aab`/app bundle: note it is a *publishing* format; analyze the universal/derived APK and say so.

### 2. Set profile (depth selector)
The profile sets how deep you go and what even counts as a finding. These are the OWASP **MAS Testing
Profiles** (they moved from MASVS v1 levels into the MASTG; you'll see them as `profiles: [L1, L2]` in MASTG
test front matter). A 4th profile, **P (privacy / MAS-P)**, exists — fold privacy in when the app handles
personal data.

| Profile | Use when | Scope of review |
|---|---|---|
| **L1** (MAS-L1, Essential) | Most apps; baseline | All groups except deep RESILIENCE. Storage/crypto/network/platform/code/privacy. |
| **L2** (MAS-L2, Advanced) | High-risk data/functions (finance, health, auth) | L1 + stricter expectations (e.g. encryption required, pinning expected, hardware-backed keys). |
| **R** (MAS-R, Resilience) | App must resist reverse-engineering/tampering (anti-fraud, DRM, paywalled) | Adds MASVS-RESILIENCE: root/tamper/debug/hook detection, obfuscation. **Augments L1/L2, never replaces them.** |

If the user doesn't specify, infer from the app's purpose, **state the profile you chose and why**, and
proceed. RESILIENCE findings are assessed **only under R**.

### 3. Static analysis
Fully automated — no device needed. **First fingerprint the framework** (native vs React Native / Flutter /
Cordova / Unity / Xamarin — see `references/cross-platform-static.md`). Then open the platform overview
(`references/android-overview.md` or `references/ios-overview.md`) for tools + the manifest/Info.plist pre-pass,
and walk the per-MASVS-group files (`references/<platform>/<group>.md`) — all applicable groups for a full
review, or just the relevant one for a targeted assist. A static signal (grep / MobSF / APKiD hit, manifest
attribute) is a **candidate**, not a finding, until it clears the gate below.

### 4. Dynamic analysis — only with a real, prepared device, in scope
Dynamic testing is **human-in-the-loop**: it needs a prepared device/emulator and an operator who exercises
the app's flows. Its job is to **confirm** what static analysis suspected (effective pinning, real on-disk
storage, actual component exposure, behavior under root/jailbreak) and to fuse with static, raising confidence.
If no device is available or it's out of scope, **say so** and leave static-only items at confidence
**"Needs dynamic verification."**

### 5. Consolidate / dedupe
Merge static and dynamic observations for the same root cause into one finding (don't report the static
suspicion and its dynamic confirmation as two). Apply the anti-false-positive gate. Set honest confidence.

### 6. Report
Assemble `assets/report-template.md`. Output is Markdown.

---

## Router — which reference(s) to read

Read **only** what the task needs. Start from the platform **overview** (tools, pre-pass, and a router to the
per-group files); for a targeted assist, jump straight to the relevant group file.

| Artifact / situation | Read |
|---|---|
| `.apk`, `.aab`, extracted APK, smali/jadx output → **Android** | `references/android-overview.md` → `references/android/<group>.md` |
| `.ipa`, Mach-O, iOS app folder → **iOS** | `references/ios-overview.md` → `references/ios/<group>.md` |
| Cross-platform app (React Native, Flutter, Cordova, Unity, Xamarin, KMP) | `references/cross-platform-static.md` — fingerprint FIRST |
| Automated tooling / SBOM-SCA / reachability / secrets / Firebase | `references/static-tooling-and-methodology.md` |
| Android + prepared device in scope → **confirm dynamically** | `references/android-dynamic.md` |
| iOS + prepared jailbroken device in scope → **confirm dynamically** | `references/ios-dynamic.md` |
| Setting up any dynamic test environment (shared) | `references/setup-dynamic.md` |

Then expand each finding with `assets/finding-template.md` and assemble with `assets/report-template.md`.

---

## The contract (applies to EVERY finding, on every platform)

This is the single source of truth. The platform references defer to it.

### Finding schema
Every finding is a YAML front-matter block + Markdown body (see `assets/finding-template.md`):

| Field | Required | Notes |
|---|---|---|
| `id` | ✔ | Stable within the report, e.g. `MSR-001`. |
| `title` | ✔ | Specific and concrete (name the component/endpoint). |
| `severity` | ✔ | `Critical` \| `High` \| `Medium` \| `Low` \| `Info`. |
| `confidence` | ✔ | `Confirmed` \| `Likely` \| `Needs dynamic verification`. |
| `platform` | ✔ | `Android` \| `iOS`. |
| `masvs` | ✔ | The control anchor, e.g. `MASVS-NETWORK-1`. **Always present.** |
| `maswe` | ✔ | Weakness ID, e.g. `MASWE-0050`. `MASWE: unmapped` if none fits (Beta catalog has gaps). |
| `mastg` | ✔ | List of test/technique IDs verified against the live guide. |
| `cwe` | optional | When a clean mapping exists (e.g. `CWE-319`). |
| `affected_component` | ✔ | File/class/manifest entry/endpoint where it lives. |
| `description` / `evidence` / `impact` / `remediation` / `references` | ✔ | Body sections. |

### Mandatory traceability: MASVS → MASWE → MASTG
Every finding must trace **control → weakness → test**:
- **MASVS is the anchor — cite the *correct* control, not just the right group.** The 8 groups and the
  `MASVS-GROUP-N` numbering are stable (v2.0.0). **Do not guess the number:** pick it from the **MASVS control
  list** below by matching your finding to the control *statement*, and sanity-check by quoting that statement.
  Mis-numbering inside the right group (e.g. tagging SQL injection `MASVS-CODE-2` instead of `MASVS-CODE-4`, or
  `debuggable` under CODE instead of RESILIENCE) is the most common traceability error — the list exists to stop it.
- **Let the MASWE entry choose the group**, then the statement chooses the number. Anchors that are easy to get wrong:
  - Hardcoded **API keys / tokens / credentials** → **MASVS-AUTH-1** (MASWE-0005); hardcoded **crypto keys / IVs** → **MASVS-CRYPTO**. (You *find* these during code review, but they do **not** anchor to MASVS-CODE.)
  - **SQL injection / any unsafe untrusted input** → **MASVS-CODE-4**; **known-vulnerable libraries** → **MASVS-CODE-3**; outdated platform → CODE-1; update enforcement → CODE-2.
  - **debuggable / anti-debug / anti-tamper / obfuscation / root or emulator detection** → **MASVS-RESILIENCE** (never MASVS-CODE) — even when reported only as Info under an L1/L2 engagement.
  - Exported components / IPC / deep links → **PLATFORM-1**; WebViews → **PLATFORM-2**; screenshot/clipboard/notification UI exposure → **PLATFORM-3**.
- **MASWE/MASTG IDs are mid-refactor — verify, don't trust memory.** MASWE is Beta; MASTG is splitting legacy
  narrative tests into atomic tests (legacy low IDs and atomic 0200+ IDs coexist). Verify each ID against the
  live guide / OWASP source repos. If unsure, cite the MASVS control + a descriptive test name and mark the ID
  **"to confirm"** — never invent one, and **never borrow an unrelated ID** to fill the slot.
- **Some weaknesses have no clean atomic test** (e.g. `debuggable`, `allowBackup`): cite the control + a
  descriptive name + "ID to confirm" rather than attaching an unrelated test ID.
- **Beware deprecated/consolidated IDs.** Prefer the atomic successor over a deprecated legacy test, or note
  "(legacy, superseded by MASTG-TEST-####)"; some MASWE were merged (e.g. MASWE-0013 → MASWE-0014) — use the current one.
- Canonical test URL: `https://mas.owasp.org/MASTG/tests/<platform>/<MASVS-CATEGORY>/<ID>/` — `<MASVS-CATEGORY>`
  must be the test's *real* category (atomic tests live under `/tests-beta/` in the repo but resolve under
  `/tests/` on the site). MASWE: `https://mas.owasp.org/MASWE/<MASVS-CATEGORY>/<ID>/`.

### Severity = impact × exploitability **in this app**, modulated by the profile
Severity is about *this* app, not the abstract badness of a pattern. Weigh: how sensitive is the exposed
asset, how reachable is the code path, what preconditions are required (device state, user interaction,
adjacency, another app installed), and the profile. The same pattern can be High in an L2 banking app and
Info in an L1 utility. A theoretically-bad construct in dead/unreachable code is not High.

### Anti-false-positive gate — the most important rule
Before anything becomes a finding, it must pass all three:
- **(a) Real evidence?** Concrete, reproducible proof — not just a pattern/grep/MobSF match. Show the code/config.
- **(b) Reachable / exploitable here?** Is the path reached in this build, with realistic preconditions, under
  this profile? A CVE in a bundled-but-unused library, or `debuggable` in a debug build, usually is not.
- **(c) Honest confidence?** If only statically suspected, it is **"Needs dynamic verification,"** not Confirmed.

A grep hit or a MobSF flag is a **candidate, not a finding.** Record dismissed candidates (and why) in the
report appendix — that transparency is part of the deliverable. Each platform reference lists its classic
false positives; consult them before promoting a candidate.

### Static / dynamic boundary — never fabricate dynamic results
- **Static** is fully automated and self-contained.
- **Dynamic** requires a *real prepared device + a human operator* exercising flows. It is the only way to
  *confirm* runtime behavior (effective pinning, actual storage at rest, live component exposure).
- **NEVER fabricate dynamic results.** Anything only suggested by static analysis is `Needs dynamic
  verification` until an actual dynamic run confirms it. If you did not run on a device, do not claim
  runtime behavior — describe what a dynamic test *would* check and mark it accordingly.

### Output
Markdown, assembled from `assets/report-template.md`: executive summary → scope/methodology (incl. Rule-Zero
authorization + profile rationale) → findings summary table → findings → MASVS coverage → appendices. "Pass"
and "Not applicable" per MASVS group are valid, useful results — show breadth, not just hits.

---

## MASVS v2.0.0 controls (authoritative anchors — pick the exact control here)

Match each finding to a control **statement** below and cite that `MASVS-GROUP-N`. Statements are verbatim from
MASVS v2.0.0; *(italics)* are the kinds of findings that anchor there.

**MASVS-STORAGE** — data at rest & leakage
- `MASVS-STORAGE-1` — The app securely stores sensitive data. *(SharedPreferences/DB/files holding secrets unencrypted)*
- `MASVS-STORAGE-2` — The app prevents leakage of sensitive data. *(logs, backups/allowBackup, IPC, external/shared storage)*

**MASVS-CRYPTO** — cryptography & keys
- `MASVS-CRYPTO-1` — The app employs current strong cryptography and uses it according to industry best practices. *(weak algos/modes, ECB, MD5/SHA-1 for security, bad RNG)*
- `MASVS-CRYPTO-2` — The app performs key management according to industry best practices. *(hardcoded keys/IVs/salts, Keystore misuse)*

**MASVS-AUTH** — authentication & authorization
- `MASVS-AUTH-1` — The app uses secure authentication and authorization protocols and follows the relevant best practices. *(client-side token/session handling; hardcoded API keys/tokens — MASWE-0005)*
- `MASVS-AUTH-2` — The app performs local authentication securely according to the platform best practices. *(biometric/PIN gate not tied to Keystore)*
- `MASVS-AUTH-3` — The app secures sensitive operations with additional authentication. *(step-up auth / MFA)*

**MASVS-NETWORK** — data in transit
- `MASVS-NETWORK-1` — The app secures all network traffic according to the current best practices. *(cleartext, disabled TLS/hostname/cert validation, user trust anchors)*
- `MASVS-NETWORK-2` — The app performs identity pinning for all remote endpoints under the developer's control. *(missing/weak pinning)*

**MASVS-PLATFORM** — OS & inter-app interaction
- `MASVS-PLATFORM-1` — The app uses IPC mechanisms securely. *(exported activities/services/receivers/providers, intents, deep links, PendingIntents)*
- `MASVS-PLATFORM-2` — The app uses WebViews securely. *(JS bridges, file access, remote/mixed content)*
- `MASVS-PLATFORM-3` — The app uses the user interface securely. *(screenshots, clipboard, notifications, shoulder-surfing)*

**MASVS-CODE** — platform currency, dependencies, input handling
- `MASVS-CODE-1` — The app requires an up-to-date platform version. *(low minSdk/targetSdk)*
- `MASVS-CODE-2` — The app has a mechanism for enforcing app updates.
- `MASVS-CODE-3` — The app only uses software components without known vulnerabilities. *(vulnerable libraries / reachable CVEs)*
- `MASVS-CODE-4` — The app validates and sanitizes all untrusted inputs. *(SQL/command injection, unsafe deserialization, unsafe handling of network data)*

**MASVS-RESILIENCE** — anti-reverse-engineering / tampering *(assessed under the **R** profile; `debuggable` & anti-debug anchor here even when noted Info under L1/L2)*
- `MASVS-RESILIENCE-1` — The app validates the integrity of the platform. *(root/jailbreak detection)*
- `MASVS-RESILIENCE-2` — The app implements anti-tampering mechanisms. *(signature/integrity self-check, repackaging detection)*
- `MASVS-RESILIENCE-3` — The app implements anti-static analysis mechanisms. *(obfuscation)*
- `MASVS-RESILIENCE-4` — The app implements anti-dynamic analysis techniques. *(anti-debug/anti-hook/emulator detection; the `debuggable` flag)*

**MASVS-PRIVACY** — personal data
- `MASVS-PRIVACY-1` — The app minimizes access to sensitive data and resources. *(over-permissioning, third-party SDK data sharing)*
- `MASVS-PRIVACY-2` — The app prevents identification of the user. *(persistent identifiers, fingerprinting)*
- `MASVS-PRIVACY-3` — The app is transparent about data collection and usage.
- `MASVS-PRIVACY-4` — The app offers user control over their data.

Canonical sources (verify MASWE/MASTG IDs here, don't trust memory):
- MASVS: https://mas.owasp.org/MASVS/  ·  Profiles: https://mas.owasp.org/MASTG/0x03b-Testing-Profiles/
- MASWE (Beta): https://mas.owasp.org/MASWE/  ·  MASTG tests: https://mas.owasp.org/MASTG/tests/

---

## Files in this skill
- `references/android-overview.md` / `references/ios-overview.md` — **start here per platform**: tools, pre-pass, router to group files.
- `references/android/<group>.md` and `references/ios/<group>.md` — per-MASVS-group static checks (storage, crypto, auth, network, platform, code, resilience, privacy).
- `references/cross-platform-static.md` — detect + statically analyze RN / Flutter / Cordova / Unity / Xamarin / KMP.
- `references/static-tooling-and-methodology.md` — semgrep / MobSF / APKiD, SBOM/SCA, reachability/xref, secrets, Firebase/cloud config.
- `references/android-dynamic.md` / `references/ios-dynamic.md` — runtime confirmation of static flags (HITL).
- `references/setup-dynamic.md` — shared dynamic environment setup.
- `assets/finding-template.md` — per-finding template (schema + gate reminder).
- `assets/report-template.md` — full report skeleton.
