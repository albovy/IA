# Mobile Application Security Review — <App Name>

| | |
|---|---|
| **Artifact** | `<filename>` (`.apk` / `.aab` / `.ipa`) |
| **Platform** | Android / iOS |
| **Package / Bundle ID** | `<com.example.app>` |
| **Version** | `<versionName> (<versionCode>)` |
| **SHA-256** | `<sha256 of the analyzed artifact>` |
| **Signing** | `<signer / certificate subject, signature scheme>` |
| **Build type** | Release / Debug (`debuggable=?`) |
| **Profile applied** | L1 / L2 / R (see Methodology) |
| **Analysis performed** | Static / Static + Dynamic |
| **Reviewer** | `<name>` |
| **Date** | `<YYYY-MM-DD>` |

> **Authorization & scope (Rule Zero).** Record here the explicit authorization to test this artifact, who
> granted it, and the agreed scope/boundaries. Analysis must not begin until this is confirmed. If dynamic
> testing was performed, note the test device and that flows were exercised by an authorized operator.

---

## 1. Executive summary
<!-- 3-6 sentences for a non-specialist: what was reviewed, the overall security posture, the headline risks,
     and the single most important thing to fix. No jargon dumps. -->

**Findings by severity:**

| Critical | High | Medium | Low | Info |
|:---:|:---:|:---:|:---:|:---:|
| 0 | 0 | 0 | 0 | 0 |

---

## 2. Scope & methodology
- **Scope:** what was in scope (this artifact / these endpoints / this version) and what was explicitly out.
- **Profile rationale:** why L1, L2, or R was chosen (data sensitivity, threat model, whether anti-tampering is a requirement).
- **Standard:** OWASP MASVS (controls) → MASWE (weaknesses) → MASTG (tests). Note the MASVS version used and that
  MASWE/MASTG IDs were verified against the live guide on the analysis date.
- **Static analysis:** tools and steps (unpack, decompile, manifest/Info.plist review, code/config inspection).
- **Dynamic analysis:** device/emulator state, instrumentation (e.g. Frida), interception proxy + CA, and which
  app flows were exercised. If no dynamic testing was performed, say so — and mark the affected findings
  "Needs dynamic verification".

---

## 3. Findings summary

| ID | Title | Severity | Confidence | MASVS | Component |
|---|---|---|---|---|---|
| MSR-001 | … | High | Confirmed | MASVS-NETWORK-1 | … |
| MSR-002 | … | Medium | Needs dynamic verification | MASVS-STORAGE-2 | … |

---

## 4. Findings
<!-- One subsection per finding, expanded from assets/finding-template.md. Order by severity, then by ID. -->

### MSR-001 — <title>
*(full finding here: severity, confidence, MASVS→MASWE→MASTG, affected component, description, evidence,
impact, remediation, references)*

---

## 5. MASVS coverage
<!-- Show what was assessed per MASVS group so the reader sees the breadth of the review, not just the hits.
     "Not applicable" and "Pass" are valid and useful outcomes. -->

| MASVS group | Assessed | Result | Notes |
|---|:---:|---|---|
| MASVS-STORAGE | ✔ | findings: MSR-002 | |
| MASVS-CRYPTO | ✔ | pass | |
| MASVS-AUTH | ✔ | | |
| MASVS-NETWORK | ✔ | findings: MSR-001 | |
| MASVS-PLATFORM | ✔ | | |
| MASVS-CODE | ✔ | | |
| MASVS-RESILIENCE | — | n/a (L1/L2 profile) | only assessed under the R profile |
| MASVS-PRIVACY | ✔ | | |

---

## 6. Appendices
- **A. Artifact fingerprint** — full file listing hashes, signature details, certificate, declared permissions.
- **B. Tooling & versions** — exact tool versions used (apktool, jadx, apksigner, MobSF, Frida, etc.).
- **C. Reproduction** — commands/scripts used (static), and dynamic scripts + proxy config for authorized re-testing.
- **D. Static candidates not promoted to findings** — what was flagged by tools/greps but dismissed by the
  anti-false-positive gate, and why (transparency on what was ruled out).
