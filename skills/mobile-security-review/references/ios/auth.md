# iOS — MASVS-AUTH (static)

Scope: client-side authentication & authorization in an iOS artifact (`.ipa` / `.app` / Mach-O) — token/credential handling, hardcoded API keys, and local (biometric/passcode) authentication. Server-side auth logic is out of scope for static review; flag it for dynamic/API testing.

Anchor each finding to the exact control in SKILL.md (read it); verify MASWE/MASTG IDs against the live guide.

> **FairPlay caveat applies.** Against a `cryptid=1` App Store binary, `otool`/`nm`/`class-dump`/Ghidra read **ciphertext** — every conclusion about hardcoded tokens, biometric API references, or auth logic is invalid until the binary is decrypted (`cryptid=0`). Confirm decryption (`rabin2 -I`) before promoting any AUTH finding from binary strings/symbols. See the iOS static pre-pass for extraction/decryption.

## MASVS-AUTH controls (verbatim, MASVS v2.0.0 — anchor by statement match)
- **MASVS-AUTH-1** — The app uses secure authentication and authorization protocols and follows the relevant best practices. *(client-side token/session handling; hardcoded API keys/tokens — MASWE-0005)*
- **MASVS-AUTH-2** — The app performs local authentication securely according to the platform best practices. *(biometric/PIN gate not tied to Keychain)*
- **MASVS-AUTH-3** — The app secures sensitive operations with additional authentication. *(step-up auth / MFA)*

> The MAS site lists all MASVS-AUTH weaknesses under one "MASVS-AUTH" group without printing the `-1/-2/-3` sub-number; the test pages likewise tag only "MASVS-AUTH". **Pick the sub-number by statement match** (above), not from the page. Biometric/local-auth weaknesses → AUTH-2; fallback/step-up for sensitive transactions → AUTH-3; protocol/token/secret handling → AUTH-1.

---

## Checks (static)

Each = concrete static check · MASVS anchor · MASWE · MASTG. Promote only after the SKILL.md anti-false-positive gate.

### AUTH-1 — secure auth/authz protocols, token & credential handling

- **Hardcoded API keys / tokens / credentials in the binary or bundle.** Recover the (decrypted) Mach-O strings/symbols and bundle resources (`Info.plist`, embedded `.plist`/JSON, `assets/`) and look for bearer tokens, API keys, basic-auth creds, OAuth client *secrets* (not public `client_id`). Apply the "what does it unlock" triage from the secrets methodology — a server-side secret/private key is a finding; a SHA-restricted public Google key / OAuth `client_id` / Firebase `api_key` is dismissed. **Anchor `MASVS-AUTH-1`, not CODE.** → **MASWE-0005** (API Keys Hardcoded in the App Package). No clean iOS *atomic* static test for secret discovery → cite the binary-review technique **MASTG-TECH-0070** (Extracting Information from the Application Binary) + descriptive name "hardcoded credential discovery (ID to confirm)". `cwe` ≈ CWE-798.

- **Auth token / session storage location.** Trace where access/refresh tokens and session identifiers are persisted: Keychain (correct, with a `ThisDeviceOnly` accessibility class) vs `UserDefaults`/`.plist`/Core Data/SQLite/cached files (wrong). Token-at-rest in a plaintext store that gates auth state → MASVS-AUTH-1 leakage. → **MASWE-0036** (Authentication Material Stored Unencrypted on the Device); cross-anchors to MASVS-STORAGE-1/CRYPTO-2 (see the iOS STORAGE/CRYPTO reference — report once, anchor by primary root cause). MASTG: storage atomic **MASTG-TEST-0300** (ID to confirm for the AUTH-token framing); legacy umbrella MASTG-TEST-0052.

- **Auth material sent over insecure channels / in URL query strings.** Tokens/credentials carried on an ATS-excepted or cleartext path, or placed in a request **URL query string** (logged, cached, leaked via `Referer`) rather than headers/body over TLS. This is the AUTH×NETWORK cross-cut — report as a one-line cross-reference to the NETWORK cleartext checks, don't duplicate the whole check. → **MASWE-0037** (Authentication Material Sent over Insecure Connections). Lean on **MASTG-TEST-0321** (hardcoded HTTP URLs) / **-0322** (ATS cleartext) / **-0323** (low-level networking cleartext); no AUTH-specific atomic test → "auth material over insecure channel (ID to confirm)".

- **Client-side JWT/token validation (decode without verify).** If the app validates a JWT/token locally to gate behavior, flag decode-without-signature-verification, `alg=none` acceptance, or missing `exp`/`nbf`/`iss`/`aud` checks (e.g. parse-only paths in JOSE/JWT libs). Client-side validation never replaces server-side enforcement. → **MASWE-0038** (Authentication Tokens Not Validated). No iOS atomic test → cite control + "client-side token validation (ID to confirm)". *(Low frequency on iOS clients; one bullet — don't expand.)*

- **Auth/authz enforced only locally.** Logic that grants access or authorizes a sensitive operation purely on a client-side decision (a local boolean, a feature flag in storage) with no server check — bypassable by hooking/patching. → **MASWE-0041** (Authentication Enforced Only Locally) / **MASWE-0042** (Authorization Enforced Only Locally), both MASVS-AUTH-1. Statically you can only name the gate and mark **Needs dynamic verification**; no atomic static test → "local-only enforcement (ID to confirm)".

### AUTH-2 — local (biometric / passcode) authentication done securely

The secure iOS pattern ties the **release of a Keychain secret** to biometrics via `SecAccessControlCreateWithFlags`, evaluated by `LAContext`. A `LAContext.evaluatePolicy(...)` used purely as an `if authenticated { ... }` boolean gate is bypassable (hook the completion handler / patch the branch) — the offensive default to look for.

- **Event-bound biometric present at all (boolean-gate-only smell).** Grep the (decrypted) binary for `LocalAuthentication` use: `LAContext.evaluatePolicy`. Then check whether the sensitive secret is actually gated by a Keychain item created with `SecAccessControlCreateWithFlags` (`.biometryCurrentSet`/`.userPresence`) and retrieved via `SecItemCopyMatching` — i.e. event-bound to a crypto op — vs a bare boolean check with no Keychain binding. → **MASVS-AUTH-2** / **MASWE-0044** (Biometric Authentication Can Be Bypassed) / **atomic MASTG-TEST-0266** (References to APIs for Event-Bound Biometric Authentication, static; runtime counterpart **MASTG-TEST-0267**). Legacy **MASTG-TEST-0064** (Testing Biometric Authentication) is **deprecated/superseded** by the 0266–0271 atomic split — prefer the atomic test, note the legacy umbrella.

- **Fallback to non-biometric (passcode) where biometric-only required.** Flag `LAPolicy.deviceOwnerAuthentication` (allows device-passcode fallback) used where `...WithBiometrics` is required; a non-empty `localizedFallbackTitle`; or a `SecAccessControl` built with `.devicePasscode`/`.or` allowing passcode where biometric-only is the requirement. → **MASVS-AUTH-2** (local-auth strength) / **MASWE-0045** (Fallback to Non-biometric Credentials Allowed for Sensitive Transactions) / **atomic MASTG-TEST-0268** (References to APIs Allowing Fallback to Non-Biometric Authentication, static; runtime **MASTG-TEST-0269**). *(When the fallback specifically weakens a sensitive transaction/step-up flow, the statement also reads onto AUTH-3 — anchor by which control statement fits the finding.)*

- **Crypto keys not invalidated on new biometric enrollment.** Flag a `SecAccessControl` using `.biometryAny` (or legacy `kSecAccessControlTouchIDAny`) instead of `.biometryCurrentSet` — the key survives an attacker enrolling a new fingerprint/face. Also flag absence of any enrollment-change detection (`LAContext.evaluatedPolicyDomainState` comparison). → **MASVS-AUTH-2** / **MASWE-0046** (Crypto Keys Not Invalidated on New Biometric Enrollment) / **atomic MASTG-TEST-0270** (References to APIs Detecting Biometric Enrollment Changes, static; runtime **MASTG-TEST-0271**).

- **App custom PIN not bound to the Keychain/Secure Enclave.** An app-defined PIN/passcode validated in-app (compared to a stored value) rather than gating release of a Keychain item — bypassable and the PIN is at-rest. → **MASVS-AUTH-2** / **MASWE-0043** (App Custom PIN Not Bound to Platform KeyStore). No iOS MASTG test is linked to MASWE-0043 → cite control + "custom PIN not bound to Keychain (ID to confirm)".

### AUTH-3 — additional authentication for sensitive operations (step-up / MFA)

- **No step-up / re-authentication for sensitive actions.** Sensitive operations (money transfer, credential/email change, payment, disabling security settings) reachable without a fresh `LAContext.evaluatePolicy` / Keychain-gated re-auth — and no re-auth triggered after timeout, backgrounding, or other contextual state change. Statically: identify the sensitive action handlers and check for an adjacent re-auth call; mark **Needs dynamic verification** for the actual runtime gate. → **MASVS-AUTH-3** / **MASWE-0029** (Step-Up Authentication Not Implemented After Login) and **MASWE-0030** (Re-Authenticates Not Triggered On Contextual State Changes). No atomic static test → cite control + "missing step-up / re-auth (ID to confirm)".

- **MFA best practices not followed.** If the app implements MFA client-side, check it isn't reduced to a bypassable local check. → **MASVS-AUTH-3** / **MASWE-0028** (MFA Implementation Best Practices Not Followed). Largely server-side; statically flag only obvious client-side shortcuts, mark Needs dynamic verification. *(One bullet — don't expand; MFA correctness is a server/API concern.)*

---

## Classic false positives (MASVS-AUTH, iOS)
Consult before promoting a candidate. Each below is **usually NOT a finding** absent extra evidence:

| Candidate | Why it's usually a false positive | When it *is* real |
|---|---|---|
| "Hardcoded key/token in strings/symbols" on a FairPlay binary | If `cryptid=1`, the `__TEXT` strings are ciphertext — your read is invalid, not a finding | binary is decrypted (`cryptid=0`) and the secret is genuinely present |
| OAuth `client_id` / SHA-restricted public Google (`AIza…`) key / Firebase config `api_key` "leaked" | These are public-by-design identifiers, not authentication secrets | a server-side secret, private key, OAuth *client secret*, or live bearer/API token is present |
| `LAContext.evaluatePolicy` "biometric bypassable" | The secret is actually released by a Keychain item gated with `SecAccessControlCreateWithFlags` — biometrics gate a crypto op, not just a bool | it's a pure `if authenticated {}` boolean gate with no Keychain binding (hook/patch the branch) |
| Passcode fallback (`deviceOwnerAuthentication`) present | Acceptable when device-passcode fallback is the intended/accessible UX and the asset isn't high-value | biometric-only is required for a sensitive transaction (AUTH-3) yet passcode fallback is allowed |
| `.biometryAny` / no enrollment-change detection | Acceptable for low-value local convenience auth | high-value secret whose key must die on new biometric enrollment (`.biometryCurrentSet` expected) |
| Local-only auth/authz check | A defense-in-depth client check backed by real server-side enforcement | the client decision is the *only* gate (no server check) — bypassable by hooking |

When you dismiss a candidate, record it (and the reason) in the report's "candidates not promoted" appendix.
