# Android — MASVS-AUTH (static)

Static, client-side assessment of authentication/authorization handling in an Android artifact (`.apk` / `.aab` / extracted APK) — no device required; every item is a candidate until it clears the gate.
Anchor each finding to the exact control in SKILL.md (read it); verify MASWE/MASTG IDs against the live guide.

## Group controls (MASVS v2.0.0, verbatim)
- **MASVS-AUTH-1** — The app uses secure authentication and authorization protocols and follows the relevant best practices.
- **MASVS-AUTH-2** — The app performs local authentication securely according to the platform best practices.
- **MASVS-AUTH-3** — The app secures sensitive operations with additional authentication.

> Scope note: the **server owns authentication**. Statically you assess the **client's** handling — where credentials/tokens live, how they're validated and transmitted, and how local (biometric) auth and step-up are wired. Cross-anchor: token storage → MASVS-STORAGE; token transit → MASVS-NETWORK; the App-Link/deep-link leg of an OAuth redirect → MASVS-PLATFORM-1.

## Checks

### Token / session / credential handling (AUTH-1)
- **Where tokens/session material are stored** — long-lived bearer/refresh tokens, passwords, or session ids in plain `SharedPreferences`/files/SQLite. This is an **AUTH-1 + STORAGE-1** finding; anchor the *storage* defect to STORAGE-1 and the *auth-design* angle (token lifetime/rotation) to AUTH-1. → MASVS-AUTH-1 · MASWE-0036 "Authentication Material Stored Unencrypted on the Device" · MASTG-TEST-0017 "Testing Confirm Credentials" (legacy AUTH umbrella; atomic split pending — ID to confirm).
- **Token transit / leakage** — tokens placed in URL query strings (logged, cached, sent in `Referer`), or sent over cleartext/insecurely. Anchor transit to NETWORK; note the auth-material exposure as AUTH-1 cross-ref (don't double-count). → MASVS-AUTH-1 · MASWE-0037 "Authentication Material Sent over Insecure Connections" · MASTG-TECH-0021 (network sniffing — confirm dynamically; static is the lead only).
- **Token lifetime / rotation** — hardcoded never-expiring tokens, no refresh-token rotation, refresh token treated as a long-lived secret on disk. Distinct from generic cleartext: it's an auth-design weakness. → MASVS-AUTH-1 · MASWE: unmapped (relate MASWE-0036/-0037 — *verify live*) · descriptive: "client token lifetime/rotation review" (ID to confirm).

### Client-side authorization logic (AUTH-1)
- **Trust-boundary inversion** — decisions that must be server-enforced made (or enforceable) on the client: feature gating, `isAdmin`/`isPremium`/role flags, price/entitlement checks read from a response field or local store and trusted without server re-validation. Trivially bypassable by tampering/hooking → finding (severity rises under R and for sensitive functions). When the gate value comes from local storage with no integrity check, that's also **MASVS-CODE-4 / MASWE-0082** (local-storage integrity) — cross-ref. → MASVS-AUTH-1 · MASWE-0033 "Authentication or Authorization Protocol Security Best Practices Not Followed" · descriptive: "client-side authorization decision" (ID to confirm).

### OAuth2 / OIDC client (AUTH-1, RFC 8252)
- **Authorization-code + PKCE required** — for a public mobile client, require `response_type=code` with **PKCE `code_challenge_method=S256`**; flag the **implicit flow** (`response_type=token`), plain-`code` without PKCE, or `code_challenge_method=plain`. Statically: locate the AppAuth `AuthorizationRequest`/Custom Tabs builder (or hand-rolled `/authorize` URL construction) and inspect the parameters. → MASVS-AUTH-1 · MASWE-0033 "Authentication or Authorization Protocol Security Best Practices Not Followed" · descriptive: "OAuth public-client PKCE check" (ID to confirm).
- **Redirect URI hijack surface** — the `redirect_uri` must be a **verified App Link** (`autoVerify="true"` with hosted `assetlinks.json`), **not** a hijackable custom scheme or `http://localhost`/loopback that any installed app can claim. Trace the redirect scheme/host to the manifest `<intent-filter>` and confirm verification. The redirect-capture leg anchors to PLATFORM-1. → MASVS-AUTH-1 (protocol) + MASVS-PLATFORM-1 (interception) · MASWE-0033 · **MASTG-TEST-0028** "Testing Deep Links" (PLATFORM, for the App-Link/scheme leg).

### Client-side token / JWT validation (AUTH-1)
- **Decode-without-verify** — the app decodes a JWT/opaque token and trusts its claims **without verifying the signature**: jjwt `parseClaimsJwt(...)` (unsigned) vs `parseClaimsJws(...)` (verified); auth0 `JWT.decode(...)` used without a corresponding `.verify(...)`; Nimbus `SignedJWT.parse` with no `verify(verifier)`. → MASVS-AUTH-1 · MASWE-0038 "Authentication Tokens Not Validated" · descriptive: "client JWT signature verification" (atomic ID to confirm; relate MASWE-0038).
- **`alg=none` / algorithm-confusion acceptance** — verifier that accepts `alg: none`, or an HMAC verifier fed an RS256 token (key-confusion), or no `alg` allow-list. → MASVS-AUTH-1 · MASWE-0038 "Authentication Tokens Not Validated" · ID to confirm.
- **Missing claim checks** — token gates client behavior but `exp`/`nbf`/`iss`/`aud` are not validated (expired or wrong-audience tokens accepted). → MASVS-AUTH-1 · MASWE-0038 "Authentication Tokens Not Validated" · ID to confirm.

### Local (biometric) authentication (AUTH-2)
> The secure pattern **binds biometric auth to a cryptographic operation**: a Keystore key created with `setUserAuthenticationRequired(true)` and unlocked per-operation via a `BiometricPrompt.CryptoObject`. A `BiometricPrompt` that merely returns a success **boolean** (an "event-bound" UI gate) with no `CryptoObject`/key unlock is bypassable by hooking/patching the callback. Each knob below is its own atomic test.
- **Boolean-only gate (no crypto binding)** — `BiometricPrompt.authenticate(...)` called **without** a `CryptoObject`, or a key whose `KeyGenParameterSpec` has `setUserAuthenticationRequired(false)`. The presence of the correct event-bound/crypto pattern is what MASTG-TEST-0327 looks for; its **absence** is the finding. → MASVS-AUTH-2 · MASWE-0044 "Biometric Authentication Can Be Bypassed" · **MASTG-TEST-0327** "References to APIs for Event-Bound Biometric Authentication" (legacy umbrella MASTG-TEST-0018 "Testing Biometric Authentication").
- **Extended key validity duration** — `setUserAuthenticationValidityDurationSeconds(N>0)` (deprecated) or API 30+ `setUserAuthenticationParameters(N>0, ...)` makes a biometric-bound key usable for `N` seconds after *any* device unlock, decoupling it from a per-operation `CryptoObject` (use `-1`/per-use auth). → MASVS-AUTH-2 · MASWE-0046 "Crypto Keys Not Invalidated on New Biometric Enrollment" · **MASTG-TEST-0330** "References to APIs for Keys used in Biometric Authentication with Extended Validity Duration".
- **Key survives new biometric enrollment** — `setInvalidatedByBiometricEnrollment(false)` lets a biometric-bound key keep working after an attacker enrolls a new fingerprint/face. → MASVS-AUTH-2 · MASWE-0046 "Crypto Keys Not Invalidated on New Biometric Enrollment" · **MASTG-TEST-0328** "References to APIs Detecting Biometric Enrollment Changes".
- **Authentication without explicit user action** — passive auth accepted with no deliberate user gesture, e.g. `setConfirmationRequired(false)` for a passive (face/iris) modality, so a glance authorizes. → MASVS-AUTH-2 · MASWE-0044 "Biometric Authentication Can Be Bypassed" · **MASTG-TEST-0329** "References to APIs Enforcing Authentication without Explicit User Action".

### Fallback / step-up (AUTH-3)
- **Non-biometric fallback for sensitive transactions** — `setAllowedAuthenticators(... | DEVICE_CREDENTIAL)`, deprecated `setDeviceCredentialAllowed(true)`, or accepting `BIOMETRIC_WEAK` where `BIOMETRIC_STRONG` is required → PIN/pattern downgrade weakens a high-value action. → MASVS-AUTH-3 · MASWE-0045 "Fallback to Non-biometric Credentials Allowed for Sensitive Transactions" · **MASTG-TEST-0326** "References to APIs Allowing Fallback to Non-Biometric Authentication".
- **No step-up / re-auth on sensitive actions** — money transfer, credential/email change, payment, key export performed with no fresh `BiometricPrompt`/credential challenge. → MASVS-AUTH-3 · MASWE-0029 "Step-Up Authentication Not Implemented After Login" · descriptive: "missing step-up for sensitive action" (ID to confirm).
- **No re-auth on contextual state change** — session not re-validated after timeout/return-from-background/device-state change; long-lived in-memory session with no re-prompt. → MASVS-AUTH-3 · MASWE-0030 "Re-Authenticates Not Triggered On Contextual State Changes" · descriptive: "missing contextual re-authentication" (ID to confirm).

### Hardcoded API keys / tokens / credentials (AUTH-1)
- A **server API key, access token, or credential** baked into code/`res/`/`assets`/native strings that grants access on its own → AUTH-1 finding (this is *found* during code review but anchors to AUTH, **not** MASVS-CODE). Apply the FP gate below before promoting. Hardcoded **crypto** keys/IVs anchor to MASVS-CRYPTO-2 instead. → MASVS-AUTH-1 · MASWE-0005 "API Keys Hardcoded in the App Package" · descriptive: "hardcoded API key/token in package" (atomic ID to confirm; MASTG-TECH-0117 for manifest/string extraction).

## Classic false positives
Consult before promoting a candidate. Each below is **usually NOT a finding** absent extra evidence.

| Candidate | Why it's usually a false positive | When it *is* real |
|---|---|---|
| "Hardcoded API key" | It's an OAuth **client_id**, a package/SHA-restricted public Google key, Firebase config, or a **cert pin / public key** | it's a server secret / access token / private key granting access (→ AUTH-1, MASWE-0005) |
| `BiometricPrompt` "not crypto-bound" | App genuinely only needs a convenience UI gate (no sensitive data/key protected by it) and the server still enforces auth | the boolean gate protects a sensitive local key/action with no `CryptoObject` / `setUserAuthenticationRequired(true)` |
| `DEVICE_CREDENTIAL` allowed | Intended UX fallback on a **low-value** flow where PIN/pattern is acceptable | a **sensitive transaction** requires biometric-strong and accepts device credential / `BIOMETRIC_WEAK` (→ AUTH-3, MASWE-0045) |
| "Client checks isAdmin/role" | The client only *renders* UI from a flag and the **server re-validates** every privileged call | the client-side decision is the **only** gate (no server enforcement) → trivially tamperable |
| JWT present in code | App merely forwards an opaque token it never inspects | app **decodes and trusts** claims without signature/`exp`/`aud` verification (`parseClaimsJwt`, `JWT.decode` w/o `.verify`) |
| Custom-scheme OAuth redirect | Redirect is a **verified App Link** (`autoVerify` + hosted `assetlinks.json`) | redirect is an unverified custom scheme / `localhost` any app can claim → code interception |
