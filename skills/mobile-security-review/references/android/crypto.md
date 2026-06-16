# Android — MASVS-CRYPTO (static)

Static checks for cryptographic primitives, modes, randomness, and key management in an Android artifact (`.apk` / `.aab` / extracted APK), read from decompiled Java/Kotlin (jadx), smali, `res/`, `assets/`, and native `.so`. Fully automated, no device required. Every item is a **candidate generator** — promote to a finding only after the anti-false-positive gate in `SKILL.md`.

Anchor each finding to the exact control in SKILL.md (read it); verify MASWE/MASTG IDs against the live guide.

## Group controls (verbatim, MASVS v2.0.0)

- **MASVS-CRYPTO-1** — The app employs current strong cryptography and uses it according to industry best practices. *(weak algos/modes, ECB, MD5/SHA-1 for security, predictable IVs, bad RNG, weak/missing MAC, risky padding)*
- **MASVS-CRYPTO-2** — The app performs key management according to industry best practices. *(hardcoded keys/IVs/salts, weak key generation/derivation, insufficient key sizes, Keystore misuse, keys not protected at rest, keys reused across purposes)*

> Pick the sub-control by **statement match**, not by group alone: *how crypto is used* (algorithm, mode, IV, RNG, MAC, padding) → **CRYPTO-1**; *how key material is generated, derived, sized, stored, scoped, or reused* → **CRYPTO-2**. When a weakness touches both (e.g. a hardcoded key used in ECB), anchor to the dominant defect and note the secondary.

> ID status: legacy narrative tests (MASTG-TEST-0013/-0014/-0015/-0016) and atomic tests (0200+/0300+) coexist; prefer the atomic successor and note the legacy umbrella. Live URL: `https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/<ID>/`. MASWE: `https://mas.owasp.org/MASWE/MASVS-CRYPTO/<ID>/`.

---

## Checks

**Primitives / algorithms**

- **Weak or broken symmetric algorithms** — `Cipher.getInstance(...)` / `KeyGenerator.getInstance(...)` / `SecretKeySpec(..., "DES"|"DESede"|"RC4"|"ARCFOUR"|"Blowfish"|"RC2")`. DES/3DES, RC4, Blowfish, RC2 are broken/deprecated. → **MASVS-CRYPTO-1**, MASWE-0020 (Improper Encryption), **MASTG-TEST-0221** (Broken Symmetric Encryption Algorithms); legacy MASTG-TEST-0013 (Testing Symmetric Cryptography), -0014 (algorithm config).
- **MD5 / SHA-1 used for a security purpose** — `MessageDigest.getInstance("MD5"|"SHA-1")`, `Mac` with these, or any digest backing signatures, password hashing, or integrity of trusted data. MD5/SHA-1 as a non-security checksum, cache key, or ETag is **not** a finding. → **MASVS-CRYPTO-1**, MASWE-0021 (Improper Hashing), MASTG "Broken Hashing Algorithms" descriptive test **(ID to confirm — the confirmed atomic `MASTG-TEST-0211` Broken Hashing Algorithms is the iOS test; the Android equivalent ID could not be confirmed against the live catalog)**; legacy MASTG-TEST-0014.

**Modes / padding / IVs**

- **Insecure mode — ECB / implicit-default** — `Cipher.getInstance("AES/ECB/...")` (ECB leaks plaintext structure), or bare `Cipher.getInstance("AES")` / `"AES/CBC/PKCS5Padding"` with no explicit authenticated mode (Android's default transformation resolves to ECB → flag the missing explicit secure mode). Prefer AES-GCM/AES-CCM. → **MASVS-CRYPTO-1**, MASWE-0020 (Improper Encryption), **MASTG-TEST-0232** (Broken Symmetric Encryption Modes); runtime confirmation MASTG-TEST-0350.
- **Static / zero / reused IV** — `IvParameterSpec(new byte[16])`, a hardcoded byte[] IV literal, or the same IV across encryptions; CBC with a fixed IV, or **GCM/CTR nonce reuse** (catastrophic — leaks the auth key for GCM). → **MASVS-CRYPTO-1**, MASWE-0022 (Predictable Initialization Vectors), **MASTG-TEST-0309** (References to Reused IVs in Symmetric Encryption); runtime MASTG-TEST-0310.
- **Risky padding (padding-oracle exposure)** — AES-CBC + PKCS#7/PKCS5 where decrypt errors are distinguishable (no authenticated mode, no separate MAC). → **MASVS-CRYPTO-1**, MASWE-0023 (Risky Padding), MASTG "Risky Padding" descriptive test **(ID to confirm — no atomic Android test confirmed in the live catalog)**.

**MAC / authenticated encryption**

- **Missing or improper MAC (unauthenticated encryption)** — CBC/CTR with no separate HMAC, encrypt-then-nothing, MAC built on MD5/SHA-1, CRC32 used as an integrity check, or truncated tags on data that is trusted after decryption. → **MASVS-CRYPTO-1**, MASWE-0024 (Improper Use of Message Authentication Code), MASTG "Improper MAC" descriptive test **(ID to confirm — no atomic Android test confirmed)**.

**Randomness**

- **Bad RNG for crypto** — `java.util.Random`, `Math.random()`, time-based or otherwise low-entropy seeds used to generate keys/IVs/nonces/tokens/salts; use `java.security.SecureRandom`. Also `SecureRandom.setSeed(constant)` (overriding entropy) and the deprecated `Crypto`/`SHA1PRNG` provider. → **MASVS-CRYPTO-1**, MASWE-0027 (Improper Random Number Generation), **MASTG-TEST-0204** (Insecure Random API Usage) + **MASTG-TEST-0205** (Non-random Sources Usage); legacy MASTG-TEST-0016 (Testing Random Number Generation).

**Key management (CRYPTO-2)**

- **Hardcoded keys in code** — `SecretKeySpec(<literal byte[]/String>, ...)`, `IvParameterSpec` from a literal, or key/PBKDF-salt string constants in code or `res/`/`assets/`. → **MASVS-CRYPTO-2**, MASWE-0013 (Hardcoded Cryptographic Keys in Use), **MASTG-TEST-0212** (Use of Hardcoded Cryptographic Keys in Code); demo MASTG-DEMO-0017 (hardcoded AES key in `SecretKeySpec`, semgrep). *(Note: the live catalog maps -0212 to MASWE-0013, which is current — not merged into MASWE-0014; MASWE-0014 covers keys-not-protected-at-rest, a distinct weakness.)*
- **Keys/secrets bundled in the package** — keystores, `.pem`/`.p12`/`.jks`, config with key material in `res/raw`, `assets/`, or string resources. → **MASVS-CRYPTO-2**, MASWE-0014 (Cryptographic Keys Not Properly Protected at Rest); discovery via MASTG-TECH-0117 (AndroidManifest/resources). *(A bundled key granting server/API access re-anchors to MASVS-AUTH-1 / MASWE-0005 — classify by what it unlocks.)*
- **Weak key generation** — keys built from predictable material (device ID, package name, constant), `KeyGenerator` without explicit secure size, or homemade key schedules. → **MASVS-CRYPTO-2**, MASWE-0009 (Improper Cryptographic Key Generation), MASTG "Improper key generation" descriptive test **(ID to confirm)**.
- **Weak key derivation (KDF/PBKDF)** — `PBEKeySpec` with low iteration count, missing or static salt, short derived-key length, or a raw password used directly as a key (`SecretKeySpec(password.getBytes(), ...)` / `CC_SHA256(password)`-style). → **MASVS-CRYPTO-2**, MASWE-0010 (Improper Cryptographic Key Derivation), MASTG "Weak KDF / PBKDF parameters" descriptive test **(ID to confirm — no atomic Android test confirmed)**.
- **Insufficient key sizes** — RSA/DSA/DH < 2048-bit, EC < 224-bit, AES < 128-bit (check `KeyGenParameterSpec.setKeySize`, `KeyPairGenerator.initialize`, `RSAKeyGenParameterSpec`). → **MASVS-CRYPTO-2**, MASWE-0009 (Improper Cryptographic Key Generation), **MASTG-TEST-0208** (Insufficient Key Sizes).
- **Android Keystore misuse** — keys that should be hardware-backed kept in software/SharedPreferences; `KeyGenParameterSpec` with `setUserAuthenticationRequired(false)` for high-value keys, no `setUnlockedDeviceRequired(true)`, or purposes too broad (`PURPOSE_ENCRYPT | PURPOSE_DECRYPT | PURPOSE_SIGN`). *(The biometric/auth-validity knobs — `setUserAuthenticationValidityDurationSeconds`, `setInvalidatedByBiometricEnrollment` — anchor to MASVS-AUTH-2; see the AUTH reference.)* → **MASVS-CRYPTO-2**, MASWE-0014 (Cryptographic Keys Not Properly Protected at Rest) / MASWE-0018 (Cryptographic Keys Access Not Restricted); legacy MASTG-TEST-0015 (Testing the Purposes of Keys).
- **Deprecated / software KeyStore type** — `KeyStore.getInstance("BKS"|"BC"|"PKCS12"|"BouncyCastle")` or a file/software-backed keystore used to protect secrets instead of the hardware-backed `"AndroidKeyStore"` provider → keys are not hardware-backed and are extractable from the artifact/storage. Static provider-string check. → **MASVS-CRYPTO-2**, MASWE-0015 (Deprecated Android KeyStore Implementations), descriptive test "deprecated KeyStore type" (ID to confirm).
- **Key reused across purposes** — one key for both encrypt and MAC, or sign and encrypt (violates NIST SP 800-57 key separation). → **MASVS-CRYPTO-2**, MASWE-0012 (Insecure or Wrong Usage of Cryptographic Key), **MASTG-TEST-0307** (References to Asymmetric Key Pairs Used For Multiple Purposes); runtime MASTG-TEST-0308.

**Provider selection**

- **Explicit security-provider pinning** — passing a `provider` argument to `Cipher`/`MessageDigest`/`KeyGenerator.getInstance(transform, provider)` (e.g. forcing `"BC"`/Bouncy Castle) instead of letting the platform pick, which can lock the app to an outdated/vulnerable provider. Keystore code (`"AndroidKeyStore"`) is the legitimate exception. → **MASVS-CRYPTO-1**, MASWE-0019 (Risky Cryptography Implementations) **(MASWE mapping to confirm)**, **MASTG-TEST-0312** (References to Explicit Security Provider in Cryptographic APIs).

---

## Classic false positives
Consult before promoting a candidate. Each below is **usually NOT a finding** absent extra evidence:

| Candidate | Why it's usually a false positive | When it *is* real |
|---|---|---|
| MD5 / SHA-1 detected | Used for a checksum, cache key, ETag, dedup, or other non-security hash | Used for signatures, password hashing, or integrity of trusted data |
| "Hardcoded key" string | It's a cert pin / public key, OAuth `client_id`, or other **public** value (not secret) | It's a symmetric key, private key, or PBKDF salt that protects real data |
| `java.util.Random` present | Used for non-security purposes (UI jitter, shuffle, backoff jitter, retry timing) | Used to generate keys, IVs, nonces, salts, session tokens, or OTPs |
| AES with no mode shown in source | A wrapper/library actually sets an explicit secure mode downstream — trace the full call | Bare `Cipher.getInstance("AES")` / explicit `"AES/ECB/..."` reaches real sensitive data |
| Provider argument passed | It's `"AndroidKeyStore"` for Keystore operations (required, legitimate) | A non-Keystore provider (e.g. legacy Bouncy Castle) is pinned, freezing crypto to it |
| Weak primitive in a bundled lib | The vulnerable crypto path is dead / unused in this app | The weak primitive is invoked on this app's sensitive data |

When you dismiss a candidate, record it (and the reason) in the report's "candidates not promoted" appendix — that transparency is part of an honest deliverable.
