# iOS — Static Analysis by MASVS Group

Static checks for an iOS artifact (`.ipa` / `.app` bundle / Mach-O). Work **group by group**. Everything here
is a **candidate generator** — promote to a finding only after the anti-false-positive gate in `SKILL.md`. Cite
the MASVS control as the anchor — **pick the exact control number from the MASVS control list in `SKILL.md`** —
and **verify MASWE/MASTG IDs against the live guide**. The MASTG is mid-refactor: legacy umbrella tests (e.g.
`MASTG-TEST-0052` storage, `-0062` key management, `-0068` pinning, `-0078` WebView, `-0075` URL schemes) are
being split into atomic, MASWE-mapped tests (0200s/0300s); both generations are live, so a finding may be
citable under either — prefer the atomic one and note the legacy umbrella. Live URL:
`https://mas.owasp.org/MASTG/tests/ios/<MASVS-CATEGORY>/<ID>/`.

> **FairPlay caveat — read this first.** App Store binaries are DRM-encrypted (`LC_ENCRYPTION_INFO`,
> `cryptid=1`). `otool`/`nm`/`class-dump`/Ghidra read the on-disk file, so against an encrypted binary they see
> **ciphertext** for the `__TEXT` executable region — every static conclusion (strings, symbols, class dump,
> control flow) is **invalid until the binary is decrypted**. So a static-only review of an App Store `.ipa` is
> fundamentally limited; say so, and decrypt before concluding (see Tools).

## Contents
- [Tools & extraction (incl. FairPlay decryption)](#tools--extraction-incl-fairplay-decryption)
- [Pre-pass — Info.plist, entitlements, Mach-O](#pre-pass--infoplist-entitlements-mach-o)
- [MASVS-PLATFORM](#masvs-platform)
- [MASVS-STORAGE](#masvs-storage)
- [MASVS-CRYPTO](#masvs-crypto)
- [MASVS-NETWORK](#masvs-network)
- [MASVS-AUTH (client side)](#masvs-auth-client-side)
- [MASVS-CODE](#masvs-code)
- [MASVS-RESILIENCE (R profile only)](#masvs-resilience-r-profile-only)
- [MASVS-PRIVACY](#masvs-privacy)
- [Classic false positives](#classic-false-positives)

---

## Tools & extraction (incl. FairPlay decryption)

An `.ipa` is a ZIP: `unzip` it; the app is in `Payload/<App>.app/`. Compute SHA-256 of the analyzed artifact.

| Tool | Use |
|---|---|
| **otool** | `otool -l <bin> \| grep -i LC_ENCRYPTION` → detect FairPlay (`cryptid`); `otool -hv`/`-L` for header, linked libs. |
| **nm** | List symbols/symbol table of the Mach-O. |
| **class-dump / class-dump-swift / dsdump** | Recover Objective-C/Swift class & method declarations from the binary. |
| **plutil / PlistBuddy** | Convert/inspect `Info.plist` & entitlements (binary ⇄ XML/JSON). |
| **security** | macOS/iOS CLI for cert/Keychain inspection. |
| **Ghidra / radare2 (rabin2) / objdump** | Disassembly/decompilation; `rabin2 -I` to confirm the binary is no longer encrypted. |
| **swift-demangle / c++filt** | Demangle symbols for readable review. |
| **MobSF (iOS) / objection / semgrep** | Automated IPA static triage — **every hit is a candidate**, confirm in the binary. |
| **frida-ios-dump** | **Decrypt** a FairPlay binary: run the app on a jailbroken device so iOS decrypts `__TEXT` into memory, dump the unencrypted image, rebuild the IPA, then verify `cryptid=0` with `rabin2`. |

> Hopper and `jtool2` appear in older guides but have no current `MASTG-TOOL` ID (`jtool2` is effectively
> replaced by `otool`/`radare2`/`ipsw`); use them if you have them, but cite the technique, not a tool ID.

Entry technique: `MASTG-TECH-0066` (Static Analysis on iOS). Get/extract/decrypt: `MASTG-TECH-0054` (Obtaining
and Extracting Apps — contains the "Decrypting the App Binary" section). Binary review: `MASTG-TECH-0070`
(Extracting Information from the Application Binary), `-0075`/`-0076` (reviewing decompiled/disassembled
ObjC/Swift), `-0118` (compiler security features: PIE/ARC/stack canaries).

---

## Pre-pass — Info.plist, entitlements, Mach-O

Read `Info.plist`, the embedded provisioning profile/entitlements, and Mach-O metadata first; it frames
everything. (Techniques: `MASTG-TECH-0153`/`-0154` Info.plist, `MASTG-TECH-0111` entitlements,
`MASTG-TECH-0118` compiler features, `MASTG-TECH-0155` ATS.)

- **FairPlay / build type** — `otool -l | grep LC_ENCRYPTION` → `cryptid=1` means encrypted (App Store build);
  a development/ad-hoc/enterprise build is usually already decrypted. Record which you have.
- **Bundle id / version** — `CFBundleIdentifier`, `CFBundleShortVersionString` (+ build).
- **ATS** — `NSAppTransportSecurity` dict: `NSAllowsArbitraryLoads`, `NSExceptionDomains`,
  `NSAllowsArbitraryLoadsInWebContent`, `NSExceptionAllowsInsecureHTTPLoads` (→ MASVS-NETWORK).
- **Custom URL schemes** — `CFBundleURLTypes` / `CFBundleURLSchemes`; **Associated Domains** entitlement for
  Universal Links (→ MASVS-PLATFORM).
- **Permissions / purpose strings** — `NS*UsageDescription` keys (camera, mic, location, contacts…) vs actual
  use (→ MASVS-PRIVACY).
- **Entitlements** — `get-task-allow` (debuggable!), keychain-access-groups, app groups, associated domains,
  background modes. `get-task-allow=true` on a shipped build is a RESILIENCE finding.
- **Compiler hardening** — PIE, stack canaries, ARC (`MASTG-TECH-0118`): absence weakens memory-safety posture.
- **Privacy manifest** — `PrivacyInfo.xcprivacy` (`MASTG-TECH-0136`/`-0137`): declared data types & tracking domains.

---

## MASVS-PLATFORM
*Safe interaction with the OS and other apps.* (Tests: `MASTG-TEST-0056` IPC; `-0075` Custom URL Schemes (deprecated → `-0370`/`-0371` input/source validation); `-0070` Universal Links; `-0076`/`-0077`/`-0078` WebViews; `-0073`/`-0276`–`0280` Pasteboard; `-0057`/`-0059` UI/screenshot exposure.)

- **Custom URL schemes** — registered handlers (`application(_:open:options:)`) that act on attacker-supplied
  URLs without **input/source validation** (any app can invoke a scheme; schemes aren't unique). (`MASTG-TEST-0370`/`-0371`, PLATFORM-1)
- **Universal Links** — `apple-app-site-association` correctly hosted/scoped; do handlers trust link params? (`MASTG-TEST-0070`)
- **WKWebView** — `MASTG-TEST-0078`: native methods exposed to JS via `JSExport`, `WKScriptMessageHandler`
  (`addScriptMessageHandler`), or `evaluateJavaScript` with untrusted input. File access:
  `allowFileAccessFromFileURLs`/`allowUniversalAccessFromFileURLs` private prefs, overly broad file read
  (`MASTG-TEST-0333`/`-0335`); attacker-controlled URI loaded (`MASTG-TEST-0332`); `UIWebView` (deprecated) usage. (PLATFORM-2)
- **App extensions / share / IPC** — data exposed via extensions, `UIActivity` sharing, `NSUserActivity`. (`MASTG-TEST-0072`/`-0071`/`-0056`)
- **Pasteboard (PLATFORM-3)** — sensitive data written to the **general** `UIPasteboard` (system-wide, readable
  by other apps; persists). (`MASTG-TEST-0073`/`-0276`)
- **UI exposure (PLATFORM-3)** — sensitive data in **auto-generated screenshots** (no blank/secure view on
  backgrounding) (`MASTG-TEST-0059`); keyboard cache on text fields not marked secure (`MASTG-TEST-0313`/`-0346`).

---

## MASVS-STORAGE
*Sensitive data at rest, and leakage.* (Tests: `MASTG-TEST-0052` local storage (legacy umbrella) → atomic `-0299`/`-0300`/`-0302`/`-0303`; logs `-0053`→`-0296`/`-0297`; backups `-0058`/`-0215`; keyboard cache `-0055`; third-party sharing `-0054`.)

First: **what is sensitive in THIS app?** Then check where it lands and how it's protected:
- **Keychain** — is sensitive data in the Keychain (right) and with the correct **accessibility class**?
  `kSecAttrAccessibleAlways`/`...AfterFirstUnlock` are weaker than `...WhenUnlockedThisDeviceOnly`. (CRYPTO/STORAGE)
- **Data Protection** — file `NSFileProtection` class / `kSecAttrAccessible` levels (`MASTG-TEST-0299`,
  STORAGE-1): files without `Complete`/`CompleteUnlessOpen` protection are readable when the device is locked.
- **Plaintext stores** — `NSUserDefaults`, `.plist`, Core Data / SQLite, cached files, `Documents`/`Library`
  holding secrets unencrypted (`MASTG-TEST-0300`/`-0302`).
- **Logs** — `NSLog`/`os_log`/`print` of sensitive data (`MASTG-TEST-0296`/`-0297`, STORAGE-2).
- **Backups** — sensitive files not excluded from iTunes/iCloud backup (`isExcludedFromBackup`) (`MASTG-TEST-0215`, STORAGE-2).
- **Keyboard cache / pasteboard / screenshots** — covered under PLATFORM-3 but they are STORAGE-2 leakage too.

---

## MASVS-CRYPTO
*Strong crypto, used correctly; sound key management.* (Tests: `MASTG-TEST-0061` algorithm config; `-0210` broken symmetric algos; `-0211` broken hashing; `-0317` broken modes; `-0209` weak key sizes; `-0062` key management; `-0213`/`-0214` hardcoded keys in code/files; `-0063`/`-0311` RNG.)

- **Weak/broken primitives** — DES/3DES/RC4, MD5/SHA-1 for security, via **CommonCrypto** (`CCCrypt`,
  `kCCAlgorithmDES`) or third-party libs.
- **Insecure modes/padding** — ECB; static/zero IV with CBC. (`MASTG-TEST-0317`)
- **Hardcoded keys/IVs/salts** — literals in code or resources (`MASTG-TEST-0213`/`-0214`, anchor `MASVS-CRYPTO-2`).
- **Bad RNG** — non-CSPRNG (`rand()`/`arc4random()` misuse for keys) instead of `SecRandomCopyBytes`. (`MASTG-TEST-0063`)
- **CryptoKit / Keychain key mgmt** — keys generated/stored without Secure Enclave / proper accessibility;
  key derivation with weak params. (`MASTG-TEST-0062`, CRYPTO-2)

---

## MASVS-NETWORK
*Secure data in transit.* (Tests: `MASTG-TEST-0322` ATS cleartext config (static, `MASWE-0050`); `-0342` weak ATS TLS exceptions; `-0321` hardcoded HTTP URLs; `-0343`/`-0344`/`-0345` TLS config; `-0068` pinning (legacy) → `MASWE-0047`/`-0052`; `-0067` endpoint identity (deprecated).)

- **ATS** — `NSAllowsArbitraryLoads=true` (disables ATS globally) or per-domain
  `NSExceptionAllowsInsecureHTTPLoads`/weak `NSExceptionMinimumTLSVersion` in `Info.plist`. Reachable cleartext
  to a real endpoint = finding; a blanket exception with no cleartext endpoint is weaker/Info. (`MASTG-TEST-0322`/`-0342`, NETWORK-1)
- **Hardcoded `http://` URLs** — (`MASTG-TEST-0321`).
- **Pinning** — present? For which endpoints? (`URLSession` delegate `didReceiveChallenge`, TrustKit, AFNetworking
  pinning). Missing pinning is profile-dependent (expected at L2/R). (`MASTG-TEST-0068`, NETWORK-2)
- **Endpoint verification disabled** — custom `URLSessionDelegate` accepting any server trust
  (`completionHandler(.useCredential, URLCredential(trust:))` unconditionally) → MITM. (NETWORK-1)
- **Outdated TLS** — explicit < TLS 1.2 in `URLSession`/`Network.framework`/embedded stack. (`MASTG-TEST-0343`/`-0344`/`-0345`)

---

## MASVS-AUTH (client side)
*Client-side handling of auth/authz.* (Test: `MASTG-TEST-0064` biometric auth; controls MASVS-AUTH-1/2.)

- **Token/session handling** — where tokens are stored (→ Keychain vs plist), logged, or sent.
- **Hardcoded API keys/credentials** — anchor `MASVS-AUTH-1` (`MASWE-0005`), not CODE.
- **Biometrics (LocalAuthentication)** — `LAContext.evaluatePolicy` used purely as a boolean gate (bypassable
  by hooking) **without** binding to a Keychain item protected by `SecAccessControlCreateWithFlags`
  (`.biometryCurrentSet`/`.userPresence`). The secure pattern ties the secret's release to biometrics. (`MASTG-TEST-0064`, AUTH-2)

---

## MASVS-CODE
*Up-to-date platform, dependencies, input handling, memory safety.* (Tests: `MASTG-TEST-0079` object persistence/deserialization; `-0080` enforced updating; `-0085`/`-0273`/`-0275` third-party libs & SBOM; `-0086` memory-corruption; `-0087`/`-0228`/`-0229`/`-0230` PIE/canary/ARC.)

- **Unsafe deserialization** — `NSKeyedUnarchiver` (non-secure), `NSCoding` without `NSSecureCoding`, on
  attacker-influenced data (incl. via URL schemes / IPC). (`MASTG-TEST-0079`, CODE-4)
- **Third-party libs + CVEs** — identify embedded frameworks and **versions**; a CVE is a finding only if the
  vulnerable path is **reachable**. (`MASTG-TEST-0085`/`-0273`, CODE-3)
- **Memory-corruption / unsafe C** — `strcpy`/`sprintf`/`memcpy` on external input in native code; missing
  PIE/stack-canary/ARC (`MASTG-TEST-0228`/`-0229`/`-0230`, `MASTG-TECH-0118`). Deep memory-safety is largely
  beyond static reach → name the function and mark **Needs dynamic verification**.
- **Endpoints / debug leftovers** — hardcoded hosts, debug/test code, verbose logging.

---

## MASVS-RESILIENCE (R profile only)
*Resistance to reverse engineering & tampering.* **Assess only under R.** (Tests: `MASTG-TEST-0088`/`-0240` jailbreak detection; `-0089` anti-debugging; `-0090` file integrity; `-0091` RE-tool detection; `-0092` emulator detection; `-0093` obfuscation; `-0081` signing; `-0082`/`-0261` debuggable / `get-task-allow`.)

Under R, *absence* of these is the finding (defense-in-depth, never a substitute for L1/L2 controls):
- **Jailbreak detection** — presence and robustness (single-point checks are trivially bypassed). (`MASTG-TEST-0088`)
- **Anti-debugging** — `ptrace(PT_DENY_ATTACH)`, `sysctl` checks. (`MASTG-TEST-0089`)
- **Anti-tampering / integrity** — code-signature/file-integrity self-checks; `get-task-allow`/debuggable on a
  release build is a real finding here (`MASTG-TEST-0082`/`-0261`, anchor `MASVS-RESILIENCE-4`).
- **Anti-hook / emulator detection**; **obfuscation** — is the binary obfuscated, or is logic/strings fully readable?

---

## MASVS-PRIVACY
*Minimize/protect personal data; transparency.* (Tests: `MASTG-TEST-0281` undeclared tracking domains; `-0360`/`-0362` purpose-string / entitlement justification; control MASVS-PRIVACY-1.)

- **Permissions vs use** — `NS*UsageDescription` purpose strings present and accurate vs the resources actually
  accessed; entitlements vs needed capabilities. (`MASTG-TEST-0360`/`-0362`)
- **Privacy manifest** — `PrivacyInfo.xcprivacy` declared data types/tracking vs reality.
- **Tracking SDKs / identifiers** — IDFA/IDFV, fingerprinting, undeclared tracking domains (`MASTG-TEST-0281`); exfiltration to unexpected endpoints.

---

## Classic false positives
Consult before promoting a candidate. Each below is **usually NOT a finding** absent extra evidence:

| Candidate | Why it's usually a false positive | When it *is* real |
|---|---|---|
| "Binary unencrypted / no obfuscation" | A development/ad-hoc build is decrypted by design; obfuscation isn't required under L1/L2 | required & absent under the **R** profile |
| `NSAllowsArbitraryLoads` "ATS disabled" | Sometimes set but no cleartext endpoint is actually used; or scoped to a WebView-content exception | a real `http://` endpoint is reached, or it's a blanket production exception |
| Strings/symbols "leaking" from a binary | If the binary is **FairPlay-encrypted** (`cryptid=1`), tool output is ciphertext — your read is invalid, not a finding | binary is decrypted (`cryptid=0`) and the secret is genuinely present |
| MD5/SHA-1 in CommonCrypto | Used for a checksum/cache key | used for signatures/password hashing/integrity of trusted data |
| Custom URL scheme "hijackable" | Handler validates input/source and does nothing sensitive | handler acts on attacker URL params without validation |
| `get-task-allow=true` | Expected in a development/debug build | present in the shipped/release artifact (RESILIENCE) |
| CVE in an embedded framework | Vulnerable path not reachable | the vulnerable API is actually invoked with attacker-influenced input |
| Missing pinning | Acceptable under **L1** | expected & absent under **L2/R**, or high-value data |

When you dismiss a candidate, record it (and the reason) in the report's "candidates not promoted" appendix.
