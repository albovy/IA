# iOS — Static Analysis: overview, tools & pre-pass

Read this **first** for an `.ipa` / `.app` bundle / Mach-O. It covers tooling (incl. the FairPlay caveat), the
`Info.plist`/entitlements/Mach-O pre-pass, and **which per-group file to open next**. Everything is a
**candidate generator** — promote only after the anti-false-positive gate in `SKILL.md`. Anchor each finding to
the exact MASVS control (control list in `SKILL.md`) and **verify MASWE/MASTG IDs against the live guide**
(MASTG mid-refactor: legacy umbrellas + atomic 0200s/0300s coexist; prefer atomic, note the legacy umbrella).

> **FairPlay caveat — read first.** App Store binaries are DRM-encrypted (`LC_ENCRYPTION_INFO`, `cryptid=1`).
> `otool`/`nm`/`class-dump`/Ghidra read the on-disk file, so against an encrypted binary they see **ciphertext**
> for `__TEXT` — every static conclusion (strings, symbols, class dump, control flow) is **invalid until
> decrypted**. A static-only review of an App Store `.ipa` is fundamentally limited; say so, and decrypt first.

## 0. Fingerprint the framework FIRST
Determine native (ObjC/Swift) vs cross-platform (React Native, Flutter, Cordova, Unity, Xamarin, KMP). If
cross-platform, the logic + secrets live in the JS bundle / `libapp.so` / assemblies, not the Mach-O symbols
below → see `references/cross-platform-static.md` first.

## Tools & extraction (incl. FairPlay decryption)
An `.ipa` is a ZIP; the app is in `Payload/<App>.app/`. Compute SHA-256 of the analyzed artifact.

| Tool | Use |
|---|---|
| **otool** | `otool -l <bin> \| grep -i LC_ENCRYPTION` → detect FairPlay (`cryptid`); `-hv`/`-L` for header, linked libs. |
| **nm** | List Mach-O symbols. |
| **class-dump / class-dump-swift / dsdump** | Recover ObjC/Swift class & method declarations. |
| **plutil / PlistBuddy** | Inspect/convert `Info.plist` & entitlements (binary ⇄ XML/JSON). |
| **security** | macOS/iOS CLI for cert/Keychain inspection. |
| **Ghidra / radare2 (rabin2) / objdump** | Disassembly/decompilation; `rabin2 -I` confirms the binary is decrypted. |
| **swift-demangle / c++filt** | Demangle symbols. |
| **MobSF (iOS) / objection / semgrep** | Automated IPA static triage — every hit is a **candidate**. |
| **frida-ios-dump** | **Decrypt** a FairPlay binary on a jailbroken device, rebuild the IPA, verify `cryptid=0` with `rabin2`. |

> Hopper and `jtool2` appear in older guides but have no current `MASTG-TOOL` ID (`jtool2` ≈ replaced by
> `otool`/`radare2`/`ipsw`); use them if you have them, but cite the technique, not a tool ID.

Entry technique `MASTG-TECH-0066`; get/extract `MASTG-TECH-0054` ("Obtaining and Extracting Apps") — decrypting the FairPlay app binary is a sub-step inside it, not a separate titled technique; binary
review `MASTG-TECH-0070`/`-0075`/`-0076`; compiler hardening `MASTG-TECH-0118`.

## Pre-pass — Info.plist, entitlements, Mach-O
(Techniques: `MASTG-TECH-0153`/`-0154` Info.plist; `-0111` entitlements; `-0118` compiler features; `-0155` ATS.)

- **FairPlay / build type** — `cryptid=1` = encrypted (App Store); dev/ad-hoc/enterprise usually already decrypted. Record which.
- **Bundle id / version** — `CFBundleIdentifier`, `CFBundleShortVersionString` (+ build).
- **ATS** — `NSAppTransportSecurity` (`NSAllowsArbitraryLoads`, `NSExceptionDomains`, `NSAllowsArbitraryLoadsInWebContent`, `NSExceptionAllowsInsecureHTTPLoads`) → `ios/network.md`.
- **URL schemes / Universal Links** — `CFBundleURLTypes`/`CFBundleURLSchemes`; **Associated Domains** entitlement → `ios/platform.md`.
- **Purpose strings / permissions** — `NS*UsageDescription` vs actual use → `ios/privacy.md`.
- **Entitlements** — `get-task-allow` (debuggable!), keychain-access-groups, app groups, background modes. `get-task-allow=true` shipped → RESILIENCE.
- **Compiler hardening** — PIE, stack canaries, ARC (`MASTG-TECH-0118`) → `ios/code.md`.
- **Privacy manifest** — `PrivacyInfo.xcprivacy` (`MASTG-TECH-0136`/`-0137`) → `ios/privacy.md`.

## Router — open the group file for what you're checking
| Checking… | File |
|---|---|
| Keychain / Data Protection / storage / backups | `references/ios/storage.md` |
| Cryptography / key management (CommonCrypto/CryptoKit) | `references/ios/crypto.md` |
| Auth / tokens / biometrics (LocalAuthentication) | `references/ios/auth.md` |
| ATS / TLS / pinning | `references/ios/network.md` |
| URL schemes / Universal Links / WKWebView / extensions / pasteboard / UI exposure | `references/ios/platform.md` |
| Dependencies / deserialization / memory-corruption / compiler hardening | `references/ios/code.md` |
| Jailbreak / anti-debug / anti-hook / obfuscation (**R profile only**) | `references/ios/resilience.md` |
| Purpose strings / entitlements / trackers / privacy manifest | `references/ios/privacy.md` |
| Cross-platform app (RN/Flutter/Cordova/Unity/Xamarin) | `references/cross-platform-static.md` |
| Tooling, SBOM/SCA, reachability, secrets, Firebase | `references/static-tooling-and-methodology.md` |

**Full autonomous review** → walk all applicable group files (skip N/A; RESILIENCE only under R). **Targeted
assist** → open just the relevant file.
