# iOS — MASVS-CODE (static)

Scope: static review of an iOS artifact (`.ipa` / `.app` / Mach-O) for platform currency, update enforcement, known-vulnerable dependencies, untrusted-input handling, unsafe deserialization, and compiler-provided memory-safety hardening — the things you read out of the binary, `Info.plist`, and dependency-manager artifacts without a device.

Anchor each finding to the exact control in SKILL.md (read it); verify MASWE/MASTG IDs against the live guide.

> Everything here is a **candidate generator** — promote to a finding only after the anti-false-positive gate in `SKILL.md`. **FairPlay caveat:** if the binary is encrypted (`cryptid=1`), `otool`/`nm`/`class-dump`/Ghidra read **ciphertext** for `__TEXT` — strings, symbols, deserialization sinks, hardening flags are all **invalid until decrypted** (see `references/ios-overview.md` Tools). Compiler-hardening flags (PIE/canary/ARC) are read from the Mach-O load commands/`__TEXT` and are also unreliable on an encrypted binary — decrypt first.

## Group MASVS controls (verbatim, MASVS v2.0.0)
- **MASVS-CODE-1** — The app requires an up-to-date platform version.
- **MASVS-CODE-2** — The app has a mechanism for enforcing app updates.
- **MASVS-CODE-3** — The app only uses software components without known vulnerabilities.
- **MASVS-CODE-4** — The app validates and sanitizes all untrusted inputs.

Anchor by *statement*, not by group. Common mis-anchors to avoid: hardcoded **API keys/tokens** → **MASVS-AUTH-1** (MASWE-0005), hardcoded **crypto keys/IVs** → **MASVS-CRYPTO-2** — you find these during code review but they do **not** anchor to CODE. `debuggable`/`get-task-allow`, anti-debug, jailbreak detection, obfuscation, symbol stripping → **MASVS-RESILIENCE** (R profile), not CODE.

---

## Checks

### CODE-1 — up-to-date platform version
- **Low deployment target** — `MinimumOSVersion` in `Info.plist` (and the Xcode deployment target) set to an old iOS major: the app keeps running on EOL OS versions that no longer receive security fixes. (`MASVS-CODE-1`, MASWE-0077 "Running on a recent Platform Version Not Ensured")
- **Latest platform not targeted** — built against an old SDK (`DTSDKName`/`DTPlatformVersion` / `LC_BUILD_VERSION` `sdk=` in `otool -l`): the app opts out of newer platform mitigations. (`MASVS-CODE-1`, MASWE-0078 "Latest Platform Version Not Targeted") — *fold into one bullet with the line above; do not expand.* (technique: Info.plist review MASTG-TECH-0153/-0154; binary build-version via "Application Binary review" MASTG-TECH-0070 (ID to confirm))

### CODE-2 — enforced update mechanism
- **No forced-update / kill-switch** — is there a server-driven minimum-version check that blocks an outdated client (and does every entry point pass through it, so it can't be bypassed)? Statically: look for a version/feature-flag fetch on launch and a hard gate. Absence is profile-dependent; report low unless the app handles high-value data. (`MASVS-CODE-2`, MASWE-0075 "Enforced Updating Not Implemented", `MASTG-TEST-0080` "Testing Enforced Updating" — legacy, slated for MASTG v2 overhaul)

### CODE-3 — components without known vulnerabilities
- **Enumerate embedded dependencies + exact versions** — list `Payload/<App>.app/Frameworks/*.framework` and `*.dylib`, statically-linked libs (symbol/string evidence), and Swift/ObjC runtime libs; then read the dependency-manager artifacts: `Package.resolved` (SwiftPM), `Podfile.lock` (CocoaPods), `Cartfile.resolved` (Carthage). For a shipped `.ipa` the **binary/SBOM is the reachable inventory** — source lockfiles may be absent and version info is frequently stripped at compile time, so embedded-framework enumeration is the fallback. (`MASVS-CODE-3`, MASWE-0076 "Dependencies with Known Vulnerabilities")
- **Generate a CycloneDX SBOM and diff against advisories** — build the SBOM (cdxgen for SwiftPM; note cdxgen does **not** cover CocoaPods/Carthage and skips SwiftPM transitive deps) or build-time from the package manager, then correlate every component+version against NVD/OSV/GitHub Advisories (e.g. dependency-track). Report the SBOM as a deliverable. (`MASVS-CODE-3`, MASWE-0076, `MASTG-TEST-0275` "Dependencies with Known Vulnerabilities in the App's SBOM" + `MASTG-TEST-0273` "Identify Dependencies with Known Vulnerabilities"; techniques `MASTG-TECH-0132` (SCA via SBOM) / `MASTG-TECH-0133` (SCA via package-manager artifacts); legacy umbrella `MASTG-TEST-0085` "Checking for Weaknesses in Third Party Libraries" — **deprecated**, superseded by -0273/-0275)
- **Reachability gate** — a CVE is a finding only if the vulnerable API is actually **reached** in this build. Confirm with xref from real entry points (URL-scheme / Universal Link / app-delegate handlers) to the vulnerable call: `class-dump` + Ghidra/radare2 `axt`/`axf` cross-references. Mark unreachable CVEs dismissed (defensible in the appendix). (gate per SKILL.md; reachability/xref technique `MASTG-TECH-0072` (Retrieving Cross References, iOS); binary review via `MASTG-TECH-0070`/`-0076`)

### CODE-4 — validate & sanitize all untrusted inputs
- **Unsafe object deserialization** — `NSKeyedUnarchiver(forReadingWith:)` / `unarchiveObject(with:)` / `unarchiveTopLevelObjectWithData` **without** `requiringSecureCoding = true`; classes adopting `NSCoding` instead of `NSSecureCoding`; and `NSKeyedUnarchiver` not constrained to an **allow-list of expected classes** (`decodeObject(of:forKey:)` / `unarchivedObject(ofClass(es):from:)`). On attacker-influenced bytes (URL scheme, `NSUserActivity`/Handoff, pasteboard, IPC/app-group file, network) this enables object-substitution → RCE. Also flag `PropertyListSerialization` / `JSONDecoder` / third-party decoders fed attacker bytes without validation. (`MASVS-CODE-4`, MASWE-0088 "Insecure Object Deserialization", `MASTG-TEST-0079` "Testing Object Persistence" — legacy umbrella; atomic successor to confirm)
- **Untrusted input by source (taxonomy)** — classify and trace each taint source to its sink; each source is its own MASVS-CODE-4 weakness: network (MASWE-0079), backups/restored data (MASWE-0080), external interfaces (MASWE-0081), local storage (MASWE-0082), UI (MASWE-0083), IPC — URL schemes / Universal Links / app extensions / app-group containers (MASWE-0084). At minimum treat URL-scheme params, Universal-Link path/query, pasteboard, and app-group/IPC bytes as untrusted. (`MASVS-CODE-4`; per-channel MASWE above; descriptive test name "Unsafe handling of untrusted input" (ID to confirm))
- **Injection / unsafe parsing** — attacker-controlled strings reaching `String(format:)` / `NSLog`/`os_log` with a non-literal format argument (format-string), `NSPredicate(format:)` built from user input (predicate injection), raw SQL string-concatenation into `sqlite3_exec`/FMDB instead of bound parameters (SQLi), and XML/plist parsing of untrusted documents with external-entity resolution enabled (XXE-style). (`MASVS-CODE-4`; SQLi → MASWE-0086 "SQL Injection"; format/predicate/XML parsing → MASWE-0087 "Insecure Parsing and Escaping"; descriptive test names (ID to confirm))
- **Memory-corruption / unsafe C on external input** — `strcpy`/`strcat`/`sprintf`/`memcpy`/`gets` on attacker-influenced buffers in bundled native code. Static can name the call site; deep exploitability is largely beyond static reach → name the function and mark **Needs dynamic verification**. (`MASVS-CODE-4`, MASWE-0087 / unmapped; descriptive test name (ID to confirm))
- **Compiler-provided hardening absent** — read the Mach-O for the three memory-safety mitigations; each missing one is statically detectable and decides native-bug exploitability:
  - **PIE/PIC** — `MH_PIE` flag in the Mach-O header (`otool -hv` / `rabin2 -I` `pic=true`); absence = fixed load address, easier ROP. (`MASVS-CODE-4`, MASWE-0116 "Compiler-Provided Security Features Not Used", `MASTG-TEST-0228` "Position Independent Code (PIC) not Enabled")
  - **Stack canaries** — presence of `__stack_chk_guard`/`__stack_chk_fail` symbols (`otool -Iv` / `nm`). Caveat: pure-Swift binaries legitimately omit canaries (memory-safe by design), and Swift-with-ObjC may not surface them via `otool` — do **not** flag a Swift app as missing canaries without C/C++/ObjC code present. (`MASVS-CODE-4`, MASWE-0116, `MASTG-TEST-0229` "Stack Canaries Not enabled")
  - **ARC** — Automatic Reference Counting enabled (`_objc_release`/`_objc_autoreleaseReturnValue` symbol evidence, `objc_msgSend` patterns); absence in ObjC code = manual retain/release memory-management bugs. (`MASVS-CODE-4`, MASWE-0116, `MASTG-TEST-0230` "Automatic Reference Counting (ARC) not enabled")
  - Technique: `MASTG-TECH-0118` "Obtaining Compiler-Provided Security Features". **Scope nuance:** PIE applies to the **main executable** only; frameworks/dylibs are checked separately — "no PIE on a dylib" is expected, not a finding (avoids a classic FP). These map to MASWE-0116, **not** the legacy CODE-1/CODE-2 framing.
- **Unsafe dynamic code loading** — `dlopen`/`dlsym`/`NSBundle.load()`/`objc_allocateClassPair` on writable or downloaded paths, JSPatch-style hot-patching, loading a downloaded `.dylib`: code from outside the signed bundle defeats integrity and is an injection sink. *(one bullet; dual RESILIENCE concern.)* (`MASVS-CODE-4`, MASWE-0085 "Unsafe Dynamic Code Loading"; descriptive test name (ID to confirm))
- **Endpoints / debug leftovers** — hardcoded hosts, staging/test code paths, verbose logging compiled into the release binary. (CODE context; if it aids reverse-engineering, **also** cross-ref MASVS-RESILIENCE-3 under an R engagement — do not write a separate section.)

---

## Classic false positives
Consult before promoting a candidate. Each below is **usually NOT a finding** absent extra evidence:

| Candidate | Why it's usually a false positive | When it *is* real |
|---|---|---|
| Strings/symbols/sinks "leaking" from a binary | If the binary is **FairPlay-encrypted** (`cryptid=1`), tool output is ciphertext — your read is invalid, not a finding | binary is decrypted (`cryptid=0`) and the construct genuinely exists |
| CVE in an embedded framework | Vulnerable path not reachable in this build | the vulnerable API is invoked with attacker-influenced input (confirm via xref) |
| "No stack canary" on a pure-Swift binary | Swift is memory-safe by design and legitimately omits canaries; `otool` may not surface them even when set | C/C++/ObjC code is present and the canary mitigation is genuinely absent |
| "No PIE" reported on a framework/dylib | PIE applies to the main executable; dylibs are checked separately | the **main executable** lacks `MH_PIE` |
| `NSKeyedUnarchiver` / `NSCoding` usage | Decoding app-generated, trusted, in-sandbox data with secure coding on | non-secure coding (no `requiringSecureCoding`/no class allow-list) on attacker-reachable bytes (URL scheme, Handoff, pasteboard, IPC) |
| `String(format:)` / `NSLog` with a format string | Format string is a compile-time literal | the format argument is attacker-controlled (format-string / injection) |
| Hardcoded API key / token found "in code" | This is **MASVS-AUTH-1** (MASWE-0005), not CODE; a crypto key/IV is **MASVS-CRYPTO-2** | — (re-anchor, don't drop; correct the group) |
| Old `MinimumOSVersion` | Broad device support is a product decision; alone it's Info-level | EOL OS target on an L2/high-value app where dropped mitigations matter |

When you dismiss a candidate, record it (and the reason) in the report's "candidates not promoted" appendix.
