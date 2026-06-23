# iOS — Dynamic Analysis (confirm static **and** discover runtime-only)

**Purpose.** Dynamic analysis on iOS does **two** jobs:
1. **Confirm** what the static pass (`ios-overview.md` / `references/ios/*.md`) flagged and **fuse** it with
   static to raise confidence — the static-confirmation lane.
2. **Discover** runtime-only issues static cannot reach — live API/business-logic on the wire, secrets in
   process memory, session/token handling, live IPC/deep-link exploitation, WebView JS-bridge calls, biometric
   bypass, runtime crypto misuse, anti-instrumentation behaviour — the **offensive/discovery lane**.

On iOS, dynamic is frequently the **PRIMARY** lane, not a follow-up: a static review of a **FairPlay-encrypted**
App Store binary reads ciphertext, so instrumentation is the only way to see real behaviour (see
**FairPlay-primary lane** below).

> **Human-in-the-loop & authorization (Rule Zero).** Requires a **prepared, dedicated test device** and an
> **operator exercising the app's flows**. Re-confirm authorization/scope **before instrumenting**; bypass
> techniques are for **authorized testing only**. **Never fabricate dynamic results** — anything not actually run
> stays `Needs dynamic verification`. Severity = impact × exploitability **in this app**, modulated by the MAS
> profile (L1 / L2 / R).

---

## Preconditions
- **Device**: a **jailbroken** iOS device (privileged access, no code-signing restrictions; `frida-server`
  handles injection even into encrypted apps — entry technique **`MASTG-TECH-0067`** *Dynamic Analysis on iOS*).
  **Non-jailbroken** path: repackage with the **Frida Gadget** (**`MASTG-TECH-0090`** *Injecting Frida Gadget
  into an IPA Automatically* via Sideloadly/objection; `-0091` manual `.dylib`) and launch in debug mode with
  `get-task-allow` (**`MASTG-TECH-0055`** *Launching a Repackaged App in Debug Mode*) — only works if the binary is **not** FairPlay-encrypted. Umbrella for
  this whole non-JB path: **`MASTG-TECH-0146`** *Dynamic Analysis on Non-Jailbroken Devices*. (The **iOS
  Simulator is not an emulator** — x86 debug builds only; **Corellium** is the only public iOS "emulator", covered under
  `MASTG-TECH-0088` *Emulation-based Analysis*.)
- **Shell / frida-server over SSH**: device shell via SSH (`MASTG-TECH-0052`); SSH-over-USB with **iproxy**
  (`iproxy 2222 22` then `ssh root@127.0.0.1 -p 2222`). Install/manage with **ios-deploy** / **libimobiledevice**
  (`ideviceinstaller`, `idevice_id`).
- **Interception**: Burp / **mitmproxy** with its **CA installed and trusted** on iOS
  (**`MASTG-TECH-0063`** *Setting up an Interception Proxy*); set a global proxy under Settings → Wi-Fi, or
  tunnel over the SSH-USB connection. **iOS CA full-trust is a two-step** — see false positives.
- **Debugging**: `lldb` + `debugserver` re-signed with `task_for_pid-allow` (**`MASTG-TECH-0084`** *Debugging*).
- **Patching** (offensive): `get-task-allow` patch / binary patch to defeat pinning or anti-debug —
  **`MASTG-TECH-0147`** *Patching*.
- iOS has **no procfs** and lacks `lsof`/`vmmap` by default (install via Cydia on a jailbroken device).

## Tooling
| Tool | Use |
|---|---|
| **frida / frida-server (iOS)** | Hook ObjC/Swift/native; bypass pinning, jailbreak & biometric checks; method/native trace. |
| **objection (iOS)** | `ios sslpinning disable`, `ios ui biometrics_bypass`, `ios keychain dump`, `memory dump all`, `ios nsuserdefaults get`. |
| **r2frida** | Runtime RE (**`MASTG-TECH-0097`**): memory maps (`:dm`), in-memory search/dump, live disassembly. |
| **frida-trace** | `MASTG-TECH-0086` Method Tracing / `MASTG-TECH-0087` Native Code Tracing (`-m '-[NSURLSession *]'`, `-i 'CCCrypt'`). |
| **Burp / mitmproxy** | MITM HTTP(S); confirm cleartext / whether pinning blocks interception; capture live API (`MASTG-TECH-0063`). |
| **rvictl + Wireshark** | Low-level / non-URLSession sniffing ATS doesn't cover (**`MASTG-TECH-0062`** Basic Network Monitoring/Sniffing). |
| **SSL Kill Switch 2** | Jailbroken-only system-wide pinning bypass — *one technique within* `MASTG-TECH-0064` (Bypassing Certificate Pinning). |
| **Frida CodeShare** | `frida --codeshare` community SSL-pinning / JB-detection bypass scripts for non-standard implementations. |
| **frida-ios-dump** | Decrypt a FairPlay IPA from memory (`MASTG-TECH-0054`); verify `cryptid=0` with `rabin2 -I` afterwards. |
| **lldb** | Debugger (`MASTG-TECH-0084`); `debugserver` must be re-signed with `task_for_pid-allow`. |
| **Safari Web Inspector / GlobalWebInspect** | Inspect `WKWebView` (`MASTG-TECH-0139` *Attach to WKWebView*); since **iOS 16.4** apps must set `isInspectable=true` (GlobalWebInspect forces it on jailbroken devices). |

> **Cycript is deprecated** (broke on iOS 12; superseded by Frida) — don't rely on it; use Frida/Frida-cycript.

---

## FairPlay-primary lane (iOS-specific: dynamic is the ONLY lane)
For an App Store IPA the static read was on **ciphertext**. Make decrypt-then-instrument the explicit primary
discovery flow:
1. **Inject without decrypting first** — `frida-server` attaches to the encrypted process
   (`MASTG-TECH-0067`); much runtime work needs no decrypted binary at all.
2. **Enumerate live classes/methods** — `ObjC.enumerateLoadedClasses()` / `$ownMethods`
   (**`MASTG-TECH-0094`** *Getting Loaded Classes and Methods dynamically*) to find bridge/handler/crypto/auth
   class names that were unreadable statically.
3. **Trace the interesting methods** — `frida-trace` (`MASTG-TECH-0086`/`-0087`) on the enumerated selectors.
4. **Decrypt only when you must read `__TEXT`** — frida-ios-dump (`MASTG-TECH-0054`), then **confirm decryption
   with `rabin2 -I <bin>` → `crypto false` / `cryptid 0`** before trusting any in-memory `__TEXT` read.
This is the one place the dynamic lane is **not** confirming static — it **is** the only lane.

---

## Per-area runtime checks (candidate generators — MASVS → MASWE → MASTG → command)

Each row is a runtime candidate, not a confirmed finding. Run it, observe, then write the finding. iOS atomic
runtime tests live in the `Runtime Use of …` family (verified live on `mas.owasp.org`, June 2026).

### STORAGE — MASVS-STORAGE-1/2
| Check | Trace | Run |
|---|---|---|
| App writes sensitive data **unencrypted** to private storage at runtime | STORAGE-1 → MASWE-0006 → **`MASTG-TEST-0301`** *Runtime Use of APIs for Storing Unencrypted Data in Private Storage* (pairs static `-0300`) | Hook write APIs: `objection ... ios nsuserdefaults get`; frida-hook `-[NSData writeToFile:]`, `NSUserDefaults setObject:forKey:`, SQLite/CoreData. Exercise the flow, then read `Documents/`, `Library/`. |
| Sensitive data **confirmed on disk** in private files | STORAGE-1 → MASWE-0006 → **`MASTG-TEST-0302`** *Sensitive Data Unencrypted in Private Storage Files* (pairs static `-0300`) | After exercising, pull the container (`objection ... env`, then `frida-ios-dump`/SSH) and grep the files for the marker secret. |
| **Data-protection class effective while locked** (read a "protected" file with the device locked) | STORAGE-1 → MASWE-0006 → **`MASTG-TEST-0299`** *Data Protection Classes for Files in Private Storage* (runtime sibling of static `-0300`; static API-ref pair `MASTG-TEST-0300`) | Runtime-only angle: static only reads the *declared* `NSFileProtection` attribute — runtime proves whether the file is **actually unreadable while locked**. Lock the device (or simulate post-first-unlock evicted state), then attempt to read the target file over SSH/`frida` while locked: `ls -lO` the file, check the protection class via `frida` hooking `-[NSFileManager attributesOfItemAtPath:error:]` (look for `NSFileProtectionKey`), and try `cat`/`NSData dataWithContentsOfFile:` while locked. Readable-while-locked = weak class (`None`/`UntilFirstUserAuthentication`) regardless of what the source claimed. |
| **Backup-eligibility at runtime** (file actually flows into a backup) | STORAGE-2 → MASWE-0004 → **`MASTG-TEST-0298`** *Runtime Monitoring of Files Eligible for Backup* (runtime sibling of static `-0215`) | Runtime-only angle: static checks for the `isExcludedFromBackup` flag in code — runtime confirms the flag is **set on the live file** at write time. Exercise the flow, then hook/read the resource value: `frida` hook `-[NSURL resourceValuesForKeys:error:]` / `setResourceValue:forKey:` for `NSURLIsExcludedFromBackupKey`, or over SSH read the attribute on the written file. Flag clear (or unset) on a credential/PII file in `Documents`/`Library` = rides iCloud/Finder backup. |
| **Keyboard-cache** eligibility of text fields (live) | STORAGE-2 / PLATFORM-3 → MASWE-0053 → **`MASTG-TEST-0314`** *Runtime Monitoring of Text Fields Eligible for Keyboard Caching* | Hook `UITextField`/`UITextView`; check `secureTextEntry` / `autocorrectionType` per field while typing into each form. |
| **Secrets in process memory** (residue after use) | STORAGE-1 → MASWE-0118 *(Sensitive Data Not Removed After Use; mapping to confirm)* → legacy `MASTG-TEST-0060`; technique **`MASTG-TECH-0096`** *Process Exploration* | `objection ... memory dump all out.bin` then `strings`/grep the marker secret; or r2frida `:/ <secret>`. Distinguish transient (acceptable) from persisted. |
| **Keychain** contents & accessibility class | STORAGE-1 → (data-protection) → technique **`MASTG-TECH-0061`** *Dumping KeyChain Data* | `objection ... ios keychain dump` (note: keychain dump is the **technique `-0061`**, NOT test `-0301`). Confirm accessibility class (`WhenUnlocked` vs `Always`) and what persists. |

### NETWORK — MASVS-NETWORK-1/2
| Check | Trace | Run |
|---|---|---|
| **Insecure/deprecated TLS** on the wire | NETWORK-1 → MASWE-0050 → **`MASTG-TEST-0348`** *Insecure TLS Protocols in Network Traffic* | mitmproxy/Wireshark while exercising; flag TLS < 1.2, weak ciphers, plaintext. The **only purely-network runtime atomic test**. |
| **Cleartext** request actually sent | NETWORK-1 → MASWE-0050 → `-0348` (static counterpart `MASTG-TEST-0322`) | mitmproxy: observe a real `http://` request leave the app. |
| **Server-trust / accept-all** validation (MITM with a **trusted-CA** cert, **no** pinning-bypass tooling) | NETWORK-1 → **MASWE-0052** *(Insecure Certificate Validation — DISTINCT from pinning MASWE-0047)* → **`MASTG-TEST-0067`** *Testing Endpoint Identity Verification* (LIVE, has a Dynamic Analysis section; static counterpart same id) | Runtime-only angle: proves a custom `URLSessionDelegate` actually **accepts a CA it shouldn't** at runtime, not just that the code *looks* permissive. Install your proxy CA in the **system trust store** (two-step iOS full-trust) and intercept with **no** `sslpinning disable` / SSL Kill Switch running. If traffic decodes with a *trusted* CA, that is **expected** (CA default) — escalate only if it also decodes with an **untrusted/self-signed** leaf or a **mismatched hostname** (hook `-[NSURLSession ...didReceiveChallenge:]` to confirm it returns `.useCredential` unconditionally / ignores `SecTrustEvaluateWithError`). Keep separate from the pinning row below: accept-all is a **validation** flaw (MASWE-0052), missing pinning is **MASWE-0047**. |
| **Pinning** present & effective | NETWORK-2 → MASWE-0047 *(Insecure Identity Pinning)* → **`MASTG-TEST-0068`** *Testing Custom Certificate Stores and Certificate Pinning* (LIVE, has a Dynamic Analysis section — **not** deprecated); bypass via **`MASTG-TECH-0064`** | Trusted-CA proxy first. **Interceptable with a trusted CA *and* no bypass → no effective pinning** (anchor **MASWE-0047**, the *missing-pinning* weakness — do **not** conflate with MASWE-0052 accept-all above). Else attempt authorized bypass (`objection ios sslpinning disable` / SSL Kill Switch 2 / `frida --codeshare`) and re-check. There is **no atomic runtime pinning test yet**; `-0385` "Missing Certificate Pinning in ATS" is **STATIC** — do not cite it as the runtime test. |

### PLATFORM — MASVS-PLATFORM-1/2/3
| Check | Trace | Run |
|---|---|---|
| Sensitive data copied to **General Pasteboard** at runtime | PLATFORM-3 → MASWE-0053 → **`MASTG-TEST-0277`** *Sensitive Data in the iOS General Pasteboard at Runtime*; technique **`MASTG-TECH-0134`** *Monitoring the Pasteboard* | Hook `UIPasteboard generalPasteboard` / `setString:` (or use `MASTG-TECH-0134` pasteboard-monitoring); exercise copy flows; read pasteboard from a second app. |
| Sensitive content in **backgrounding screenshot** | PLATFORM-3 → MASWE-0055 → **`MASTG-TEST-0290`** *Runtime Verification of Sensitive Content Exposure in Screenshots During App Backgrounding* | Background the app on a sensitive screen; pull `Library/Caches/Snapshots/...`; check for unredacted snapshot. |
| **Secure text input** not applied to sensitive fields | PLATFORM-3 → MASWE-0053 → **`MASTG-TEST-0347`** *Runtime Use of APIs Hiding Sensitive Data in Text Input Fields* | Hook field config at runtime; confirm `isSecureTextEntry` on password/PII fields. |
| WebView **relaxed file-origin** set at runtime | PLATFORM-2 → MASWE-0069 → **`MASTG-TEST-0336`** *Runtime Setting of Relaxed WebView File Origin Policies* | Hook `WKWebView` config; check `allowFileAccessFromFileURLs` / `allowUniversalAccessFromFileURLs` at load. |
| **WebView JS↔native bridge** callable (discovery) | PLATFORM-2 → (bridge exposure) → technique **`MASTG-TECH-0139`** | Attach Safari Web Inspector (iOS 16.4+ needs `isInspectable=true`); enumerate `window.webkit.messageHandlers`; call `…<name>.postMessage(...)` live to prove a bridge does privileged work. |
| **Deep-link / custom-URL-scheme** action fires (discovery) | PLATFORM-1 → MASWE-0058 (Insecure Deep Links) → handler tests `MASTG-TEST-0370` *Missing Input Validation in Custom URL Scheme Handlers* / `MASTG-TEST-0371` *Missing Source Validation in Custom URL Scheme Handlers* (both map MASWE-0058; both are **custom-URL-scheme**, not Universal-Link, tests — for Universal Links use legacy `MASTG-TEST-0070`) | **Invoke** the scheme/UL with crafted params (`xcrun simctl openurl`, Safari, or a second app) and observe the sensitive action **actually fire** — not just read the handler. |

### CRYPTO — MASVS-CRYPTO-1/2
| Check | Trace | Run |
|---|---|---|
| **Insecure randomness** used at runtime | CRYPTO-2 → MASWE-0027 → **`MASTG-TEST-0349`** *Runtime Use of Insecure Random APIs* | Hook/trace `arc4random*`, `rand`, `random` vs `SecRandomCopyBytes`; flag predictable-RNG use for security material. |
| **Crypto misuse** (keys/IV/mode/nonce) via tracing | CRYPTO-1 → MASWE-0020/0022 → technique **`MASTG-TECH-0086`**/`-0087` (no atomic runtime test — confirm by tracing) | `frida-trace -i 'CCCrypt'` and hook `AES.GCM.seal` / CryptoKit; read **live** keys, IVs, modes, nonce reuse — invisible in an encrypted static binary. State honestly: no atomic id; descriptive **(ID to confirm)**. |

### AUTH — MASVS-AUTH-1/2
| Check | Trace | Run |
|---|---|---|
| Biometric gate **not event-bound** (bare boolean) | AUTH-2 → MASWE-0044 → **`MASTG-TEST-0267`** *Runtime Use Of Event-Bound Biometric Authentication* | `objection ... ios ui biometrics_bypass` / `MASTG-TECH-0135`. If flipping the `LAContext` callback grants access, the gate is a boolean, **not** Keychain/Secure-Enclave-bound → bypassable. |
| Biometric **falls back** to non-biometric for sensitive ops | AUTH-2 → MASWE-0045 → **`MASTG-TEST-0269`** *Runtime Use Of APIs Allowing Fallback to Non-Biometric Authentication* | Hook `LAContext evaluatePolicy:`; check policy is `…WithBiometrics` (not `…OwnerAuthentication`) for sensitive transactions. |
| Keys **not invalidated** on new biometric enrollment | AUTH-2 → MASWE-0046 → **`MASTG-TEST-0271`** *Runtime Use Of APIs Detecting Biometric Enrollment Changes* | Hook keychain ACL / `SecAccessControl`; confirm `biometryCurrentSet` (not `biometryAny`) so re-enrollment invalidates the key. |
| **Session / token / refresh** handling (discovery) | AUTH-1 → MASWE-0037 (tokens in URL) / weak-session → technique **`MASTG-TECH-0061`** + `MASTG-TECH-0063` | Hook keychain reads/writes + capture on the wire: observe token lifetime, rotation, revoke-on-logout, refresh-token reuse, tokens in query strings. **Only observable at runtime.** |

### CODE — MASVS-CODE-4
| Check | Trace | Run |
|---|---|---|
| Injection / unsafe deserialization on tainted input | CODE-4 → injection: MASWE-0086 (SQL Injection) / MASWE-0087 (Insecure Parsing and Escaping); deserialization: MASWE-0088 (Insecure Object Deserialization) → **no iOS runtime atomic test** — stays `Needs dynamic verification` | Exercise with crafted input + trace the sink (`NSXMLParser`, `JSONDecoder`, format-string sinks, `eval`-like JS bridges). State honestly: confirmed only by exercising + tracing. |

### RESILIENCE — MASVS-RESILIENCE-1/2/4 (R profile)
| Check | Trace | Run |
|---|---|---|
| **Jailbreak detection** present & effective | RESILIENCE-1 → MASWE-0097 → **`MASTG-TEST-0241`** *Runtime Use of Jailbreak Detection Techniques* (pairs static `-0240`) | Run on JB device: does the app detect/exit? Then `frida --codeshare` JB-bypass and observe if behaviour changes. **Distinguish "control absent" from "control present and effective".** |
| **Anti-hook / anti-instrumentation** behaviour | RESILIENCE-4 → MASWE-0107 → **`MASTG-TEST-0354`** *Runtime Use of Hook Detection Techniques* | Attach Frida: does the app crash/exit on attach, detect the Gadget, or kill on hook? This is the **BEHAVIOUR test** — observe reaction, then bypass and note delta. |
| **Virtual-device / emulator** detection | RESILIENCE-1 → MASWE-0099 → **`MASTG-TEST-0367`** *Runtime Use of Virtual Device Detection Techniques* | Run under Corellium/Simulator; does the app detect & react? |
| **Secure-lock (passcode)** detection | RESILIENCE-1 → MASWE-0008 → **`MASTG-TEST-0246`** *Runtime Use of Secure Screen Lock Detection APIs* | Hook `LAContext canEvaluatePolicy:` / passcode check; confirm the app reacts to a device with no passcode. |
| **Anti-tampering / integrity self-check efficacy** (re-sign / repackage, observe the check fire) | RESILIENCE-2 → MASWE-0104 *(App Integrity Not Verified)* / MASWE-0105 *(Integrity of App Resources Not Verified)* / MASWE-0106 *(Official Store Verification Not Implemented)* → **no atomic iOS runtime test** — descriptive **"Runtime app-integrity / receipt self-check efficacy" (ID to confirm)**; the in-memory inline-patch cousin is MASWE-0107 → `MASTG-TEST-0354` (hook detection, see RESILIENCE-4 row) | Runtime-only angle: static only finds the `SecCodeCheckValidity` / `CodeResources`-rehash / `appStoreReceiptURL` *references* — runtime proves whether they **actually reject a tampered binary**. Re-sign / repackage the IPA (modify a resource or patch `__TEXT`, re-sign with your own cert via `MASTG-TECH-0147` *Patching* / `MASTG-TECH-0055` debug-mode launch) and run: does the app detect the broken signature / changed resource hash / non-store receipt and refuse to run or degrade? **No reaction = control absent or ineffective; reaction = present.** Distinguish "the self-check fired" from "it crashed for an unrelated re-sign reason". |
| **Anti-debug** behaviour | RESILIENCE-2 → (anti-debug) → technique `MASTG-TECH-0084` | Attach `lldb`/`debugserver`; observe `ptrace(PT_DENY_ATTACH)` / `sysctl` debugger checks firing. |

### PRIVACY — MASVS-PRIVACY-1/2
| Check | Trace | Run |
|---|---|---|
| Protected-resource API fires **without accurate purpose string** | PRIVACY-1 → MASWE-0117 → **`MASTG-TEST-0361`** *Runtime Use of Protected Resource APIs Without Accurate Purpose Strings* | Trace the protected API (location/contacts/mic/camera); confirm it actually fires and the `NS…UsageDescription` matches real use. |
| Entitlement-backed API used for **unjustified capability** | PRIVACY-1 → MASWE-0117 → **`MASTG-TEST-0363`** *Runtime Use of Entitlement-Backed APIs for Unjustified Capability Exposure* | Trace entitlement-gated APIs at runtime; flag declared-but-overbroad vs actually-used. The "declared vs actually-used-at-runtime" lane static defers here. |
| **Persistent identifier read for tracking** (IDFV / IDFA / DeviceCheck) | PRIVACY-2 → MASWE-0110 *(Use of Unique Identifiers for User Tracking)* → **no atomic iOS runtime test** — descriptive **"Runtime use of unique identifiers for user tracking" (ID to confirm)**; technique `MASTG-TECH-0086` *Method Tracing* | Runtime-only angle: static sees the symbol; runtime proves the id is **actually read and shipped** to a tracker. Hook/trace `-[ASIdentifierManager advertisingIdentifier]` (IDFA), `-[UIDevice identifierForVendor]` (IDFV used as a cross-session key), and `DCDevice generateToken` / `DCAppAttestService` misused as a stable id — then watch the wire (`MASTG-TECH-0063`) for the value leaving. **Check ATT gating**: IDFA must be preceded by `requestTrackingAuthorization`; reading a non-zero IDFA *before* consent = finding. Mirrors the Android ad-id/`getId()` runtime row. |

---

## Offensive / discovery lane (runtime-only, static-blind)
Beyond confirming static, hunt for issues static **cannot** find:
- **Live API / business-logic on the wire** — mitmproxy/Burp (`MASTG-TECH-0063`) while exercising flows → IDOR,
  missing server-side authz (MASWE-0042), tokens in query strings (MASWE-0037), replay, mass-assignment. Anchor
  by what's seen: AUTH-1/AUTH-3 or CODE. Present in **no** static file.
- **Secrets in process memory** (STORAGE-1 → MASWE-0118 *(mapping to confirm)*) — `objection ... memory dump all`
  / `MASTG-TECH-0096` after the secret transits memory.
- **Session/token/refresh** (AUTH-1) — keychain hooks (`MASTG-TECH-0061`) + trace refresh; lifetime/rotation/
  revocation/reuse. Static sees only storage location.
- **Live IPC / deep-link / Universal-Link exploitation** (PLATFORM-1) — invoke + observe action fire.
- **WebView JS-bridge at runtime** (PLATFORM-2) — Safari Web Inspector + live `postMessage` (`-0336` for
  file-origin).
- **Biometric bypass as discovery** (AUTH-2) — `objection ios ui biometrics_bypass` proves a boolean-only gate
  (`-0267`).
- **Runtime crypto misuse via tracing** (CRYPTO-1/2) — `frida-trace` keys/IVs/nonces (`-0349` + `-0086`).
- **Anti-instrumentation behaviour** (RESILIENCE-2/4) — `-0241`/`-0354`/`-0367`; control-absent vs
  present-and-effective.

---

## Mode 2 — targeted assist (user asks for ONE thing → run ONE step, no full report)
| User asks | Single runnable step | Anchor |
|---|---|---|
| "test the pinning" | Trusted-CA proxy first; if blocked → `objection -g <app> explore` then `ios sslpinning disable` (or SSL Kill Switch 2 on JB / `frida --codeshare` for non-standard) → re-check interception | `MASTG-TECH-0064` / `MASTG-TEST-0068` |
| "test biometrics" | `objection -g <app> explore` → `ios ui biometrics_bypass` | `MASTG-TECH-0135` / `MASTG-TEST-0267` |
| "dump the keychain" | `objection -g <app> explore` → `ios keychain dump` | `MASTG-TECH-0061` |
| "check what's on the wire" | mitmproxy with trusted CA + exercise the flow | `MASTG-TECH-0063` |
| "is the jailbreak detection real" | `frida --codeshare` JB-bypass, relaunch, observe | `MASTG-TEST-0241` |
| "trace the crypto" | `frida-trace -i 'CCCrypt' -m '*[* *crypt*]'` while exercising | `MASTG-TECH-0086` |
| "what classes/methods are live" (FairPlay) | frida REPL → `ObjC.enumerateLoadedClasses()` / `$ownMethods` | `MASTG-TECH-0094` |

---

## Dynamic false positives / honest negatives
- **Interception failed ≠ pinning.** On iOS, CA trust is a **two-step**: install the profile **and** enable it
  in *Settings → General → About → Certificate Trust Settings*. If you skipped step two, you'll see TLS errors
  that look like pinning but aren't. (This is the iOS analogue of the Android 7 / API 24 user-CA default gotcha —
  keep both in mind.) Confirm full-trust before concluding the app pins.
- **"A bypass changed nothing" ≠ "control present".** If `objection ios sslpinning disable` makes **no**
  difference, the app may not pin **at all** — that's "control absent", not "bypass succeeded". Verify by
  intercepting **without** any bypass first.
- **JB / Frida-Gadget artifacts as your own noise.** Cydia paths, Substrate, the default Frida port **27042**,
  and Gadget signatures can trip the app's **own** detection and change its behaviour — that's a
  test-environment artifact, not real app behaviour. Re-test with a stealthier setup before reporting "the app
  is broken".
- **Single observation ≠ confirmed.** One captured request / one bypass success is a lead; **re-run** to confirm
  reproducibility before raising severity.
- **Simulator / Corellium ≠ real device.** Simulator is x86 debug-only; FairPlay, Keychain accessibility, and
  Secure-Enclave-bound keys behave differently. Confirm Keychain/biometric/crypto findings on **real hardware**.
- **Reading FairPlay `__TEXT` before decryption.** Don't trust in-memory `__TEXT` reads until `rabin2 -I`
  confirms `cryptid 0`; otherwise you're reading ciphertext and inventing findings.
- **`Needs dynamic verification` stays that way** unless the step was **actually run** on the authorized device.

---

## Fusing with static (confidence)
Same rule as Android: static-confirmed path + dynamic observation → one **`Confirmed`** finding; un-run → keep
**`Needs dynamic verification`**; dynamic **disproof** → downgrade/drop and note it. For an App Store IPA, state
explicitly when a conclusion required decrypting/instrumenting (otherwise the static read was on ciphertext).

> Shared environment setup (proxy CA, frida-server, objection, device prep) is in `setup-dynamic.md`.

---

## Runtime test-id table (consolidated — verified live, `mas.owasp.org`, June 2026)
| Area | Runtime ID | Title | MASWE | Static pair |
|---|---|---|---|---|
| STORAGE | `MASTG-TEST-0301` | Runtime Use of APIs for Storing Unencrypted Data in Private Storage | MASWE-0006 | `-0300` |
| STORAGE | `MASTG-TEST-0302` | Sensitive Data Unencrypted in Private Storage Files | MASWE-0006 | `-0300` |
| STORAGE | `MASTG-TEST-0299` | Data Protection Classes for Files in Private Storage (read-while-locked) | MASWE-0006 | `-0300` |
| STORAGE | `MASTG-TEST-0298` | Runtime Monitoring of Files Eligible for Backup | MASWE-0004 | `-0215` |
| STORAGE | `MASTG-TEST-0314` | Runtime Monitoring of Text Fields Eligible for Keyboard Caching | MASWE-0053 | `-0313` |
| STORAGE | *(none — legacy `-0060`)* | Secrets in process memory / not removed after use (memory-residue) | MASWE-0118 *(mapping to confirm)* | — |
| NETWORK | `MASTG-TEST-0348` | Insecure TLS Protocols in Network Traffic | MASWE-0050 | `-0322` |
| NETWORK | `MASTG-TEST-0067` | Testing Endpoint Identity Verification (accept-all / custom-trust; has Dynamic section) | MASWE-0052 | `-0067` (same id) |
| NETWORK | `MASTG-TEST-0068` | Testing Custom Certificate Stores and Certificate Pinning (umbrella, has Dynamic section) | MASWE-0047 | — |
| PLATFORM | `MASTG-TEST-0277` | Sensitive Data in the iOS General Pasteboard at Runtime | MASWE-0053 | — |
| PLATFORM | `MASTG-TEST-0290` | Runtime Verification of Sensitive Content Exposure in Screenshots During App Backgrounding | MASWE-0055 | — |
| PLATFORM | `MASTG-TEST-0336` | Runtime Setting of Relaxed WebView File Origin Policies | MASWE-0069 | — |
| PLATFORM | `MASTG-TEST-0347` | Runtime Use of APIs Hiding Sensitive Data in Text Input Fields | MASWE-0053 | — |
| CRYPTO | `MASTG-TEST-0349` | Runtime Use of Insecure Random APIs | MASWE-0027 | — |
| AUTH | `MASTG-TEST-0267` | Runtime Use Of Event-Bound Biometric Authentication | MASWE-0044 | `-0266` |
| AUTH | `MASTG-TEST-0269` | Runtime Use Of APIs Allowing Fallback to Non-Biometric Authentication | MASWE-0045 | `-0268` |
| AUTH | `MASTG-TEST-0271` | Runtime Use Of APIs Detecting Biometric Enrollment Changes | MASWE-0046 | `-0270` |
| RESILIENCE | `MASTG-TEST-0241` | Runtime Use of Jailbreak Detection Techniques | MASWE-0097 | `-0240` |
| RESILIENCE | `MASTG-TEST-0354` | Runtime Use of Hook Detection Techniques | MASWE-0107 | — |
| RESILIENCE | *(none — ID to confirm)* | Runtime app-integrity / receipt self-check efficacy (re-sign / repackage, observe reaction) | MASWE-0104 / -0105 / -0106 | — |
| RESILIENCE | `MASTG-TEST-0367` | Runtime Use of Virtual Device Detection Techniques | MASWE-0099 | — |
| RESILIENCE | `MASTG-TEST-0246` | Runtime Use of Secure Screen Lock Detection APIs | MASWE-0008 | — |
| PRIVACY | `MASTG-TEST-0361` | Runtime Use of Protected Resource APIs Without Accurate Purpose Strings | MASWE-0117 | — |
| PRIVACY | `MASTG-TEST-0363` | Runtime Use of Entitlement-Backed APIs for Unjustified Capability Exposure | MASWE-0117 | — |
| PRIVACY | *(none — ID to confirm)* | Runtime use of unique identifiers for user tracking (IDFV / IDFA / DeviceCheck) | MASWE-0110 | — |
| CODE | *(none)* | No iOS runtime atomic test — CODE-4 stays `Needs dynamic verification`, confirmed by exercising + tracing | MASWE-0086/0087 (injection); MASWE-0088 (deserialization) | — |

## Dynamic technique-id table (verified live)
| TECH ID | Title |
|---|---|
| `MASTG-TECH-0052` | Accessing the Device Shell |
| `MASTG-TECH-0055` | Launching a Repackaged App in Debug Mode (`get-task-allow`) |
| `MASTG-TECH-0061` | Dumping KeyChain Data |
| `MASTG-TECH-0062` | Basic Network Monitoring/Sniffing |
| `MASTG-TECH-0063` | Setting up an Interception Proxy |
| `MASTG-TECH-0064` | Bypassing Certificate Pinning |
| `MASTG-TECH-0067` | Dynamic Analysis on iOS |
| `MASTG-TECH-0084` | Debugging |
| `MASTG-TECH-0086` | Method Tracing |
| `MASTG-TECH-0087` | Native Code Tracing |
| `MASTG-TECH-0088` | Emulation-based Analysis (covers iOS Simulator, Corellium, Unicorn) |
| `MASTG-TECH-0090` | Injecting Frida Gadget into an IPA Automatically |
| `MASTG-TECH-0094` | Getting Loaded Classes and Methods dynamically |
| `MASTG-TECH-0096` | Process Exploration |
| `MASTG-TECH-0097` | Runtime Reverse Engineering |
| `MASTG-TECH-0134` | Monitoring the Pasteboard (iOS) |
| `MASTG-TECH-0135` | Bypassing Biometric Authentication |
| `MASTG-TECH-0139` | Attach to WKWebView |
| `MASTG-TECH-0146` | Dynamic Analysis on Non-Jailbroken Devices |
| `MASTG-TECH-0147` | Patching |

> **ID hygiene.** These are **static**, not runtime — do **not** file them here: `-0385` (Missing Cert Pinning
> in ATS), `-0387` (Storage Integrity Check APIs), `-0388` (shared app-group containers), `-0389`/`-0390`
> (custom keyboard extension), `-0391` (native-code obfuscation), `-0383/-0384/-0386` (CODE). MASTG is
> mid-refactor (legacy narrative tests + atomic `02xx/03xx` coexist; atomic live under `tests-beta/` on GitHub,
> resolve under `/tests/` on the site); MASWE is Beta. Re-verify IDs live before citing.
>
> **Technique-ID disambiguation (cross-file canon).** Tracing/hooking technique ids are easy to swap — keep them
> straight: **Method Hooking = `MASTG-TECH-0043`** (Android) / **`MASTG-TECH-0095`** (iOS); **Execution Tracing =
> `MASTG-TECH-0032`**; **Native Code Tracing = `MASTG-TECH-0034`** (Android) / **`MASTG-TECH-0087`** (iOS);
> **Method Tracing = `MASTG-TECH-0086`** (iOS). **`MASTG-TECH-0033` is neither "Method Hooking" nor a tracing id
> to cite here** — do not use it for hooking/tracing. For HTTP interception, **prefer iOS `MASTG-TECH-0063`**
> (*Setting up an Interception Proxy*) over the generic/unverified **`MASTG-TECH-0120`** — qualify or replace any
> `-0120` citation. **Cert-validation vs pinning weaknesses are distinct:** accept-all / bad hostname / no chain
> check = **MASWE-0052** (Insecure Certificate Validation, runtime via `MASTG-TEST-0067`); *missing* pinning =
> **MASWE-0047** (Insecure Identity Pinning, runtime via `MASTG-TEST-0068`) — never collapse them. **Memory-residue
> anchors to MASVS-STORAGE-1 + MASWE-0118 (mapping to confirm)** for parity with `android-dynamic.md` /
> `setup-dynamic.md`. **Enforced-updating has no confirmed runtime atomic test** — use legacy static `-0080` (iOS)
> *(atomic successor to confirm)* or mark descriptive; never cite `-0382`/`-0384` as a confirmed runtime code test.
