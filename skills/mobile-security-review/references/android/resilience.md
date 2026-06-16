# Android — MASVS-RESILIENCE (static)

Static, fully-automated checks for resistance to reverse-engineering and tampering on an Android artifact
(`.apk` / `.aab` / extracted APK). **Assess only under the R profile** — under L1/L2 the *absence* of these
controls is at most Info, never a finding. Resilience is defense-in-depth; it never substitutes for an
L1/L2 control. Statically you can confirm a mechanism is **present / absent / trivially bypassable from a
single point**, but you **cannot** judge runtime effectiveness — wire that to dynamic and mark
**Needs dynamic verification**.

Anchor each finding to the exact control in SKILL.md (read it); verify MASWE/MASTG IDs against the live guide.

## Group controls (MASVS v2.0.0, verbatim)
- **MASVS-RESILIENCE-1** — The app validates the integrity of the platform. *(root detection, attestation, secure-lock / OS-trust checks)*
- **MASVS-RESILIENCE-2** — The app implements anti-tampering mechanisms. *(signature/APK-hash self-check, repackaging & install-source verification)*
- **MASVS-RESILIENCE-3** — The app implements anti-static analysis mechanisms. *(obfuscation, stripped symbols, no readable strings/non-prod resources)*
- **MASVS-RESILIENCE-4** — The app implements anti-dynamic analysis techniques. *(anti-debug, anti-hook, emulator/virtualization detection; the `android:debuggable` flag)*

> **Anchor-by-statement, not by group.** Several reversing-aids you *find* during a code/manifest pass anchor
> by their statement: `android:debuggable` and WebView remote-debugging → **RESILIENCE-4** (dynamic-analysis
> aid), not CODE; stripped/un-stripped native symbols and readable string constants → **RESILIENCE-3**;
> signing-scheme / repackaging → **RESILIENCE-2**; root detection / attestation → **RESILIENCE-1**.

> ID note: legacy narrative tests (MASTG-TEST-0045/-0046/-0047/-0048/-0049/-0050/-0051) are superseded by
> atomic tests (0200+/0300+). Each atomic test is tagged *static* or *runtime* in its title ("References to…"
> = static signal; "Runtime Use of…" = dynamic). For a static-only review cite the **static** atomic test and
> note the runtime counterpart exists. Live URL:
> `https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/<ID>/`. Verified against the live catalog at
> time of writing.

---

## RESILIENCE-1 — platform-integrity validation (root detection / attestation)

- **Root detection present?** Grep the decompiled code for `su`/`busybox` path probes
  (`/system/bin/su`, `/system/xbin/su`, `which su`), Magisk/`magiskhub`/`/sbin/.magisk` artifacts, known
  root-manager packages (`com.topjohnwu.magisk`, `eu.chainfire.supersu`, `com.koushikdutta.superuser`),
  `Build.TAGS` containing `test-keys`, RootBeer/`com.scottyab.rootbeer` library usage, writable-system
  checks. *Absent under R* = finding. **Anchor `MASVS-RESILIENCE-1`** · MASWE-0097 (Root/Jailbreak Detection
  Not Implemented) · **MASTG-TEST-0324** "References to Root Detection Mechanisms" (static; runtime
  counterpart MASTG-TEST-0325, legacy MASTG-TEST-0045).
- **Single-point / trivially-bypassable detection.** A lone boolean method returning `isRooted()` consumed
  in one spot is bypassable with one Frida hook or a smali patch. Note brittleness even when present — static
  can see the *structure* (one check vs layered, results gating real security paths vs dead/logged-only) but
  not runtime efficacy → **Needs dynamic verification** for "is it effective". Same anchor MASWE-0097 /
  MASTG-TEST-0324.
- **Detection wired into security paths, not dead code.** Flag root/integrity results that are computed then
  ignored (logged, or a dialog the user dismisses while the sensitive flow continues). A detection that
  doesn't gate anything is equivalent to absent. Anchor `MASVS-RESILIENCE-1` · MASWE-0097.
- **Device / app attestation present?** Look for Play Integrity API (`com.google.android.play.core.integrity`,
  `IntegrityManager`/`StandardIntegrityManager`), legacy SafetyNet Attestation
  (`SafetyNetApi.attest`/`com.google.android.gms.safetynet`), or hardware **key attestation**
  (`KeyGenParameterSpec.setAttestationChallenge`). Absent where strong device-integrity assurance is required
  under R = finding. **Anchor `MASVS-RESILIENCE-1`** · MASWE: unmapped (attestation-absence weakness has no
  confirmed RESILIENCE MASWE id — cite control + descriptive name) · Hardware-attestation test name *(ID to
  confirm)*; legacy MASTG-TEST-0047.
- *(Secondary, R-1 edge)* **Secure-screen-lock verification** — `KeyguardManager.isDeviceSecure()` /
  `isKeyguardSecure()` used to gate sensitive functionality. Absent where the threat model needs it = note.
  Anchor `MASVS-RESILIENCE-1` · MASWE-0008 (Missing Device Secure Lock Verification Implementation) · **MASTG-TEST-0247**
  "References to APIs for Detecting Secure Screen Lock" (static; runtime MASTG-TEST-0249).

## RESILIENCE-2 — anti-tampering (integrity self-check, repackaging / store verification)

- **APK signature / hash self-check present?** Grep for runtime signature verification:
  `PackageManager.getPackageInfo(..., GET_SIGNATURES | GET_SIGNING_CERTIFICATES)`,
  `PackageInfo.signingInfo`/`signatures`, comparison of `signature.toByteArray()`/cert SHA against an
  expected pin, or a DEX/APK-hash self-integrity check. Absent under R (app can be repackaged and re-signed
  with an attacker key undetected) = finding. **Anchor `MASVS-RESILIENCE-2`** · MASWE-0104 (App Integrity Not
  Verified) · Repackaging/integrity-self-check test name *(ID to confirm)*; legacy MASTG-TEST-0050.
- **Install-source / official-store verification present?** `PackageManager.getInstallerPackageName` /
  `getInstallSourceInfo` compared against `com.android.vending` / known stores, to detect sideloaded
  repackaged copies. Absent under R = note. **Anchor `MASVS-RESILIENCE-2`** · MASWE-0106 (Official Store
  Verification Not Implemented) · test name *(ID to confirm)*.
- **APK signature scheme (Janus exposure).** From `apksigner verify --verbose --print-certs`: a **v1-only**
  (JAR) signed APK installable on `minSdk ≥ 24` is exposed to the Janus repackaging class (v1 signature
  doesn't cover the full APK). Prefer v2/v3/v4. **Anchor `MASVS-RESILIENCE-2`** · MASWE: unmapped (rel.
  MASWE-0104; no confirmed scheme-specific id) · **MASTG-TEST-0224** "Usage of Insecure APK Signature
  Version" · technique MASTG-TECH-0116 (Obtaining Information about the APK Signature).
- **Signing-key strength.** RSA signing key `< 2048` bits (from the printed certs) is a weak-key tampering
  risk. **Anchor `MASVS-RESILIENCE-2`** · MASWE: unmapped (cite control + descriptive name) ·
  **MASTG-TEST-0225** "Usage of Insecure APK Signature Key Size" · technique MASTG-TECH-0116.

## RESILIENCE-3 — anti-static-analysis (obfuscation, stripped symbols, non-prod cleanup)

- **Java/Kotlin obfuscation.** Open the DEX in jadx: are class/method/field names meaningful and is logic +
  string constants fully readable? R8/ProGuard identifier-renaming is the baseline; **identifier renaming
  alone is insufficient when plaintext string constants still reveal detection thresholds, endpoints, or
  secret-handling logic.** Security-relevant code readable under R = finding. **Anchor `MASVS-RESILIENCE-3`**
  · MASWE-0089 (Code Obfuscation Not Implemented) · **MASTG-TEST-0368** "Insufficient Obfuscation of
  Security-Relevant Java/Kotlin Code"; legacy MASTG-TEST-0051.
- **Native obfuscation.** Bundled `.so` whose security-relevant routines (root/anti-debug checks, key
  derivation) are trivially recoverable in Ghidra/IDA with readable strings/symbols. **Anchor
  `MASVS-RESILIENCE-3`** · MASWE-0089 · **MASTG-TEST-0369** "Insufficient Obfuscation of Security-Relevant
  Native Code".
- **Native debug symbols not stripped.** Per `.so`, check for a symbol table / `.debug_*` / DWARF sections
  (`nm -D`/`readelf -sS`/`objdump`; androguard for the file list). Un-stripped release `.so` greatly eases RE.
  **Anchor `MASVS-RESILIENCE-3`** · MASWE-0093 (Debugging Symbols Not Removed) · **MASTG-TEST-0288**
  "Debugging Symbols in Native Binaries" · technique: ELF symbol-inspection *(MASTG-TECH-0140, ID to
  confirm)*; legacy MASTG-TEST-0040.
- **Non-production resources not removed.** Staging/QA/debug endpoints, test menus, sample credentials,
  internal config left in `res/`/`assets/`/`BuildConfig`. These leak internal structure and aid static RE.
  **Anchor `MASVS-RESILIENCE-3`** · MASWE-0094 (Non-Production Resources Not Removed) · test name *(ID to
  confirm)*; legacy MASTG-TEST-0041. *(Cross-ref: endpoints also feed the NETWORK/CODE attack-surface map.)*
- **Code that disables security controls not removed.** Hidden toggles / debug branches that turn off TLS
  validation, pinning, root/anti-debug detection, or auth (e.g. `if (BuildConfig.DEBUG || sDisablePinning)
  return true;`). A shipped "disable-pinning" switch is an active tampering aid, not just dead code. **Anchor
  `MASVS-RESILIENCE-3`** · MASWE-0095 (Code That Disables Security Controls Not Removed) · test name *(ID to
  confirm)*. *(If the toggle disables a NETWORK/AUTH control, cross-ref that group; the disabling-code
  weakness itself is RESILIENCE-3.)*
- **StrictMode left enabled in release.** `StrictMode.setThreadPolicy`/`setVmPolicy` with logging in a
  release build leaks architectural detail to logcat. Minor RE aid. **Anchor `MASVS-RESILIENCE-3`** (debug
  leftover; rel. MASWE-0067) · **MASTG-TEST-0265** "References to StrictMode APIs" (static); runtime use is
  **MASTG-TEST-0264** "Runtime Use of StrictMode APIs", and **MASTG-TEST-0263** "Logging of StrictMode
  Violations" is a distinct logging-detection test (not merely a runtime counterpart). *(low)*
- *(Cross-ref, not a separate check)* Logs that expose class names / stack traces / endpoints aiding RE —
  the secret-leakage angle is **STORAGE-2** (MASWE-0001); note "logs that aid RE → also RESILIENCE-3" rather
  than re-listing.

## RESILIENCE-4 — anti-dynamic-analysis (debuggable, anti-debug, anti-hook, emulator/virtualization)

- **`android:debuggable="true"` in the manifest.** On a **release** build this is serious (JDWP attach,
  runtime inspection, memory dump). Expected in a *debug* build → not a finding; confirm build type first.
  **Anchor `MASVS-RESILIENCE-4`** · MASWE-0067 (Debuggable Flag Not Disabled) · **MASTG-TEST-0226**
  "Debuggable Flag Enabled in the AndroidManifest" (atomic test now covers the manifest flag directly —
  cite it, do not borrow an unrelated id). *(Detected in the manifest pre-pass; anchored here, not CODE.)*
- **WebView remote debugging.** `WebView.setWebContentsDebuggingEnabled(true)` unconditional / not gated on
  `ApplicationInfo.FLAG_DEBUGGABLE` exposes the WebView to `chrome://inspect`. **Independent of the manifest
  `debuggable` flag** — check it even on a non-debuggable build. **Anchor `MASVS-RESILIENCE-4`** · MASWE-0074
  (Web Content Debugging Enabled) · **MASTG-TEST-0227** "Debugging Enabled for WebViews" (maps to MASWE-0074).
- **Anti-debugging present?** `Debug.isDebuggerConnected()` / `Debug.waitingForDebugger()`, native `ptrace`
  self-attach (`ptrace(PTRACE_TRACEME)`), TracerPid checks in `/proc/self/status`, timing/JDWP checks.
  Absent under R = finding. **Anchor `MASVS-RESILIENCE-4`** · MASWE-0101 (Debugger Detection Not
  Implemented) · **MASTG-TEST-0352** "References to Debugging Detection APIs" (static; runtime counterpart
  MASTG-TEST-0353); legacy MASTG-TEST-0046.
- **Anti-hooking / instrumentation detection present? (distinct scan)** Frida artifact strings
  (`frida-server`, `frida-gadget`, `re.frida.server`, default port `27042`, `gum-js-loop`), Xposed
  (`de.robv.android.xposed`, `XposedBridge`), Substrate, Riru/Zygisk, and `/proc/self/maps` walks for
  injected libraries. Absent under R = finding. **Anchor `MASVS-RESILIENCE-4`** · MASWE-0102 (Dynamic
  Analysis Tools Detection Not Implemented) · static hook-detection test name *(ID to confirm)* — note the
  catalog's **runtime** counterpart is MASTG-TEST-0341 "Runtime Use of Hook Detection Techniques" (which the
  live guide maps to MASWE-0103 RASP); legacy MASTG-TEST-0048.
- **Emulator detection present? (distinct scan)** `Build.FINGERPRINT`/`MODEL`/`PRODUCT`/`HARDWARE` matching
  generic/`goldfish`/`ranchu`/`sdk`/`vbox`, qemu props (`ro.kernel.qemu`), emulator telephony defaults
  (IMEI all-zero, `15555215554`), missing sensors. Absent under R = finding. **Anchor `MASVS-RESILIENCE-4`**
  · MASWE-0099 (Emulator Detection Not Implemented) · static emulator-detection test name *(ID to confirm)*
  — runtime counterpart **MASTG-TEST-0351** "Runtime Use of Emulator Detection Techniques"; legacy
  MASTG-TEST-0049.
- **App-virtualization / cloning detection present? (distinct scan)** VirtualApp / dual-instance / parallel-
  space frameworks (e.g. `com.lbe.parallel`, multiple-app-clone containers) detected via package-path / data-
  dir / loaded-package anomalies. Absent where the threat model includes runtime cloning under R = finding.
  **Anchor `MASVS-RESILIENCE-4`** · MASWE-0098 (App Virtualization Environment Detection Not Implemented) ·
  test name *(ID to confirm)*.

---

## Classic false positives
Consult before promoting a candidate. Each below is **usually NOT a finding** absent extra evidence:

| Candidate | Why it's usually a false positive | When it *is* real |
|---|---|---|
| No obfuscation / root detection / anti-debug | Not required under **L1/L2** — resilience is R-only defense-in-depth | required and absent under the **R** profile |
| `android:debuggable="true"` | Expected in a **debug** build | present in the **release**/shipped artifact (MASWE-0067 / MASTG-TEST-0226) |
| Root/anti-debug "missing" but actually present | Detection exists but is obfuscated/native, so a string grep missed it | confirmed absent after reading native + DEX, **or** present-but-dead (result never gates a security path) |
| Detection "easily bypassed" | Static can't prove runtime efficacy; a single check is brittle but still a control | mark **Needs dynamic verification**; only "ineffective" once a dynamic bypass is demonstrated |
| Readable strings in jadx | R8 renames identifiers but keeps string literals; harmless for non-sensitive strings | plaintext strings reveal detection thresholds, endpoints, keys, or secret-handling logic (RESILIENCE-3) |
| `setWebContentsDebuggingEnabled(true)` | Gated behind `FLAG_DEBUGGABLE` / only in a debug build | unconditional in the release artifact (MASWE-0074 / MASTG-TEST-0227) |
| v1 (JAR) signature detected | App also carries v2/v3 (v1 kept only for `minSdk < 24` compatibility) | **v1-only** and installable on `minSdk ≥ 24` (Janus) |
| StrictMode references | Stripped/no-op in release, or debug-only | logging policy active in the **release** build |

When you dismiss a candidate, record it (and the reason) in the report's "candidates not promoted" appendix —
that transparency is part of an honest deliverable.
