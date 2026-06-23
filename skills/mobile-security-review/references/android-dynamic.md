# Android — Dynamic Analysis (confirm the static flags **and** hunt runtime-only issues)

**Purpose.** The dynamic lane has **two jobs**:
1. **Confirm + fuse** — turn a static `Needs dynamic verification` into `Confirmed` by proving it on a device,
   and **downgrade/drop** static suspicions that dynamic disproves (e.g. pinning that actually holds).
2. **Discover (offensive lane)** — find **runtime-only** issues static physically cannot see: live API /
   business-logic flaws on the wire, secrets in **process memory**, session/token/refresh behaviour over time,
   live IPC / deep-link / app-link exploitation, the WebView JS-bridge actually firing, biometric / local-auth
   bypass, runtime crypto misuse via method tracing, server-trust / MITM behaviour, and whether
   anti-instrumentation / anti-debug controls **actually trigger**.

> **Static is blind to:** obfuscated / packed / dynamically-loaded code (DexClassLoader, native `.so`,
> runtime-derived keys). For those the dynamic lane is the **primary** lane — the Android mirror of the iOS
> rule that FairPlay-encrypted App Store binaries must be analysed dynamically. If jadx shows a stub, a
> reflective loader, or a decryptor-at-startup, plan to *trace*, not just *read*.

> **Human-in-the-loop & authorization (Rule Zero).** Dynamic testing requires a **prepared, dedicated,
> AUTHORIZED test device** and an **operator who exercises the app's flows** (login, transfer, etc.) — the
> tooling observes; a human drives. **Re-confirm authorization/scope before instrumenting** and stay within it.
> The bypass techniques below are for **authorized testing only**. **Never fabricate dynamic results**: if you
> did not actually run a step on a device, the finding stays `Needs dynamic verification` — do not claim
> runtime behaviour you did not observe.

---

## Preconditions
- **Device**: a rooted physical device **or** an emulator (AVD), + `adb`. Non-rooted is possible by repackaging
  with the **Frida Gadget** (`MASTG-TECH-0026`, *Dynamic Analysis on Non-Rooted Devices*).
- **Instrumentation**: `frida-server` pushed and run on the device, **matching the host Frida version**;
  `objection` (Frida-backed) for one-command hooks.
- **Interception**: an intercepting proxy (Burp / ZAP / **mitmproxy**) with its **CA installed**, device
  Wi-Fi/proxy pointed at the host (`MASTG-TECH-0011` *Setting Up an Interception Proxy*, Android).
- **The user-CA gotcha (read this — it is the #1 source of false "pinning" calls):** since **Android 7
  (API 24)** apps do **not** trust user-installed CAs unless `network_security_config` opts in. So TLS
  interception fails *before* any app-level pinning unless you either (a) install the proxy CA into the
  **system** store (root), or (b) repackage with an NSC that trusts the `user` anchor. **Distinguish "couldn't
  intercept due to the CA-trust default" from "couldn't intercept due to pinning"** (see false-positives table).

> Shared host/device environment setup with iOS lives in `setup-dynamic.md`.

---

## Tooling
| Tool | Use |
|---|---|
| **frida / frida-server** (`MASTG-TOOL-0001`) | Hook Java/native functions: bypass pinning/root checks, trace methods, dump memory, return-value patching. |
| **objection** (`MASTG-TOOL-0038`) | One-command: `android sslpinning disable`, `android root disable`, `android ui biometrics_bypass`, keystore/storage/memory inspection. |
| **frida-trace** | Java + native method tracing (`*Cipher*!getInstance`, native `.so` crypto/anti-debug). |
| **mitmproxy / Burp / ZAP** | MITM HTTP(S): confirm cleartext, observe PII, replay/tamper requests, decide pinning vs CA-default. |
| **adb** | Install, port-forward, read app data dirs, `logcat`, invoke exported components (`am start`, `content query`). |
| **drozer** | Enumerate & exercise exported activities/services/receivers and content providers (`app.activity.start`, `app.provider.query`, `scanner.provider.*`). |
| **lldb** (+ `jdb`) | Native debugging / memory inspection of `.so` routines; JDWP debugging when `debuggable`. |
| **r2frida** | radare2 + Frida for live native memory/disassembly exploration. |
| **jadx** | Read decompiled code to locate the exact class/method names to hook. |

### Techniques (MASTG-TECH) — verified live
| ID | Technique | Use here |
|---|---|---|
| `MASTG-TECH-0049` | Dynamic Analysis (generic entry) | umbrella |
| `MASTG-TECH-0011` | Setting Up an Interception Proxy (Android) | wire interception |
| `MASTG-TECH-0012` | Bypassing Certificate Pinning | pinning confirm |
| `MASTG-TECH-0026` | Dynamic Analysis on Non-Rooted Devices | Frida Gadget repackage |
| `MASTG-TECH-0031` | Debugging (JDWP + ptrace/lldb) | anti-debug, native |
| `MASTG-TECH-0032` | Execution Tracing (jdb, strace, `frida-trace`) | control-flow / dynamic-load |
| `MASTG-TECH-0034` | Native Code Tracing (`frida-trace` native) | `.so` crypto / anti-debug |
| `MASTG-TECH-0043` | **Method Hooking** (Frida/Xposed Java hooks) | hook gates, crypto, callbacks |
| `MASTG-TECH-0044` | Process Exploration (memory maps, heap, dump) | the **memory lane** backbone |
| `MASTG-TECH-0009` | Monitoring System Logs (logcat) | runtime log leakage |
| `MASTG-TECH-0128` | Performing a Backup and Restore of App Data | STORAGE-2 backup exfil |
| `MASTG-TECH-0127` | Inspecting an App's Backup Data | STORAGE-2 backup exfil |
| `MASTG-TECH-0144` | Bypassing Root Detection | RESILIENCE efficacy |

> **Correction vs older notes:** Method Hooking is **`MASTG-TECH-0043`**, *not* `-0033`. `frida-trace` lives
> under Execution Tracing (`-0032`) / Native Code Tracing (`-0034`). (`-0120` for a generic proxy is *unverified*
> — use `-0011` for Android.)

---

## How to use this file
Each MASVS area below is a **candidate generator**: a runtime-only angle, the **MASVS → MASWE → MASTG(runtime)**
trace, and the **exact command to RUN**. Pick the area that matches the flow you are exercising. Then fuse
(below) and gate against the false-positives table. For a single targeted ask, jump to **Mode 2**.

---

## STORAGE — what *actually* persists after a real flow; secrets in RAM
Runtime-only angle: static sees *call sites*; only a real run shows the **files that actually appear** and
whether secrets sit in **process memory**.

- **Unencrypted data written at runtime** → MASVS-STORAGE-1 · MASWE-0006 (sensitive data unencrypted in private
  storage) · **MASTG-TEST-0207** *Runtime Storage of Unencrypted Data in the App Sandbox* + **MASTG-TEST-0287**
  *Runtime Storage of Unencrypted Data via the SharedPreferences API*.
  Cmd — diff the sandbox before/after the flow:
  ```
  adb shell run-as <pkg> tar -cf - . > before.tar   # baseline
  # ...drive login/transfer with marked test data...
  adb shell run-as <pkg> tar -cf - . > after.tar
  # diff trees; inspect new/changed files for the marked secret
  ```
- **External / shared storage at runtime** → MASVS-STORAGE-2 · MASWE-0007 (unencrypted in shared storage) ·
  **MASTG-TEST-0201** *Runtime Use of APIs to Access External Storage*.
  Cmd: `frida-trace -U -f <pkg> -j 'android.content.Context!getExternalFilesDir'` then inspect `/sdcard/...`.
- **Sensitive data in logs at runtime** → MASVS-STORAGE-2 · MASWE-0001 (*Insertion of Sensitive Data into Logs*)
  · **MASTG-TEST-0203** *Runtime Use of Logging APIs* (via `MASTG-TECH-0009`).
  Cmd: `adb logcat --pid=$(adb shell pidof -s <pkg>) | grep -iE 'token|pass|pin|secret|jwt|card'`
- **Sensitive content leaking via NOTIFICATIONS at runtime** → MASVS-STORAGE-2 · MASWE-0054 (*Sensitive Data
  Leaked via Notifications*) · **MASTG-TEST-0315** *Sensitive Data Exposed via Notifications* (static-leaning;
  the live test's Dynamic-Analysis lane = **trace the notification builder at runtime** — there is no separate
  runtime-only atomic id, so cite `-0315` + descriptive runtime note). Runtime-only angle: static sees the
  builder call; only a run shows the **actual rendered text** that lands on the lock screen / shade where a
  notification-listener app or shoulder-surfer can read it. Cmd:
  ```
  frida-trace -U -f <pkg> \
    -j 'androidx.core.app.NotificationCompat$Builder!setContentText' \
    -j 'androidx.core.app.NotificationCompat$Builder!setContentTitle'
  # fire an OTP/transfer notification, read the logged arg; cross-check VISIBILITY_PUBLIC vs _SECRET/_PRIVATE
  ```
  **Interpretation (gate):** content shown only when the device is **unlocked** (`VISIBILITY_PRIVATE`/`_SECRET`
  with a redacted public form) is *not* a leak; sensitive text rendered at `VISIBILITY_PUBLIC` (visible on a
  locked screen) is. *(Legacy narrative: `MASTG-TEST-0005`, superseded by `-0315`.)*
- **Backup exfiltration confirmed by actually running adb backup/restore** → MASVS-STORAGE-2 · MASWE-0003
  (*Backup Unencrypted*) + MASWE-0004 (*Sensitive Data Not Excluded From Backup*) · **no runtime atomic TEST id**
  → run the backup **techniques** **MASTG-TECH-0128** *Performing a Backup and Restore of App Data* +
  **MASTG-TECH-0127** *Inspecting an App's Backup Data*, anchored to the static tests `MASTG-TEST-0216` /
  `MASTG-TEST-0262` (legacy narrative `MASTG-TEST-0009`, deprecated). Runtime-only angle: static reads
  `allowBackup`/`dataExtractionRules`; only a real backup shows **which sensitive files actually ride off-device**
  after the STORAGE-1 write. Cmd:
  ```
  adb backup -f app.ab -noapk <pkg>          # confirm on the device prompt
  # convert the .ab (TAR-ish) and inspect:
  java -jar abe.jar unpack app.ab app.tar && tar -tf app.tar
  # search the extracted tree for the marked secret written during the flow
  ```
  **Interpretation (gate):** `adb backup` is deprecated and a **no-op on many modern OEM/OS builds** — an empty
  archive means *backup unsupported on this device*, **not** "data excluded". Confirm the backup actually
  captured *something* before concluding either way; a populated archive missing the secret = excluded (safe).
- **Sensitive data in process memory (runtime-ONLY; static is blind)** → MASVS-STORAGE-1 · closest weakness
  MASWE-0118 (*Sensitive Data Not Removed After Use* — note: no MASVS-STORAGE MASWE is scoped specifically to
  in-RAM secrets; *weakness mapping to confirm*) · **MASTG-TEST-0011** *Testing Memory for Sensitive Data* via
  **MASTG-TECH-0044**.
  Cmd:
  ```
  objection -g <pkg> explore
  memory dump all mem.bin
  # host:
  strings -n 6 mem.bin | grep -iE '<known-secret>|bearer |-----BEGIN'
  ```
  (or Fridump.) Capture **right after** the secret is used; GC may clear it later — repeat to confirm.

## CRYPTO — the *actual* algorithm/mode/IV/key at call time
Runtime-only angle: obfuscated/dynamically-loaded crypto and **runtime-derived keys** are invisible to jadx.
Hooking `Cipher`/`KeyGenerator`/`Mac` reveals the real transformation, key, and IV **bytes** at the call.

- **Broken symmetric mode at runtime** (ECB, unauthenticated CBC) → MASVS-CRYPTO-1 · MASWE-0020 (*Improper
  Encryption*) · **MASTG-TEST-0350** *Runtime Use of Broken Symmetric Encryption Modes*.
- **Reused IV/nonce at runtime** → MASVS-CRYPTO-1 · MASWE-0020/-0022 · **MASTG-TEST-0310** *Runtime Use of
  Reused Initialization Vectors in Symmetric Encryption*.
- **Asymmetric key reused across purposes** → MASVS-CRYPTO-2 · MASWE-0012 (*Insecure or Wrong Usage of
  Cryptographic Key*) · **MASTG-TEST-0308** *Runtime Use of Asymmetric Key Pairs Used For Multiple Purposes*.
  Cmd (see the transformation, the IV, the key bytes):
  ```
  frida-trace -U -f <pkg> -j 'javax.crypto.Cipher!getInstance' -j 'javax.crypto.Cipher!init' -j 'javax.crypto.Cipher!doFinal'
  ```
  Print the `transformation` arg, the `IvParameterSpec`, and the `SecretKey.getEncoded()` in the handler.

## NETWORK — the wire (deepen + correct IDs)
- **Cleartext on the wire** → MASVS-NETWORK-1 · MASWE-0050 (cleartext transmission) · **MASTG-TEST-0236**
  *Cleartext Traffic Observed on the Network* + **MASTG-TEST-0238** *Runtime Use of Network APIs Transmitting
  Cleartext Traffic*. *(replaces legacy `MASTG-TEST-0019`.)*
  Cmd: `mitmproxy --mode regular` (device proxy set); flag any `http://` request to a non-localhost host.
- **Insecure TLS protocol negotiated** → MASVS-NETWORK-1 · MASWE-0050 · **MASTG-TEST-0218** *Insecure TLS
  Protocols in Network Traffic* — the live counterpart of static TLS-config checks; the dynamic file **owns**
  this. Cmd: read the negotiated version in the proxy's TLS detail, or `tshark -Y ssl.handshake`.
- **Missing / ineffective pinning** → MASVS-NETWORK-2 · MASWE-0047 (missing pinning) · **MASTG-TEST-0244**
  *Missing Certificate Pinning in Network Traffic* via **MASTG-TECH-0012**. Keep the **Android-7 user-CA gotcha**.
  Cmd: `objection -g <pkg> explore` → `android sslpinning disable`, then retry the proxy. (Legacy: `-0022`;
  static NSC siblings `-0242` NSC, `-0243` expired pins.)
- **Server-trust / accept-all (custom TrustManager / hostname verifier)** → MASVS-NETWORK-1 · MASWE-0052
  (*Insecure Certificate Validation* — the precise weakness for accept-all trust / broken hostname checks,
  **distinct from** missing pinning MASWE-0047) · static anchors **MASTG-TEST-0282** *Unsafe Custom Trust
  Evaluation* / **MASTG-TEST-0283** *Incorrect Implementation of Server Hostname Verification* ·
  confirmed by MITM with a **trusted CA and NO pinning bypass**: if HTTPS intercepts with the CA simply trusted
  → trust is broken/over-permissive. This is **distinct from** missing pinning — record which.

## PLATFORM — live IPC / deep-link / WebView exploitation
- **Exported activity/service/receiver exploitation** → MASVS-PLATFORM-1 · MASWE-0119/0062/0063 (exposed IPC) ·
  anchors **MASTG-TEST-0364** (activities) / **-0365** (services) / **-0366** (broadcast receivers); legacy
  umbrella `MASTG-TEST-0029`.
  Cmd: `adb shell am start -n <pkg>/<cls> --es key val`; or
  `drozer ... run app.activity.start`, `run app.service.start`, `run app.broadcast.send` — observe the
  privileged action actually firing.
- **ContentProvider read / SQLi / path traversal** → MASVS-PLATFORM-1 (entry) / MASVS-CODE-4 (the SQLi) ·
  MASWE-0064 / MASWE-0086 · **MASTG-TEST-0356** *Runtime Verification of Unauthorized Database Access through
  Content Providers* (static sibling **-0355**); SQLi static anchor `MASTG-TEST-0339`.
  Cmd:
  ```
  drozer> run app.provider.query content://<auth>/<path>
  drozer> run scanner.provider.injection -a <pkg>
  drozer> run scanner.provider.traversal -a <pkg>
  ```
- **Deep link / App Link exploitation** → MASVS-PLATFORM-1 · MASWE-0058 (insecure deep link) · atomic
  **MASTG-TEST-0393** *Use of Unverified App Links* + **MASTG-TEST-0394** *Missing Input Validation in Custom URL
  Scheme Handlers* (legacy umbrella `MASTG-TEST-0028` *Testing Deep Links*).
  Cmd: `adb shell am start -a android.intent.action.VIEW -d "<scheme>://<host>/<path>?p=<payload>"` — trace
  where the param lands (WebView `loadUrl`, OAuth redirect capture, file/SQL sink).
- **WebView JS-bridge live** → MASVS-PLATFORM-2 · MASWE-0068 (*JavaScript Bridges in WebViews* — the
  `addJavascriptInterface` bridge itself) **and** MASWE-0069 (*WebViews Allows Access to Local Resources* — the
  CP/file reach the cited runtime tests exercise) · **MASTG-TEST-0251** *Runtime Use of Content Provider Access
  APIs in WebViews* + **MASTG-TEST-0253** *Runtime Use of Local File Access APIs in WebViews* (native-bridge
  static anchor **MASTG-TEST-0334** *Native Code Exposed Through WebViews*).
  Cmd: if `setWebContentsDebuggingEnabled(true)` → `chrome://inspect`; else hook `addJavascriptInterface` and
  call the bridge from injected JS via Frida.
- **Screenshot / recents leakage** → MASVS-PLATFORM-3 · MASWE-0055 (sensitive data via screenshots) ·
  **MASTG-TEST-0289** *Runtime Verification of Sensitive Content Exposure in Screenshots During App
  Backgrounding* (static siblings around `-0291…-0294`, legacy `-0010`).
  Cmd: open a sensitive screen → Home → inspect the recents thumbnail / `/data/system_ce/<user>/snapshots`.
  Check whether `FLAG_SECURE` is set.

## AUTH — token/session lifetime, biometric bypass, client-authz tamper (runtime-ONLY)
- **Live token/session/refresh handling** → MASVS-AUTH-1 · MASWE-0036/-0037/-0038 (session/token handling) ·
  **no atomic runtime test exists → descriptive: "Runtime token/session lifecycle observation (ID to confirm)"**.
  On the wire via the proxy + decode JWTs: token never rotating, refresh token replayable, `exp` not enforced
  server-side, token leaking in URL/query. *Static cannot watch a token rotate or a refresh fire — this is
  runtime-only.*
- **Client-side authorization tamper** → MASVS-AUTH-1 · MASWE-0042 (*Authorization Enforced Only Locally
  Instead of on the Server-side*) · hook the
  `isAdmin`/`isPremium`/role gate and observe the privileged action proceed → proves the gate is **client-only**
  (via `MASTG-TECH-0043`). Cmd:
  ```
  frida -U -f <pkg> -l hook.js   # hook returns true:
  # Java.use('com.app.Session').isAdmin.implementation = function(){ return true; };
  ```
- **Biometric / local-auth bypass** → MASVS-AUTH-2 · **MASWE-0044** *Biometric Authentication Can Be Bypassed*.
  **HONEST NEGATIVE:** there is **no Android *runtime* biometric atomic test** — the Android AUTH atomic tests
  (`MASTG-TEST-0326`…`-0330`) are static "References to…" and `MASTG-TEST-0018` is the legacy narrative test;
  the runtime biometric tests `MASTG-TEST-0267/-0269/-0271` and `MASTG-TECH-0135` are **iOS-only**. So on
  Android cite **MASWE-0044 + the technique**, not an iOS test id.
  Cmd: `objection -g <pkg> explore` → `android ui biometrics_bypass` (or Frida-hook
  `onAuthenticationSucceeded`). **Interpretation:** if flipping the success callback unlocks the flow →
  event-bound (bypassable, real finding); if it still fails because a Keystore **`CryptoObject`** is required →
  properly crypto-bound (**not** a vuln — see false-positives).

## CODE — injection firing, dynamic code load, native memory (runtime-ONLY)
- **Tainted untrusted input reaching a sink at runtime (CODE-4 taint trace; runtime-ONLY)** → MASVS-CODE-4 ·
  MASWE by **source channel**: network **MASWE-0079** (*Unsafe Handling of Data from the Network*) / IPC extras
  **MASWE-0084** (*Unsafe Handling of Data from IPC*) / deep-link & external interfaces MASWE-0081 / backup
  MASWE-0080 / local-storage MASWE-0082 / UI MASWE-0083 · **no atomic runtime test for the source→sink case** →
  descriptive: *"Runtime taint observation, source channel <X> (ID to confirm)"* via **MASTG-TECH-0043**.
  Runtime-only angle: static infers a *possible* source→sink path; a run **proves the attacker-controlled value
  actually arrives at the sink unsanitized**. Inject a marked payload into the channel, hook the sink, confirm
  the marker lands there intact. Cmd:
  ```
  # 1) feed a marked taint via a channel (deep link shown; or IPC extra / proxy-tampered response):
  adb shell am start -a android.intent.action.VIEW -d "<scheme>://h/p?q=TAINT_$(date +%s)"
  # 2) hook the sink and confirm the marker reaches it unescaped:
  frida-trace -U -f <pkg> \
    -j 'android.database.sqlite.SQLiteDatabase!rawQuery' \
    -j 'android.webkit.WebView!loadUrl' \
    -j 'java.lang.Runtime!exec'
  ```
  **Interpretation (gate):** the marker reaching the sink **after** validation/parameterization is not a finding;
  the raw marker landing in `rawQuery`/`loadUrl`/`exec` unsanitized is. One observation is a **lead** — repeat,
  and confirm the source is genuinely attacker-controllable (a same-process trusted caller is not).
- **SQLi / injection confirmed firing** → MASVS-CODE-4 · MASWE-0086 (*SQL Injection*) · static anchor
  `MASTG-TEST-0339`; runtime confirmation via the drozer provider injection above — observe **data returned**,
  not just the string concat.
- **Unsafe dynamic code loading at runtime** → MASVS-CODE-4 · MASWE-0085 (dynamic code loading) · **no atomic
  test → descriptive (ID to confirm)**: hook `DexClassLoader`/`System.load`/`dlopen` to capture the path/bytes
  loaded at runtime. Cmd: `frida-trace -U -f <pkg> -j 'dalvik.system.DexClassLoader!$init'` and native
  `frida-trace -U -f <pkg> -i 'dlopen'`.
- **Native memory-safety** → MASVS-CODE-4 · attach `lldb`/Frida (`MASTG-TECH-0031`/`-0034`) to a crashing
  native routine; static defers buffer-overflow confirmation to dynamic.

## RESILIENCE (R profile) — does the control *actually fire*, and is it bypassable?
Runtime-only: static cannot judge **efficacy**. This is exactly where static `Needs dynamic verification`
lands.
- **Root detection effectiveness** → MASVS-RESILIENCE-1 · MASWE-0097 (*Root/Jailbreak Detection Not
  Implemented*) · **MASTG-TEST-0325** *Runtime Use of Root Detection Techniques* via bypass `MASTG-TECH-0144`.
  Cmd: `objection -g <pkg> explore` → `android root disable`; observe whether the app still detects/quits.
- **Anti-tampering EFFICACY — repackage, re-sign, reinstall, observe (RESILIENCE-2; runtime-ONLY)** →
  MASVS-RESILIENCE-2 · MASWE-0104 (*App Integrity Not Verified*) · **no runtime atomic TEST id exists** (the
  static resilience file defers integrity-self-check efficacy to dynamic) → descriptive: *"Runtime
  repackaging/integrity self-check efficacy (ID to confirm)"* via repackage `MASTG-TECH-0026` (Frida-Gadget
  repackage path / apktool) + signing. This is the **runtime lane the static RESILIENCE-2 check defers to**:
  static sees *whether* a `signingInfo`/cert-SHA self-check exists; only a run proves it **actually fires** when
  the signing key changes. Cmd:
  ```
  apktool d app.apk -o out && apktool b out -o repacked.apk
  keytool -genkey -v -keystore evil.jks -alias x -keyalg RSA -keysize 2048 -validity 365   # DIFFERENT key
  apksigner sign --ks evil.jks repacked.apk
  adb install -r repacked.apk    # then launch and watch
  ```
  **Interpretation (gate):** if the app **launches and runs normally** under the foreign signing key → the
  integrity / signature self-check is **absent or ineffective** (real MASWE-0104 finding). If it **detects and
  refuses / degrades** → the control fired (downgrade/drop — honest negative). Distinguish a *crash* (could be a
  broken repack, not a deliberate check) from a *clean integrity refusal*; reproduce before promoting, and weigh
  against the **R-profile** (these raise attacker cost, they are not unbreakable).
- **Emulator detection effectiveness** → MASVS-RESILIENCE-1 (platform-integrity / virtual-environment
  detection) · MASWE-0099 (*Emulator Detection Not Implemented*) · **MASTG-TEST-0351** *Runtime Use of Emulator
  Detection Techniques*.
- **Anti-hook / anti-instrumentation effectiveness** → MASVS-RESILIENCE-4 · MASWE-0102/-0103 · **MASTG-TEST-0341**
  *Runtime Use of Hook Detection Techniques* — runtime-only: does attaching Frida itself get detected/killed?
- **Anti-debug effectiveness** → MASVS-RESILIENCE-4 · MASWE-0101 · **MASTG-TEST-0353** *Runtime Use of Debugging
  Detection APIs* via `MASTG-TECH-0031`. Cmd: attach `jdb`/lldb (or set `debuggable`) and see if the app reacts.

## PRIVACY — declared-vs-actual collection / PII on the wire (runtime-ONLY)
- **Persistent-identifier tracking actually read + transmitted (PRIVACY-2; runtime-ONLY)** → MASVS-PRIVACY-2 ·
  MASWE-0110 (*Use of Unique Identifiers for User Tracking*) · **no atomic Android runtime test is scoped to
  identifiers** (the PRIVACY runtime catalog is `-0319` SDK-APIs→MASWE-0112 and `-0206` PII-on-wire→MASWE-0108) →
  descriptive: *"Runtime identifier-tracking observation (ID to confirm)"* via **MASTG-TECH-0043** (Method
  Hooking). Runtime-only angle: static sees the *call site*; only a run shows the **persistent id actually
  resolved** and whether it then **leaves the device**. Hook `getAdvertisingId`, `Settings.Secure.ANDROID_ID`,
  and `MediaDrm` unique-id, log the value, then correlate that exact value against proxy traffic.
  Cmd:
  ```
  frida-trace -U -f <pkg> \
    -j 'com.google.android.gms.ads.identifier.AdvertisingIdClient$Info!getId' \
    -j 'android.provider.Settings$Secure!getString' \
    -j 'android.media.MediaDrm!getPropertyByteArray'
  # then grep the captured id in mitmproxy flows -> sent to ad/analytics/undeclared host = MASWE-0110 + MASWE-0108
  ```
  **Interpretation (gate):** a per-install cache-key read that never leaves the device is *not* tracking — only
  a persistent id **transmitted** for cross-session/cross-install correlation (correlate with NETWORK, confirm
  in transit) is the finding. `ANDROID_ID` is per-app-signing-key+user since Android 8 — note that before
  calling it cross-app tracking.
- **Actual SDK data collection** → MASVS-PRIVACY-3 · MASWE-0112 (undisclosed/over-collection) · **MASTG-TEST-0319**
  *Runtime Use of SDK APIs Known to Handle Sensitive User Data* (the runtime sibling of the static SDK survey).
  Cmd: hook the analytics/ad-SDK collection entry points and log the payload before transmission.
- **Undeclared PII in traffic** → MASVS-PRIVACY-3 / -1 · MASWE-0108 (*Sensitive Data in Network Traffic*) ·
  **MASTG-TEST-0206** *Undeclared PII in Network Traffic Capture* (proxy capture — the runtime confirmation the
  static privacy pass defers). Cmd: capture in mitmproxy, grep the body for advertising ID, IMEI, email, geo.

---

## Fusing with static (confidence)
- Static-confirmed code path **+** dynamic observation → `Confirmed`; record as **one** finding (don't
  double-count the suspicion and its confirmation).
- Static suspicion, dynamic **not** run → keep `Needs dynamic verification` and state what a run would check.
- Static suspicion, dynamic **disproves** it (e.g. pinning held even after CA install; biometric is
  CryptoObject-bound) → **downgrade/drop** and note it (honest negatives are valuable).
- Pure runtime-only discovery (memory secret, live token replay, exported-component exploit) → it is a finding
  on its own; trace it MASVS→MASWE→MASTG anyway.

---

## Mode 2 — targeted assist ("help me test X" → run this, no full report)
| Ask | Go straight to |
|---|---|
| "test the pinning" | `objection -g <pkg> explore` → `android sslpinning disable`, retry proxy. Still blocked? Frida CodeShare universal-unpinning script. Interpret via the **Android-7 user-CA gotcha** before calling it pinning. (`MASTG-TECH-0012` / `MASTG-TEST-0244`) |
| "bypass root detection" | `objection ... android root disable` (or `MASTG-TECH-0144`); watch if the app still detects → efficacy of `MASTG-TEST-0325`. |
| "dump secrets from memory" | `objection -g <pkg> explore` → `memory dump all mem.bin`, then `strings mem.bin | grep -i <secret>` (`MASTG-TEST-0011` / `MASTG-TECH-0044`). |
| "is this deep link exploitable" | `adb shell am start -a android.intent.action.VIEW -d "<scheme>://<host>/<path>?p=<payload>"`; trace where the param lands. |
| "see the crypto it actually uses" | `frida-trace -U -f <pkg> -j 'javax.crypto.Cipher!getInstance' -j 'javax.crypto.Cipher!init'` (`MASTG-TEST-0350/-0310`). |
| "can the biometric be bypassed" | `objection ... android ui biometrics_bypass`; if flow unlocks → event-bound bypass; if CryptoObject-bound it won't (`MASWE-0044`). |
| "hit the exported component" | `drozer ... run app.activity.start` / `am start -n <pkg>/<cls> --es k v`. |

---

## Dynamic false positives / honest negatives
| Observation | Naive (wrong) call | Disambiguate |
|---|---|---|
| HTTPS won't intercept | "App pins certs" | Could be the **Android-7 user-CA default**. Install CA in the **system** store / repackage NSC → if it then intercepts, it was the CA default, **not** pinning. |
| Bypass script "did nothing" | "Control is absent" | The hook may not have **fired** (wrong API hooked, obfuscated impl, gadget not injected). Confirm the hook loaded (log on entry) before concluding the control is absent. |
| Crash / odd behaviour on test device | "Found a bug" | Could be **emulator/root detection** reacting, not an app defect. Reproduce on a clean device/config. |
| Value present on a rooted device | "Leak in the field" | May be a **root/emulator artifact**, not normal-device behaviour. |
| One intercepted request / one observation | "Confirmed finding" | A single run is a **lead**, not a confirmation. **Repeat** before promoting to `Confirmed`. |
| `biometrics_bypass` flips a boolean and UI advances | "Biometric bypassable" | If the secret is **Keystore `CryptoObject`-bound**, the UI event flips but the crypto op still fails → **not** a vuln. Distinguish **event-bound** (real) from **crypto-bound** (safe). |
| Control bypassed with Frida/objection | "Broken in the field" | A control bypassed on a **prepared test device** is expected; weigh against the **R-profile** threat model — R controls raise cost, they are not unbreakable. |
| Memory `strings` hit | "Secret stored insecurely" | Transient in-use buffers are often unavoidable; weigh **persistence/lifetime** and whether it survives after the operation. Re-dump later. |

---

## Runtime / dynamic MASTG-TEST id table (verified live, June 2026)
| Area | MASWE | Runtime test | Technique | Tool |
|---|---|---|---|---|
| STORAGE | 0006 | `MASTG-TEST-0207` (sandbox) · `-0287` (SharedPreferences) | `TECH-0044` | adb `run-as`, objection |
| STORAGE | 0007 | `MASTG-TEST-0201` (external storage) | `TECH-0032` | frida-trace |
| STORAGE | 0001 | `MASTG-TEST-0203` (logging APIs) | `TECH-0009` | logcat |
| STORAGE | 0054 | `MASTG-TEST-0315` (notifications; trace builder at runtime) | `TECH-0043` | frida-trace `NotificationCompat$Builder` |
| STORAGE | 0003/0004 | *(no runtime atomic — run the technique)* backup exfil | `TECH-0128/-0127` | adb backup, abe.jar |
| STORAGE | 0118 (*closest; mapping to confirm*) | `MASTG-TEST-0011` (memory) | `TECH-0044` | objection `memory dump`, Fridump |
| CRYPTO | 0020 | `MASTG-TEST-0350` (broken symmetric mode) | `TECH-0043/-0032` | frida-trace `Cipher` |
| CRYPTO | 0020/0022 | `MASTG-TEST-0310` (reused IV) | `TECH-0043` | frida-trace `Cipher.init` |
| CRYPTO | 0012 | `MASTG-TEST-0308` (asymmetric key multi-purpose) | `TECH-0043` | Frida hook |
| NETWORK | 0050 | `MASTG-TEST-0236` (cleartext on wire) · `-0238` (cleartext APIs) | `TECH-0011` | mitmproxy |
| NETWORK | 0050 | `MASTG-TEST-0218` (insecure TLS) | `TECH-0011` | proxy / tshark |
| NETWORK | 0047 | `MASTG-TEST-0244` (missing pinning) | `TECH-0012` | objection, mitmproxy |
| PLATFORM | 0119/0062/0063 | `MASTG-TEST-0364/-0365/-0366` (exported act/svc/recv) | `TECH-0049` | adb `am`, drozer |
| PLATFORM | 0064/0086 | `MASTG-TEST-0356` (provider runtime) | `TECH-0049` | drozer `scanner.provider.*` |
| PLATFORM | 0068/0069 | `MASTG-TEST-0251` (CP-in-WebView) · `-0253` (file-in-WebView) | `TECH-0043` | chrome://inspect, Frida |
| PLATFORM | 0055 | `MASTG-TEST-0289` (screenshot/backgrounding) | `TECH-0049` | adb, recents inspect |
| AUTH | 0044 | *(no Android runtime atomic — descriptive)* biometric bypass | `TECH-0043` | objection `biometrics_bypass` |
| AUTH | 0042 | *(client-authz tamper; no runtime atomic test — descriptive)* | `TECH-0043` | Frida hook |
| AUTH | 0036/0037/0038 | *(token/session lifecycle; no runtime atomic test — descriptive)* | `TECH-0011` | proxy + JWT decode |
| CODE | 0079/0084/0081/0082/0083 | *(taint source→sink; no runtime atomic — descriptive, by channel)* | `TECH-0043` | frida-trace sink hooks, am start |
| CODE | 0086 | static `MASTG-TEST-0339`; runtime via drozer provider injection | `TECH-0049` | drozer |
| CODE | 0085 | *(dynamic code load; no atomic test — descriptive)* | `TECH-0032/-0034` | frida-trace |
| RESILIENCE | 0104 | *(no runtime atomic — repackage/re-sign/reinstall efficacy)* | `TECH-0026` | apktool, apksigner, adb install |
| RESILIENCE | 0097 | `MASTG-TEST-0325` (root detection) | `TECH-0144` | objection `root disable` |
| RESILIENCE | 0099 | `MASTG-TEST-0351` (emulator detection) | `TECH-0049` | AVD |
| RESILIENCE | 0102/0103 | `MASTG-TEST-0341` (hook detection) | `TECH-0043` | Frida attach |
| RESILIENCE | 0101 | `MASTG-TEST-0353` (debugging detection) | `TECH-0031` | jdb / lldb |
| PRIVACY | 0112 | `MASTG-TEST-0319` (SDK sensitive-data APIs) | `TECH-0043` | Frida hook |
| PRIVACY | 0108 | `MASTG-TEST-0206` (undeclared PII on wire) | `TECH-0011` | mitmproxy |

### Legacy → atomic map (prefer the atomic id; cite legacy as "(legacy)")
| Legacy | Topic | Atomic successor(s) |
|---|---|---|
| `MASTG-TEST-0019` | data encryption on the network | `-0236` + `-0238` |
| `MASTG-TEST-0021` | endpoint identity verification (hostname/trust) | `-0234`/`-0283` (hostname verification) · `-0282` (custom trust eval) |
| `MASTG-TEST-0020` | TLS settings / protocol versions | `-0217` (static) · `-0218` (in traffic) |
| `MASTG-TEST-0022` | custom cert stores / pinning | `-0242` (NSC) · `-0243` (expired pins) · `-0244` (runtime MITM) |
| `MASTG-TEST-0023` | testing the security provider (GMS/ProviderInstaller) | `-0295` (GMS provider not updated) |
| `MASTG-TEST-0029` | sensitive functionality via IPC | `-0364/-0365/-0366` (components) · `-0356` (provider) |
| `MASTG-TEST-0028` | deep link handling | `-0393` (unverified App Links) · `-0394` (custom-scheme input validation) |
| `MASTG-TEST-0010` | auto-generated screenshots | `-0289` |
| `MASTG-TEST-0018` | biometric auth (narrative) | no Android runtime atomic; use MASWE-0044 + technique |

> **ID hygiene.** MASTG is mid-refactor: atomic `-02xx/-03xx` tests live under `tests-beta/` on GitHub but
> resolve under `/tests/` on `mas.owasp.org`; MASWE is Beta. Prefer the atomic id, note legacy, and where no
> atomic test exists give a descriptive name + "(ID to confirm)" — never invent an id.
