# Dynamic Environment Setup (shared, Android + iOS)

Shared groundwork for any dynamic pass. The platform files (`android-dynamic.md`, `ios-dynamic.md`) cover what
to *confirm*; this file covers two things: (1) getting a usable, instrumented, intercepting environment first, and
(2) using that environment as an **offensive / discovery lane** for the runtime-only issues static cannot see.

> **Authorization & human-in-the-loop (non-negotiable).** Set up a dynamic environment only for an artifact you
> are **authorized** to test, within the recorded Rule-Zero scope. Re-confirm authorization/scope before you
> instrument. Dynamic testing is **operator-driven**: the tooling observes while a human exercises the app's real
> flows (login, payment, etc.). Everything here — rooting/jailbreaking, CA installation, instrumentation, pinning
> bypass, biometric/root bypass — is for **authorized testing on a dedicated test device**, never a
> production/personal device or an app you don't own or have permission for. And: **never fabricate dynamic
> output.** If a step wasn't actually run, the corresponding findings stay `Needs dynamic verification`. A single
> observation is not a reproducible one.

> **Legacy vs atomic IDs (MASTG is mid-refactor).** Atomic runtime tests (`MASTG-TEST-02xx/03xx`) live under
> `tests-beta/` on GitHub but resolve under `/tests/` on the site; legacy narrative tests (`-0011`, `-0029`,
> `-0060`) still exist alongside. Prefer the atomic runtime id and note uncertainty. **MASWE is Beta.** Verify
> every cited id against the live guide.

---

## 1. Test device
- **Android**: a **rooted** physical device or an emulator (AVD). No root? Repackage the app with the **Frida
  Gadget** — technique **MASTG-TECH-0026** *"Dynamic Analysis on Non-Rooted Devices"* — to instrument without root.
- **iOS**: a **jailbroken** device (preferred — `frida-server` injects even into FairPlay-encrypted apps, because
  it attaches to the decrypted-in-memory process; entry technique **MASTG-TECH-0067** *"Dynamic Analysis on iOS"*,
  shell access **MASTG-TECH-0052** *"Accessing the Device Shell"* via SSH). No jailbreak? Repackage with the Frida
  Gadget (`MASTG-TECH-0090` automatic / `-0091` manual injection) — only for a **non-FairPlay** binary. The **iOS
  Simulator is not an emulator**; **Corellium** is the only public virtual iOS.
- Use a **dedicated, disposable** test device/profile with no personal data. Record device/OS/jailbreak-or-root
  state in the report — emulator/root/jailbreak artifacts change app code paths (see false-positives below).

## 2. Instrumentation (Frida / objection / dumpers)
- Install matching **Frida** (`MASTG-TOOL-0031` generic; `MASTG-TOOL-0001` Frida Android; `MASTG-TOOL-0039` Frida
  iOS) on host and **frida-server** on the device (Android: push + run as root; iOS: install on the jailbroken
  device, reachable over SSH — `iproxy 2222 22` for SSH-over-USB).
- Verify with `frida-ps -U` (USB) — you should see the device's processes.
- **objection** (`MASTG-TOOL-0038`, Frida-backed) gives one-command operations across both platforms: SSL-pinning
  bypass, root/jailbreak-detection bypass, Keychain/keystore/storage inspection, memory dump.
- **Memory / process dumpers** unlock the runtime-only memory lane: **Fridump** (`MASTG-TOOL-0106`) for a full
  memory dump; **r2frida** (`MASTG-TOOL-0036`) for live read/search; iOS **Process Exploration** is
  **MASTG-TECH-0096**.
- **iOS decrypt**: **Frida-ios-dump** (`MASTG-TOOL-0050`) pulls the decrypted IPA off a device — needed to do
  *static* work on a FairPlay binary; for *dynamic* work you instrument the live decrypted process directly.
- **drozer** (`MASTG-TOOL-0015`) drives Android IPC (activities, services, broadcast receivers, content providers).

**Tracing vs hooking are distinct techniques — do not conflate them (and `frida-trace` is *tracing*, not hooking):**
- **MASTG-TECH-0032** *"Execution Tracing"* — `frida-trace`/jdb/strace observe a method's inputs/outputs (e.g. log
  every `Cipher.init` IV). For native `.so` routines use **MASTG-TECH-0034** *"Native Code Tracing"*.
- **MASTG-TECH-0043** *"Method Hooking"* (Android) — *replace* a method's behavior (e.g. neuter a root check).
- (`MASTG-TECH-0033` *"Method Tracing"* exists, but per `android-dynamic.md` `frida-trace`-style method tracing
  is filed under Execution Tracing `-0032` / Native Code Tracing `-0034` — cite those, not `-0033`.)

## 3. Interception proxy + CA (the part people get wrong)
- Run **Burp** (`MASTG-TOOL-0077`), **OWASP ZAP** (`MASTG-TOOL-0079`), or **mitmproxy** on the host; point the
  device's Wi-Fi proxy (or an SSH tunnel) at it. **Prefer the platform-specific setup techniques:**
  `MASTG-TECH-0011` *"Setting Up an Interception Proxy"* (Android) / `MASTG-TECH-0063` *"Setting up an
  Interception Proxy"* (iOS). The generic `MASTG-TECH-0120` *"Intercepting HTTP Traffic Using an Interception
  Proxy"* (and `MASTG-TECH-0121` *"Intercepting Non-HTTP Traffic…"*) exist but are generic — cite the
  platform-specific ids above for an actual Android/iOS pass. For apps that ignore the system proxy, force
  traffic with **ProxyDroid** (`MASTG-TOOL-0120`, iptables).
- **Install and trust the proxy CA on the device** — without it, HTTPS won't decrypt and you'll
  *misdiagnose it as pinning.*
  - **Android (the API-24 gotcha):** since Android 7, apps ignore **user**-store CAs unless
    `network_security_config` opts in. So either install the CA into the **system** store (root) or repackage
    the app with an NSC trusting the `user` anchor. Only after the CA is trusted does a failed interception
    indicate **app-level pinning**.
  - **iOS:** install the CA profile and **enable full trust** (Settings → General → About → Certificate Trust
    Settings) — both steps are required.
- **Flutter / cross-platform caveat:** Flutter ignores the system proxy **and** the NSC, validating against
  bundled CAs. A trusted CA + clean proxy will see **nothing** from a Flutter app — that is *not* "all traffic
  encrypted." Use **MASTG-TECH-0109** (Android) / **MASTG-TECH-0110** (iOS) *"Intercepting Flutter HTTPS
  Traffic"*, or app-layer hooking **MASTG-TECH-0119** (`SSL_read`/`SSL_write`).
- Sanity check: browse a normal HTTPS site through the proxy and confirm clean decryption **before** blaming
  the target app.

## 4. Pinning bypass (only after the CA is trusted)
If traffic still won't intercept with a trusted CA, the app is pinning. For authorized testing:
- **objection**: `android sslpinning disable` / `ios sslpinning disable`.
- **Frida CodeShare**: `frida --codeshare <ssl-bypass-script>` for non-standard implementations.
- **iOS jailbroken**: SSL Kill Switch 2 (system-wide).
- **Android**: hook the pinning APIs (`MASTG-TECH-0043`), or patch/repackage the `network_security_config`/check
  and re-sign.
Confirming a bypass *is needed* is itself the evidence that pinning is present and effective
(MASVS-NETWORK-2 → MASWE-0047 *Insecure Identity Pinning* → atomic **MASTG-TEST-0244** *Missing Certificate
Pinning in Network Traffic*). This is **distinct from** MASWE-0052 *Insecure Certificate Validation* (accept-all
trust / broken hostname check) — keep the two separate.

---

## 5. Runtime-only DISCOVERY (offensive lane — what static can't see)
The prepared environment exists to find issues that have **no static signature**. Each row: MASVS → MASWE →
MASTG, and the exact command to RUN on an authorized device. Server-side authz/IDOR flaws are *server* findings
surfaced via the client; transport anchors NETWORK.

| Runtime-only issue (static is blind) | MASVS → MASWE → MASTG (verified) | Concrete command to RUN |
|---|---|---|
| **Sensitive data lingering in process memory** (tokens, PAN, keys not cleared after a flow) | MASVS-STORAGE-1 → **MASWE-0118** *Sensitive Data Not Removed After Use* *(closest weakness; mapping to confirm)* → **MASTG-TEST-0011** (Android) / **MASTG-TEST-0060** (iOS) *Testing Memory for Sensitive Data* | `objection -g <pkg> explore` → `memory dump all mem.bin` then `memory search <pattern>`; or **Fridump** (`MASTG-TOOL-0106`); iOS via Process Exploration `MASTG-TECH-0096` / r2frida `:dm` |
| **Live API / business-logic flaws on the wire** (IDOR, missing server-side authz, replay, mass-assignment) | AUTH-1 → **MASWE-0042** *Authorization Enforced Only Locally Instead of on the Server-side* (server finding via client); transport → NETWORK-1 · MASWE-0050 | Trusted-CA proxy; intercept + tamper a real request, swap another user's id, replay. Interception-proxy setup **MASTG-TECH-0011** (Android) / **MASTG-TECH-0063** (iOS) |
| **Weak session / token / refresh handling** (token not rotated, long-lived JWT, refresh/old token accepted after logout) | AUTH-1 → **MASWE-0038** *Authentication Tokens Not Validated* → *no atomic test; "Runtime session/token handling" (ID to confirm)* | Capture login → note token → logout → **replay old token** through Burp; observe acceptance |
| **Live IPC / deep-link / app-link exploitation** firing a sensitive action | PLATFORM-1 → **MASWE-0059** *Unauthenticated Platform IPC* / **MASWE-0058** *Insecure Deep Links* → **MASTG-TEST-0029** (IPC exposure) + **MASTG-TEST-0028** (Deep Links); content-provider access **MASTG-TEST-0356** | `adb shell am start -a android.intent.action.VIEW -d "<scheme>://..."`; `drozer` `run app.activity.start` / `app.provider.query`; iOS **MASTG-TEST-0075** custom URL schemes / **-0070** Universal Links |
| **WebView JS-bridge reachable from injected JS** (native method callable at runtime) | PLATFORM-2 → **MASWE-0068** *JavaScript Bridges in WebViews* → **MASTG-TEST-0334** *Native Code Exposed Through WebViews*; runtime WebView file/content access **MASTG-TEST-0251 / -0253** | Android: `chrome://inspect` (if debuggable) or Frida-hook `addJavascriptInterface`; iOS: attach Safari Web Inspector via **MASTG-TECH-0139** *"Attach to WKWebView"* |
| **Biometric / local-auth bypass** (boolean-gated `LAContext`/`BiometricPrompt`, result not bound to Keychain/Keystore crypto) | AUTH-2 → **MASWE-0044** *Biometric Authentication Can Be Bypassed* (/ **MASWE-0045** *Fallback to Non-biometric Credentials Allowed for Sensitive Transactions*) → iOS **MASTG-TEST-0269** *Runtime Use Of APIs Allowing Fallback to Non-Biometric Authentication* (the atomic runtime test pairing 0045; no dedicated runtime test for 0044), technique **MASTG-TECH-0135** *"Bypassing Biometric Authentication"* | `objection -g <pkg> explore` → `ios ui biometrics_bypass`; if it flips a boolean-only check → not crypto-bound → bypassable |
| **Runtime crypto misuse** (reused IV, ECB, key reuse) — only the *call* reveals it | CRYPTO-1 → **MASWE-0022** *Predictable Initialization Vectors (IVs)* (broken modes → **MASWE-0020** *Improper Encryption*, also CRYPTO-1; key reuse → **MASWE-0012**, CRYPTO-2) → **MASTG-TEST-0310** *Runtime Use of Reused Initialization Vectors in Symmetric Encryption*, **MASTG-TEST-0350** *Runtime Use of Broken Symmetric Encryption Modes* | `frida-trace` (Execution Tracing `MASTG-TECH-0032`; hook via `MASTG-TECH-0043`) on `javax.crypto.Cipher.init/doFinal`; log IV/mode/key bytes |
| **Server-trust / MITM actually succeeds** (accept-all trust / broken hostname check, reachable only at runtime) | NETWORK-1 → **MASWE-0052** *Insecure Certificate Validation* (static anchors **MASTG-TEST-0282** custom trust eval / **MASTG-TEST-0283** hostname verification; cleartext observed via **MASTG-TEST-0236**) — **distinct from** missing pinning (MASWE-0047 → MASTG-TEST-0244) | Trusted-CA proxy; decrypt **without** any bypass = trust broken/over-permissive. Distinguish accept-all trust from missing pinning |
| **Anti-instrumentation / anti-debug behaviour** (does it actually detect Frida/debugger, and what does it do) | RESILIENCE-4 (anti-instrumentation) → **MASWE-0101** *Debugger Detection Not Implemented* / **MASWE-0102** *Dynamic Analysis Tools Detection Not Implemented* → **MASTG-TEST-0353** (debug), **-0341** (hook); iOS **-0354** (hook). **RESILIENCE-1** (platform-integrity, separate controls) → root MASWE-0097 **-0325**, emulator MASWE-0099 **-0351**; iOS jailbreak **-0241**, virtual device **-0367** | Attach `frida-ps -U`; observe crash/exit/no-op; then `MASTG-TECH-0144` (Android root-detection bypass) / objection to characterize |
| **iOS FairPlay-encrypted App Store binary** — static reads ciphertext, so dynamic is the **PRIMARY** lane | cross-cutting; enables every row above on a store IPA | Decrypt with **Frida-ios-dump** (`MASTG-TOOL-0050`) for static, or instrument live via `frida-server` (`MASTG-TECH-0067`) which injects into the decrypted-in-memory process |

---

## 6. Per-MASVS-area runtime checks (once the environment is up)
Mirrors the static references' per-area layout. Each = exercise the flow, then run the check. All IDs verified live.

- **STORAGE** — Android `MASTG-TEST-0207` (unencrypted in sandbox), `-0287` (SharedPreferences), `-0203`
  (logging APIs), `-0011` (memory); iOS `-0301` (unencrypted private storage), `-0296` (logs), `-0298` (backup),
  `-0314` (keyboard caching), `-0060` (memory). **Run:** exercise flow → `adb` read the app data dir; iOS
  `objection ios keychain dump` / inspect sandbox.
- **CRYPTO** — Android `MASTG-TEST-0204` (insecure random), `-0205` (non-random sources), `-0308` (asymmetric key
  reuse), `-0310` (reused IV), `-0350` (broken symmetric modes); iOS `-0311` / `-0349` (insecure random).
  **Run:** Frida `frida-trace` on crypto APIs (Execution Tracing `MASTG-TECH-0032`; native `.so` `MASTG-TECH-0034`).
- **NETWORK** — `MASTG-TEST-0236` (cleartext observed), `-0238` (cleartext network APIs at runtime), `-0218` /
  iOS `-0348` (insecure TLS in traffic), `-0244` (missing pinning in traffic); iOS `-0323` (low-level cleartext).
  **Flutter:** use `MASTG-TECH-0109/-0110/-0119`, **not** the standard proxy.
- **PLATFORM** — `MASTG-TEST-0029` (IPC), `-0028` (deep links), `-0356` (unauthorized DB via content providers),
  `-0251/-0253/-0334` (WebView runtime), `-0289` / iOS `-0290` (screenshots), `-0315` (notifications); iOS
  `-0277` (pasteboard at runtime, technique `MASTG-TECH-0134`), `-0336` (relaxed WebView file origin),
  `-0361/-0363` (purpose strings / entitlements).
- **AUTH** — iOS `MASTG-TEST-0267` (event-bound biometric), `-0269` (fallback to non-biometric), `-0271`
  (enrollment-change detection); technique `MASTG-TECH-0135`.
- **CODE** — enforced-updating has **no confirmed runtime atomic test**; use the legacy static ids
  `MASTG-TEST-0036` (Android) / `MASTG-TEST-0080` (iOS) *(atomic successor to confirm)*. Do **not** cite
  `MASTG-TEST-0382`/`-0384` as confirmed runtime code tests.
- **RESILIENCE** — the detection-effectiveness tests are the **only** way to prove a control is *effective* vs
  merely *present* (static sees presence only): Android `-0325/-0341/-0351/-0353`; iOS `-0241/-0246/-0354/-0367`.
- **PRIVACY** — surfaced via PLATFORM runtime checks (notifications `-0315`, pasteboard, screenshots, purpose
  strings `-0361`) — privacy leakage is observed while exercising flows, not from the manifest alone.

---

## 7. Mode-2 targeted-assist dispatch (one ask → one step, no full report)
When the user asks for **one** thing, jump straight to it.

| Trigger | Technique / id | Runnable step |
|---|---|---|
| "test the pinning" | proxy setup `MASTG-TECH-0011` (Android) / `MASTG-TECH-0063` (iOS); bypass `MASTG-TECH-0012` (Android) / `MASTG-TECH-0064` (iOS); `MASTG-TEST-0244` | Confirm CA in **system** store first (API-24!), browse a control site, then `objection -g <pkg> explore` → `android/ios sslpinning disable`; if proxy now decrypts → pinning present & bypassable |
| "check memory for secrets" | `MASTG-TEST-0011`/`-0060`, `MASTG-TECH-0096` | `objection -g <pkg> explore` → `memory dump all mem.bin` → `memory search <pattern>`; repeat **after** the flow ends |
| "bypass biometric" | `MASTG-TECH-0135`, `MASWE-0044` | `objection -g <pkg> explore` → `ios ui biometrics_bypass`; flips boolean-only → not crypto-bound |
| "exploit the deep link" | `MASTG-TEST-0028`/`-0075` | `adb shell am start -a android.intent.action.VIEW -d "<scheme>://<payload>"` |
| "reach the WebView bridge" | `MASTG-TEST-0334`, `MASTG-TECH-0139` | Frida-hook `addJavascriptInterface` (Android) / Safari Web Inspector attach (iOS) |
| "bypass root/jailbreak" | `MASTG-TECH-0144` (Android) | `objection ... android root disable`; if app still exits → second detection method present |
| "see Flutter traffic" | `MASTG-TECH-0109/-0110/-0119` | reFlutter or `SSL_read`/`SSL_write` hook — standard proxy won't work |
| "decrypt the iOS App Store app" | `MASTG-TOOL-0050` | `frida-ios-dump` on the jailbroken device → decrypted IPA |

---

## 8. Dynamic false positives / honest negatives
The dynamic equivalent of the static "Classic false positives" tables. Distinguish the failure modes operators confuse.

| Observation | Likely FALSE conclusion | Confirm the real cause by… |
|---|---|---|
| HTTPS won't decrypt | "the app pins" | First confirm the CA is in the **system** store (Android 7+ ignores user CAs by default); only after a *trusted* CA fails is it pinning |
| A pinning-bypass script changed nothing | "pinning is absent" | Distinguish "bypass didn't apply (wrong hook / obfuscated impl)" from "no pinning to bypass" — verify the proxy now actually decrypts |
| App crashes/exits on launch under Frida | "anti-Frida RASP confirmed" | Could be a frida-server version mismatch or an emulator artifact; reproduce on a clean attach **and** a real device |
| Sensitive value seen in one memory dump | "data not zeroized = finding" | A single read may be the value mid-use; needs it persisting **after** the flow, reproducibly |
| No cleartext / no traffic seen | "all traffic encrypted" | Flutter/cross-platform bypasses the proxy entirely — confirm the proxy sees this app's sockets (`MASTG-TECH-0109/-0119`) before concluding |
| Root/jailbreak detection didn't fire | "no detection implemented" | Could be detection present but not triggered by *this* root method; test a second method before calling it absent |
| Emulator-only behavior | real app behavior | Emulator/root artifacts (telephony defaults, missing sensors, `test-keys`) change code paths — note device state |

**Standing rule:** un-run steps stay `Needs dynamic verification`; a single observation is not a reproducible one;
a *bypass that changed something* proves a control exists — a *bypass that changed nothing* proves nothing on its own.

---

## 9. Verified runtime test-ID table (confirmed live this pass)

| Area | Android runtime test | iOS runtime test |
|---|---|---|
| STORAGE | 0011, 0203, 0207, 0287 | 0060, 0296, 0298, 0301, 0314 |
| CRYPTO | 0204, 0205, 0308, 0310, 0350 | 0311, 0349 |
| NETWORK | 0218, 0236, 0238, 0244 | 0323, 0348 |
| PLATFORM | 0028, 0029, 0251, 0253, 0289, 0315, 0334, 0356 | 0070, 0075, 0277, 0290, 0336, 0361, 0363 |
| AUTH | — | 0267, 0269, 0271 |
| CODE (enforced-updating: no confirmed runtime atomic) | 0036 (legacy static; atomic successor to confirm) | 0080 (legacy static; atomic successor to confirm) |
| RESILIENCE | 0325, 0341, 0351, 0353 | 0241, 0246, 0354, 0367 |

Memory: Android `MASTG-TEST-0011`, iOS `MASTG-TEST-0060`. Legacy IPC narrative: `MASTG-TEST-0029`. Deep links:
`MASTG-TEST-0028`. (`-0218` and `-0348` share the title *Insecure TLS Protocols in Network Traffic*.)

---

## 10. Hand-off to the platform references
With the device instrumented and traffic intercepting, go to:
- **`android-dynamic.md`** — confirm Android static flags (cleartext, pinning, exported components, storage, logs)
  **and** run the offensive lane (IPC via drozer, WebView bridge, runtime crypto trace, RESILIENCE effectiveness).
- **`ios-dynamic.md`** — confirm iOS static flags (ATS, pinning, Keychain/Data-Protection, URL schemes, WKWebView,
  biometrics) **and** the iOS-primary lane on FairPlay binaries.

Record exact tool versions, device/OS/root-or-jailbreak state, and which flows were exercised in the report's
methodology and appendices, so an authorized re-test is reproducible. Verify any cited MASTG technique/test IDs
against the live guide (the dynamic tests are heavily mid-refactor; MASWE is Beta).
