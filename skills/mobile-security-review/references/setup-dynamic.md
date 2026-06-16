# Dynamic Environment Setup (shared, Android + iOS)

Shared groundwork for any dynamic pass. The platform files (`android-dynamic.md`, `ios-dynamic.md`) cover what
to *confirm*; this file covers getting a usable, instrumented, intercepting environment first.

> **Authorization & human-in-the-loop (non-negotiable).** Set up a dynamic environment only for an artifact you
> are **authorized** to test, within the recorded Rule-Zero scope. Dynamic testing is **operator-driven**: the
> tooling observes while a human exercises the app's real flows (login, payment, etc.). Everything here —
> rooting/jailbreaking, CA installation, instrumentation, pinning bypass — is for **authorized testing on a
> dedicated test device**, never a production/personal device or an app you don't own or have permission for.
> And: **never fabricate dynamic output.** If a step wasn't actually run, the corresponding findings stay
> `Needs dynamic verification`.

## 1. Test device
- **Android**: a **rooted** physical device or an emulator (AVD). No root? Repackage the app with the **Frida
  Gadget** (`MASTG-TECH-0026`) to instrument without root.
- **iOS**: a **jailbroken** device (preferred — `frida-server` injects even into encrypted apps). No jailbreak?
  Repackage with the **Frida Gadget** + launch in debug mode (`MASTG-TECH-0055`/`-0090`/`-0091`) — only for a
  **non-FairPlay** binary. The **iOS Simulator is not an emulator**; **Corellium** is the only public virtual iOS.
- Use a **dedicated, disposable** test device/profile with no personal data.

## 2. Instrumentation (Frida / objection)
- Install matching **Frida** on host and **frida-server** on the device (Android: push + run as root; iOS:
  install on the jailbroken device, reachable over SSH — `iproxy 2222 22` for SSH-over-USB).
- Verify with `frida-ps -U` (USB) — you should see the device's processes.
- **objection** (Frida-backed) gives one-command operations used across both platforms: SSL-pinning bypass,
  root/jailbreak-detection bypass, Keychain/keystore/storage inspection, memory dump.

## 3. Interception proxy + CA (the part people get wrong)
- Run **Burp**, **OWASP ZAP**, or **mitmproxy** on the host; point the device's Wi-Fi proxy (or an SSH tunnel)
  at it. Techniques: `MASTG-TECH-0011` (Android) / `MASTG-TECH-0063` (iOS) / `-0120` (generic).
- **Install and trust the proxy CA on the device** — without it, HTTPS won't decrypt and you'll
  *misdiagnose it as pinning.*
  - **Android (the API-24 gotcha):** since Android 7, apps ignore **user**-store CAs unless
    `network_security_config` opts in. So either install the CA into the **system** store (root) or repackage
    the app with an NSC trusting the `user` anchor. Only after the CA is trusted does a failed interception
    indicate **app-level pinning**.
  - **iOS:** install the CA profile and **enable full trust** (Settings → General → About → Certificate Trust
    Settings) — both steps are required.
- Sanity check: browse a normal HTTPS site through the proxy and confirm clean decryption **before** blaming
  the target app.

## 4. Pinning bypass (only after the CA is trusted)
If traffic still won't intercept with a trusted CA, the app is pinning. For authorized testing:
- **objection**: `android sslpinning disable` / `ios sslpinning disable`.
- **Frida CodeShare**: `frida --codeshare <ssl-bypass-script>` for non-standard implementations.
- **iOS jailbroken**: SSL Kill Switch 2 (system-wide).
- **Android**: hook the pinning APIs (Frida), or patch/repackage the `network_security_config`/check and re-sign.
Confirming a bypass *is needed* is itself the evidence that pinning is present and effective.

## 5. Hand-off to the platform references
With the device instrumented and traffic intercepting, go to:
- **`android-dynamic.md`** — confirm Android static flags (cleartext, pinning, exported components, storage, logs).
- **`ios-dynamic.md`** — confirm iOS static flags (ATS, pinning, Keychain/Data-Protection, URL schemes, WKWebView, biometrics).

Record the exact tool versions, device/OS state, and which flows were exercised in the report's methodology and
appendices, so an authorized re-test is reproducible. Verify any cited MASTG technique/test IDs against the live
guide (the dynamic tests are heavily mid-refactor).
