# iOS — Dynamic Analysis (confirming the static flags)

**Purpose.** As on Android, dynamic analysis here **confirms** what the static pass (`masvs-ios-static.md`)
flagged and **fuses** it with static to raise confidence — it is not a fresh hunt. On iOS it has a second job:
a static review of a **FairPlay-encrypted** App Store binary is fundamentally limited, so dynamic
(instrumented) analysis is often the only way to read real behavior.

> **Human-in-the-loop & authorization.** Requires a **prepared device** and an **operator exercising the app's
> flows**; re-confirm Rule-Zero authorization/scope first; bypass techniques are for **authorized testing
> only**. **Never fabricate dynamic results** — un-run items stay `Needs dynamic verification`.

## Preconditions
- **Device**: a **jailbroken** iOS device (privileged access, no code-signing restrictions, `frida-server`
  handles injection even into encrypted apps — `MASTG-TECH-0067`). **Non-jailbroken** path: repackage the app
  with the **Frida Gadget** (`MASTG-TECH-0090` auto via Sideloadly/objection, `-0091` manual `.dylib`) and
  launch in debug mode with `get-task-allow` (`MASTG-TECH-0055`) — only works if the binary is **not**
  FairPlay-encrypted. (The **iOS Simulator is not an emulator** — x86 debug builds only; **Corellium** is the
  only public iOS "emulator", `MASTG-TECH-0088`.)
- **Shell / frida-server over SSH**: device shell via SSH (`MASTG-TECH-0052`); SSH-over-USB with **iproxy**
  (`iproxy 2222 22` then `ssh ... -p 2222`). Install/manage with **ios-deploy** / **libimobiledevice**
  (`ideviceinstaller`, `idevice_id`).
- **Interception**: Burp / **mitmproxy** with its **CA installed and trusted** on iOS (`MASTG-TECH-0063`); set a
  global proxy under Settings → Wi-Fi, or tunnel over the SSH-USB connection.
- iOS has **no procfs** and lacks `lsof`/`vmmap` by default (install via Cydia on a jailbroken device).

## Tooling
| Tool | Use |
|---|---|
| **frida / frida-server (iOS)** | Hook ObjC/Swift/native; bypass pinning, jailbreak & biometric checks; trace. |
| **objection (iOS)** | `ios sslpinning disable`, `ios ui biometrics_bypass`, `ios keychain dump`, `memory dump all`. |
| **r2frida** | Runtime RE: memory maps (`:dm`), in-memory search/dump. |
| **Burp / mitmproxy** | MITM HTTP(S); confirm cleartext / whether pinning blocks interception. |
| **SSL Kill Switch 2** | Jailbroken-only system-wide pinning bypass (`MASTG-TECH-0064`). |
| **Frida CodeShare** | `frida --codeshare` community SSL-pinning-bypass scripts for non-standard pinning. |
| **lldb** | Debugger; `debugserver` must be re-signed with `task_for_pid-allow` (`MASTG-TECH-0084`). |
| **Safari Web Inspector / GlobalWebInspect** | Inspect `WKWebView`; since **iOS 16.4** apps must set `isInspectable=true` (GlobalWebInspect forces it on jailbroken devices). |

> **Cycript is deprecated** (broke on iOS 12; superseded by Frida) — don't rely on it; use Frida/Frida-cycript.

## What to confirm (static flag → runtime check)

| Static flag (from `masvs-ios-static.md`) | Dynamic confirmation | Test/technique |
|---|---|---|
| **ATS / cleartext** exception | MITM proxy: observe a real cleartext request | NETWORK runtime / `MASTG-TEST-0322` (static) |
| **Pinning** present/absent | Trusted-CA proxy; if interceptable → no effective pinning; else attempt authorized bypass (`objection ios sslpinning disable`, SSL Kill Switch 2, Frida CodeShare) to confirm it's pinning | `MASTG-TECH-0064` |
| **Keychain / Data-Protection** at rest | Exercise the flow, then `objection ios keychain dump` / read the data dir; confirm accessibility class & what persists | `MASTG-TEST-0301` (runtime) |
| **Custom URL scheme / Universal Link** handler | Invoke the scheme/link with crafted params; observe the sensitive action | `MASTG-TEST-0070`; `-0370`/`-0371` |
| **WKWebView** bridge / file access | Attach via Safari Web Inspector; confirm JS↔native bridge callable / file reads | `MASTG-TECH-0139` |
| **Biometric** gate | `objection ios ui biometrics_bypass`: if it flips a boolean-only `LAContext` check → not bound to the Keychain (bypassable) | `MASTG-TECH-0135` |
| **Sensitive data in memory** | `objection memory dump` + search after exercising the flow | `MASTG-TEST-0060` |
| **Jailbreak/anti-debug detection** (R) | Observe on a jailbroken device; whether checks fire / are bypassable | RESILIENCE tests |

## Fusing with static (confidence)
Same rule as Android: static-confirmed path + dynamic observation → one `Confirmed` finding; un-run → keep
`Needs dynamic verification`; dynamic disproof → downgrade/drop and note it. For an App Store IPA, state
explicitly when a conclusion required decrypting/instrumenting (otherwise the static read was on ciphertext).

> Shared environment setup (proxy CA, frida-server, objection, device prep) is in `setup-dynamic.md`. Verify
> MASTG IDs live — iOS dynamic tests are heavily mid-refactor (many legacy IDs deprecated, v2 successors in
> `tests-beta/`).
