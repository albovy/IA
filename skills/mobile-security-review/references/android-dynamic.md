# Android — Dynamic Analysis (confirming the static flags)

**Purpose.** Dynamic analysis here is not a fresh hunt — its job is to **confirm** what the static pass
(`masvs-android-static.md`) flagged and **fuse** it with static, raising confidence. A static suspicion at
`Needs dynamic verification` becomes `Confirmed` only when an actual run on a device proves it. Static findings
that dynamic *disproves* (e.g. pinning that actually holds) get downgraded or dropped.

> **Human-in-the-loop & authorization.** Dynamic testing requires a **prepared device** and an **operator who
> exercises the app's flows** (login, transfer, etc.) — the tooling observes; a human drives. Re-confirm the
> Rule-Zero authorization/scope before instrumenting, and stay within it. The bypass techniques below are for
> **authorized testing only**. **Never fabricate dynamic results**: if you did not run on a device, do not
> claim runtime behavior — leave the item `Needs dynamic verification`.

## Preconditions
- **Device**: a rooted physical device **or** an emulator (AVD), + `adb`. Non-rooted is possible by
  repackaging the app with the **Frida Gadget** (`MASTG-TECH-0026`).
- **Instrumentation**: `frida-server` pushed and run on the device, matching the host Frida version; `objection`
  (Frida-backed) for one-command hooks.
- **Interception**: an intercepting proxy (Burp / ZAP / **mitmproxy**) with its **CA installed**, device
  Wi-Fi/proxy pointed at the host (`MASTG-TECH-0011` Android / `-0120` generic).
- **The user-CA gotcha (read this):** since **Android 7 (API 24)** apps do **not** trust user-installed CAs
  unless `network_security_config` opts in. So TLS interception fails *before* any app-level pinning unless you
  either (a) install the proxy CA into the **system** store (root), or (b) repackage with an NSC that trusts
  the `user` anchor. Distinguish "couldn't intercept due to the CA-trust default" from "couldn't intercept due
  to pinning."

## Tooling
| Tool | Use |
|---|---|
| **frida / frida-server** | Hook Java/native functions: bypass pinning/root checks, trace methods. |
| **objection** | `android sslpinning disable`, `android root disable`, storage/keystore/memory inspection. |
| **mitmproxy / Burp** | MITM HTTP(S); confirm cleartext and whether pinning blocks interception. |
| **adb** | Install, port-forward, read app data dirs, `logcat`, and invoke exported components (`am start`, `content query`). |
| **drozer** | Enumerate & exercise exported activities/services/receivers and content providers (`app.provider.read`/`download`). |
| **jadx** | Read decompiled code to locate the class/method names to target with hooks. |

Techniques: `MASTG-TECH-0049` (Dynamic Analysis, entry), `-0011`/`-0120` (interception proxy), `-0012`
(bypassing certificate pinning), `-0026` (non-rooted via Frida gadget), `-0031` (debugging: JDWP + ptrace/lldb),
`-0033` (method tracing/hooking), `-0144` (bypassing root detection).

## What to confirm (static flag → runtime check)

| Static flag (from `masvs-android-static.md`) | Dynamic confirmation | Test |
|---|---|---|
| **Cleartext** permitted (manifest/NSC) | MITM proxy: observe a real `http://` request on the wire | `MASTG-TEST-0019` (data encryption on the network) |
| **Pinning** present/absent | Proxy with trusted CA: if HTTPS is interceptable → pinning absent/ineffective; if not, attempt authorized bypass (`objection`/Frida) to confirm it's *pinning*, not the CA-trust default | `MASTG-TEST-0244` (missing pinning in traffic; atomic) — legacy `-0022` |
| **Exported component** reachable | Invoke it from `adb`/`drozer` with crafted extras; observe the sensitive action actually firing | `MASTG-TEST-0029` (IPC exposure) |
| **ContentProvider** exposure / SQLi | `drozer app.provider.query`/`read` with injection payloads; observe data returned | `MASTG-TEST-0029` + provider runtime checks |
| **Storage at rest** (prefs/DB/files) | Exercise the flow, then read the app data dir on the rooted device; confirm what actually persists and in what form | `MASTG-TEST-0001` (local storage) |
| **Logs** | `logcat` while exercising the flow; confirm sensitive data is emitted | `MASTG-TEST-0003` (logs) |
| **WebView** JS-bridge / file access | Drive the WebView; confirm the bridge is callable / `file://` reads succeed | platform WebView tests |
| **Root/anti-debug detection** (R) | Observe behavior on a rooted device and whether checks fire / are bypassable (`MASTG-TECH-0144`) | RESILIENCE tests |

## Fusing with static (confidence)
- Static-confirmed code path **+** dynamic observation → `Confirmed`; record both as **one** finding (don't
  double-count the suspicion and its confirmation).
- Static suspicion, dynamic **not** run → keep `Needs dynamic verification` and say what a run would check.
- Static suspicion, dynamic **disproves** it (e.g. pinning held even after CA install) → downgrade/drop and
  note it in the report (honest negatives are valuable).

> **Beware the deprecated/atomic split.** Network/pinning tests are mid-refactor: legacy `MASTG-TEST-0022` →
> atomic `-0242` (NSC), `-0243` (expired pins), `-0244` (runtime MITM). Prefer the atomic ID and verify live.
> Environment setup shared with iOS lives in `setup-dynamic.md`.
