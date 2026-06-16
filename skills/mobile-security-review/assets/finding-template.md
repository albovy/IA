---
# --- Identity -------------------------------------------------------------
id: MSR-001                      # sequential, stable within this report (MSR-001, MSR-002, ...)
title: Cleartext HTTP traffic permitted to api.example.com
# --- Risk -----------------------------------------------------------------
severity: High                   # Critical | High | Medium | Low | Info  (impact x exploitability IN THIS app, modulated by profile)
confidence: Confirmed            # Confirmed | Likely | Needs dynamic verification
# --- Traceability (MANDATORY: MASVS control -> MASWE weakness -> MASTG test) -
platform: Android                # Android | iOS
masvs: MASVS-NETWORK-1           # the stable control anchor (ALWAYS fill this)
maswe: MASWE-0050                # weakness ID (here: Cleartext Traffic) — verify against the live guide; "MASWE: unmapped" if none fits
mastg:                           # one or more test/technique IDs — verify against the live guide
  - MASTG-TEST-0235              # App Configurations Allowing Cleartext Traffic (static)
cwe: CWE-319                     # optional, when a clean CWE mapping exists (e.g. CWE-319 Cleartext Transmission)
# --- Localization ---------------------------------------------------------
affected_component: res/xml/network_security_config.xml; manifest android:usesCleartextTraffic="true"
---

## Description
<!-- What the weakness is, in plain language. State the MASVS control it violates and why. -->

## Evidence
<!--
Concrete, reproducible proof — file paths, line numbers, decompiled snippets, tool output, screenshots/log
excerpts. This is what separates a FINDING from a candidate. A bare grep/MobSF hit is NOT evidence on its own;
show the reachable code/config. For dynamic findings, include the captured traffic / on-disk artifact / hook output.
-->
```
<paste the smallest excerpt that proves the point>
```

## Impact
<!-- What an attacker gains IN THIS app, and under what preconditions (device state, user interaction, adjacency).
     This is what drives severity — not the abstract badness of the pattern. -->

## Remediation
<!-- Specific, actionable fix. Prefer the platform-recommended control (e.g. set cleartextTrafficPermitted=false,
     use EncryptedSharedPreferences, AES-GCM via Keystore). Link to the secure pattern. -->

## References
<!-- MASVS control page, MASWE page, MASTG test page(s), CWE, vendor docs. Use the canonical mas.owasp.org URLs. -->
- MASVS: https://mas.owasp.org/MASVS/
- MASTG: https://mas.owasp.org/MASTG/

<!--
ANTI-FALSE-POSITIVE GATE — this finding earns its place only if all three hold:
  (a) Real evidence above, not just a pattern match?
  (b) Reachable / exploitable in THIS build (right profile, right preconditions)?
  (c) Confidence honestly reflects what was actually proven? (static-only suspicion => "Needs dynamic verification")
-->
