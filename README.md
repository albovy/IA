# IA — albovy's Claude Code skills

A Claude Code **plugin marketplace**. This repo is both a marketplace and a plugin (`ia-skills`) that bundles
my skills so they install into any Claude Code with two commands — no copying folders by hand.

## Install (in any Claude Code)

```text
/plugin marketplace add albovy/IA
/plugin install ia-skills@ia
```

That's it. The skills become available immediately (and survive across projects, since plugins install at the
user level). To confirm: run `/plugin` and check that `ia-skills` is enabled.

> `albovy/IA` is the GitHub shorthand for this repo; `ia-skills@ia` is `<plugin-name>@<marketplace-name>`.

### Updating later

```text
/plugin marketplace update ia
/plugin install ia-skills@ia      # re-installs the latest version
```

### Manual install (no plugin system)

Copy a skill folder into your skills directory:

```text
# user-level (all projects)
cp -r skills/mobile-security-review ~/.claude/skills/
# or project-level
cp -r skills/mobile-security-review <your-project>/.claude/skills/
```

## What's inside

| Skill | What it does |
|---|---|
| **mobile-security-review** | Structured mobile app security review of an Android or iOS artifact (`.apk` / `.aab` / `.ipa` / Mach-O) following the OWASP Mobile Application Security project: **MASVS** controls → **MASWE** weaknesses → **MASTG** tests. Static and (with a prepared device) dynamic. Produces a traceable, false-positive-gated Markdown report. |

Once installed it triggers on its own when you ask to review/audit/pentest a mobile app or hand over an
app artifact — even without naming OWASP/MASVS. You can also invoke it explicitly: `/ia-skills:mobile-security-review`.

### mobile-security-review — layout

```
skills/mobile-security-review/
├── SKILL.md                          # router + contract (finding schema, MASVS→MASWE→MASTG traceability,
│                                     #   severity model, anti-false-positive gate, static/dynamic boundary)
│                                     #   + the 24 MASVS v2.0.0 controls (authoritative anchors)
├── references/
│   ├── masvs-android-static.md       # Android static checks by MASVS group
│   ├── masvs-ios-static.md           # iOS static checks (incl. FairPlay decryption caveat)
│   ├── android-dynamic.md            # Android runtime confirmation of static flags
│   ├── ios-dynamic.md                # iOS runtime confirmation
│   └── setup-dynamic.md              # shared dynamic environment setup
├── assets/
│   ├── finding-template.md           # per-finding template
│   └── report-template.md            # full report skeleton
└── evals/evals.json                  # qualitative test cases used while building the skill
```

**Tooling note:** static analysis uses standard tooling (apktool/jadx/aapt2/apksigner, or **androguard** for
a pure-Python, JVM-less environment; `class-dump`/otool/etc. for iOS). Dynamic analysis is human-in-the-loop
and requires a prepared, authorized test device. The skill never fabricates dynamic results.

## Adding more skills later

1. Drop a new skill folder under `skills/<new-skill>/` (must contain a `SKILL.md`).
2. Add its path to the `skills` array in [`.claude-plugin/plugin.json`](.claude-plugin/plugin.json).
3. Bump `version` in `plugin.json` and `.claude-plugin/marketplace.json`.
4. Commit and push. Users get it with `/plugin marketplace update ia`.

## License

MIT — see [LICENSE](LICENSE).
