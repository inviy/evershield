# CLI and Action reference

## Commands

| Command | What it does |
|---|---|
| `evershield demo [--fixed] [--no-browser] [--format <text\|json>]` | Runs all three layers on a built-in app whose paywall is only CSS. No config needed. `--fixed` runs the same app after the fixes |
| `evershield init [--force]` | Detects the framework and writes `evershield.config.json` and a GitHub workflow |
| `evershield scan <dir\|app> [options]` | Layer 1: scans a built web directory or an app package (`.apk`, `.aab`, `.ipa`, Electron `.asar`, npm `.tgz`) |
| `evershield recon <dir\|app> [--rea] [--rea-bin <path>]` | What reverse-engineering tools recover from a build. `--rea` checks each finding against REA's own output |
| `evershield audit [options]` | Layer 2: calls configured endpoints as each identity and compares responses (needs config `audit`) |
| `evershield surface [options]` | Layer 3: opens configured pages as each identity and finds content that is present but hidden (needs config `surface` and Playwright) |
| `evershield mcp` | MCP server over stdio. Tools: `evershield_scan`, `evershield_recon`, `evershield_audit`, `evershield_surface`, `evershield_explain_rule` |
| `evershield --version` | Prints the version |
| `evershield --help` | Shows help |

## Options for scan, audit and surface

| Option | Default | Meaning |
|---|---|---|
| `--format <text\|json\|sarif>` | `text` | Output format |
| `--output <file>` | stdout | Write the report to a file; stdout gets a one-line summary |
| `--config <file>` | `./evershield.config.json` if present | Config file |
| `--fail-on <severity\|none>` | `high` | Fail on findings at this severity or worse (`critical`, `high`, `medium`, `low`, `info`, `none`) |
| `--min-confidence <level>` | `medium` | Findings below this confidence never fail the build (`high`, `medium`, `low`) |
| `--adapter <nextjs\|plain>` | detect | `scan` only: force an adapter |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Nothing blocking |
| `1` | Findings at or above the gate (default: severity ≥ high **and** confidence ≥ medium) |
| `2` | Usage or runtime error |

## Finding format

```
✖ [critical/high] Stripe secret key shipped in assets/main.js
   severity/confidence, then what and where
```

`✖` marks a finding that fails the gate, `•` one that does not. Matched
values are never printed in full.

## GitHub Action

`uses: inviy/evershield@v0`

| Input | Required | Meaning |
|---|---|---|
| `command` | no | `scan` (default, layer 1) or `audit` (layer 2, needs an `audit` section in the config) |
| `path` | for `scan` | Built artifact directory to scan (for example `dist` or `.next`). Ignored for `audit` |
| `version` | no | evershield npm version to run |
| `fail-on` | no | Same as `--fail-on` |
| `min-confidence` | no | Same as `--min-confidence` |
| `config` | no | Path to `evershield.config.json`. Empty means `./evershield.config.json` if present |
| `adapter` | no | Same as `--adapter`, `scan` only. Empty means detect |
| `sarif-file` | no | Where to write the SARIF report |
| `upload-sarif` | no | Upload the SARIF report to GitHub code scanning (needs `security-events: write`). Category `evershield` for `scan`, `evershield-audit` for `audit` |

| Output | Meaning |
|---|---|
| `exit-code` | evershield exit code (0, 1 or 2) |
| `sarif-file` | Path of the SARIF report, when one was written |

## Related reference

- [Rules](../rules.md): every rule, with the reasoning behind its severity and confidence
- [Configuration](../configuration.md): every config key
