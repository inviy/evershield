# Configuration

evershield reads `./evershield.config.json` when it exists, or the file
named with `--config`. The file is optional; everything has a default.

```json
{
  "gate": { "failOn": "high", "minConfidence": "medium" },
  "ignore": [
    {
      "ruleId": "artifact/internal-endpoint",
      "match": "localhost:9999",
      "reason": "supabase-js bundles this fallback URL; it is unreachable in production"
    },
    {
      "ruleId": "*",
      "path": "static/vendor/**",
      "reason": "vendored library whose source maps are public upstream"
    }
  ]
}
```

## gate

Which findings fail the build. `failOn` is the least severe level that
fails (`critical`, `high`, `medium`, `low`, `info`) or `none`;
`minConfidence` is the least sure level that fails (`high`, `medium`,
`low`). A finding must meet both to block.

Precedence: CLI flags (`--fail-on`, `--min-confidence`) override the config
file, which overrides the defaults (`high`, `medium`).

## ignore

Each entry removes matching findings from the report and from the gate.
Ignored findings are counted (`N finding(s) ignored by config`) so a growing
allowlist stays visible.

| Field | Required | Meaning |
|---|---|---|
| `ruleId` | yes | A rule id, or `*` for any rule |
| `path` | no | Glob over the evidence path, relative to the scan target. `**` spans directories; `*` and `?` stay within one segment |
| `match` | no | Substring that must appear in the finding's message or redacted excerpt |
| `reason` | yes | Why this is safe. evershield refuses a config whose ignores have no reason |

An entry matches when every field it specifies matches. Prefer the
narrowest entry that works: a `match` on the exact value beats a bare
`ruleId`.

## Output

`--format text|json|sarif` chooses the report. `--output <file>` writes it to
a file and prints a one-line summary instead; this is what the GitHub
Action uses to produce `evershield.sarif` for code scanning.

SARIF paths are relative to the scanned directory, not the repository,
because build output is usually not committed.
