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

## audit (layer 2)

`evershield audit` needs this block. It calls each endpoint as each
identity, least privileged first, and runs the
[response rules](rules.md#layer-2-response) over what came back.

```json
{
  "audit": {
    "baseUrl": "https://api.example.com",
    "tiers": ["anonymous", "free", "pro"],
    "identities": {
      "anonymous": {},
      "free": { "headers": { "Authorization": "Bearer ${EVERSHIELD_FREE_TOKEN}" } },
      "pro":  { "headers": { "Authorization": "Bearer ${EVERSHIELD_PRO_TOKEN}" } }
    },
    "endpoints": [
      {
        "method": "POST",
        "path": "/api/analyze",
        "headers": { "Idempotency-Key": "evershield-audit" },
        "body": { "text": "sample" },
        "tiered": true,
        "expect": {
          "anonymous": { "absent": ["perplexity", "burstiness"] },
          "free": { "absent": ["perplexity", "burstiness"] }
        }
      },
      { "path": "/api/profile" }
    ],
    "timeoutMs": 15000
  }
}
```

| Field | Required | Meaning |
|---|---|---|
| `baseUrl` | yes | The only origin the audit will contact. Endpoint paths are resolved against it |
| `tiers` | yes | Identity names from least to most privileged. Rules compare lower tiers against higher ones |
| `identities` | yes | Name → `{ headers }`. Header values may use `${ENV_VAR}`; `Authorization`, `Cookie` and API-key headers **must**, a literal credential is rejected |
| `endpoints[].method` | no | `GET` (default), `POST`, `PUT`, `PATCH`, `DELETE` |
| `endpoints[].path` | yes | Starts with `/` |
| `endpoints[].headers`, `.body` | no | Sent with every identity. String values may use `${ENV_VAR}` |
| `endpoints[].tiered` | no | The endpoint is supposed to differ by tier; identical bodies then fail the build |
| `endpoints[].expect.<identity>.absent` | no | JSON paths (dot notation, `[]` for arrays) that must be absent or `null` for that identity. Nested paths are covered by their prefix |
| `timeoutMs` | no | Per-request timeout (default 15000) |

Requests run sequentially. Credentials are interpolated at request time and
never stored on the result, so no output format can contain them. A missing
variable is a config error naming the variable.

Non-2xx and non-JSON responses are not evaluated and are listed as warnings
at the top of the report. If **no** response could be evaluated the command
exits 2 instead of reporting "no findings": an audit that looked at nothing
must not pass.

Behind an HTTP proxy, set `NODE_USE_ENV_PROXY=1`: Node's `fetch` ignores
`HTTPS_PROXY` by default, and the warning for a failed request says so. Ignore rules apply to response findings too: with
response evidence the `path` glob matches `METHOD /path`.

## Output

`--format text|json|sarif` chooses the report. `--output <file>` writes it to
a file and prints a one-line summary instead; this is what the GitHub
Action uses to produce `evershield.sarif` for code scanning.

SARIF paths are relative to the scanned directory, not the repository,
because build output is usually not committed.
