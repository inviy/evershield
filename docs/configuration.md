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

## surface (layer 3)

`evershield surface` needs this block and [Playwright](https://playwright.dev)
(`npm install --save-dev playwright && npx playwright install chromium`;
`playwright-core` with a Chromium also works, and `EVERSHIELD_CHROMIUM_PATH`
points at a specific browser). It opens each page as each identity, least
privileged first, and runs the [surface rules](rules.md#layer-3-surface).

```json
{
  "surface": {
    "baseUrl": "https://staging.example.com",
    "tiers": ["anonymous", "free", "pro"],
    "identities": {
      "anonymous": {},
      "free": { "storageState": "${EVERSHIELD_FREE_STATE}" },
      "pro":  { "cookies": { "session": "${EVERSHIELD_PRO_SESSION}" } }
    },
    "pages": [
      {
        "path": "/report/demo",
        "waitFor": "[data-report-ready]",
        "expect": { "free": { "absentText": ["Burstiness"], "absentSelectors": ["[data-pro-metric]"] } }
      }
    ],
    "timeoutMs": 30000,
    "minTextLength": 12
  }
}
```

| Field | Required | Meaning |
|---|---|---|
| `baseUrl` | yes | The origin pages are resolved against and the only origin that receives identity headers and cookies |
| `tiers` | yes | Identity names from least to most privileged |
| `identities.<name>.headers` | no | Added to requests for `baseUrl`'s origin only. Credential headers must use `${ENV_VAR}` |
| `identities.<name>.cookies` | no | Name → value, set for `baseUrl`. Values must use `${ENV_VAR}` |
| `identities.<name>.storageState` | no | Path (may use `${ENV_VAR}`) to a Playwright storage-state file with cookies and `localStorage`, e.g. from `npx playwright codegen --save-storage=free.json`. Use this for apps that keep the session in `localStorage` (Supabase, Firebase). Keep the file out of git |
| `pages[].path` | yes | Starts with `/` |
| `pages[].waitFor` | no | CSS selector to wait for before capturing |
| `pages[].expect.<identity>.absentText` | no | Strings that must not appear anywhere for that identity |
| `pages[].expect.<identity>.absentSelectors` | no | CSS selectors that must match nothing for that identity |
| `timeoutMs` | no | Per-page navigation timeout (default 30000) |
| `minTextLength` | no | Shortest text the differential rule compares (default 12, minimum 4) |

Each page load gets a fresh browser context with service workers blocked, so
identities never share state. Pages load one at a time and wait for network
idle. A page that errors, returns 4xx/5xx or redirects to another origin
(a login provider, say) is a warning, not evaluated; if nothing could be
evaluated the command exits 2. Ignore rules apply: with DOM evidence the
`path` glob matches the page path.

Run it against staging or a preview deployment with seeded accounts, not
against production users' data.

## Output

`--format text|json|sarif` chooses the report. `--output <file>` writes it to
a file and prints a one-line summary instead; this is what the GitHub
Action uses to produce `evershield.sarif` for code scanning.

SARIF paths are relative to the scanned directory, not the repository,
because build output is usually not committed.
