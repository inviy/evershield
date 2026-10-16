<p align="center">
  <img src="docs/assets/banner.svg" alt="evershield: shield everything, everywhere" width="100%" />
</p>

# evershield

**Shield everything, everywhere.** Find what your web app exposes to the
browser before attackers do.

> Status: pre-release. Layer 1 (built-artifact scan) works today with four
> rules and Next.js / plain adapters. Layers 2 and 3 are next; follow the
> [roadmap](docs/design.md#roadmap) or open an issue to help shape them.

## Why

Everything a browser receives is public: bundles, source maps, API responses,
the rendered DOM. Reverse-engineering tools now read all of it automatically,
and they look like ordinary visitors, so you cannot block them. The only
defence that works is to control what you ship.

Teams leak in three recurring ways, and evershield checks all three before
deploy:

| Layer | What leaks | Example |
|---|---|---|
| **Artifact** | keys, internal URLs, prompts, source maps in the build | an LLM system prompt shipped as a string constant |
| **Response** | higher-tier data in lower-tier API responses | "Pro only" metrics present in every free user's JSON |
| **Surface** | data hidden by CSS instead of withheld by the server | a blurred paywall with the real numbers in the DOM |

Secret scanners look at your repository. evershield looks at what your users
actually get.

## Quick start

```bash
# scan a built artifact directory
npx evershield scan ./dist            # Vite, CRA, Astro, static sites, …
npx evershield scan ./.next           # Next.js: only browser-facing files are scanned

# machine-readable output and a stricter gate for CI
npx evershield scan ./dist --format json --fail-on medium --min-confidence low

# SARIF for code scanning, written to a file
npx evershield scan ./dist --format sarif --output evershield.sarif
```

Exit code `0` means nothing blocking, `1` means findings at or above the
gate (default: severity ≥ high **and** confidence ≥ medium), `2` means a
usage or runtime error. Matched values are never printed in full.

What layer 1 catches today, with the reasoning behind each severity and
confidence, is in [docs/rules.md](docs/rules.md):

- `artifact/secret-like-string`: provider keys, private key blocks, Supabase
  `service_role` JWTs, and name-based high-entropy values
- `artifact/source-map-published`: shipped `.map` files and inline maps
- `artifact/sensitive-env-name`: `SERVICE_ROLE`, `*_SECRET`, `DATABASE_URL`, …
- `artifact/internal-endpoint`: private IPs, `.internal` hosts, dev fallbacks

## In CI

The GitHub Action scans your build and uploads the result to the Security
tab as code-scanning alerts:

```yaml
# .github/workflows/evershield.yml
name: evershield
on: [pull_request, push]
permissions:
  contents: read
  security-events: write   # for the SARIF upload
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm run build      # produce dist/ or .next/
      - uses: inviy/evershield@v0
        with:
          path: ./dist
```

Inputs: `path` (required), `fail-on`, `min-confidence`, `config`, `adapter`,
`sarif-file`, `upload-sarif`, `version`. The step fails when evershield
exits 1 (blocking findings) or 2 (error), after the SARIF upload.

## Allowlisting with a reason

Known-safe matches go in `evershield.config.json`, each with a reason:

```json
{
  "ignore": [
    {
      "ruleId": "artifact/internal-endpoint",
      "match": "localhost:9999",
      "reason": "supabase-js bundles this fallback URL; unreachable in production"
    }
  ]
}
```

evershield refuses a config whose ignores have no `reason`, and reports how
many findings the config removed. Details in
[docs/configuration.md](docs/configuration.md).

## Principles

- **Defensive only.** It audits targets you own, listed in your config.
- **Local only.** Nothing leaves your machine. No telemetry.
- **Evidence first.** Every finding has a location and a confidence. Noise is
  a bug.
- **Framework agnostic.** Files and HTTP responses, whatever produced them.
- **CI first.** Stable exit codes, JSON and SARIF output.

Read the full [design document](docs/design.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports: see
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
