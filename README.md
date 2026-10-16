<p align="center">
  <img src="docs/assets/banner.svg" alt="evershield: shield everything, everywhere" width="100%" />
</p>

# evershield

**Shield everything, everywhere.** Find what your web app exposes to the
browser before attackers do.

> Status: pre-release. The finding model and CLI skeleton are in place; the
> first scanner (built-artifact scan) is in progress. Follow the
> [roadmap](docs/design.md#roadmap) or open an issue to help shape it.

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
# scan a built artifact directory (coming in v0.1)
npx evershield scan ./dist
```

Until v0.1 ships, the command prints its help and the finding model is
available from the package for early integrations.

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
