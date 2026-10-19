# Changelog

All notable changes to evershield are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/). Until 1.0, minor versions may
change rule defaults and output shapes; each such change is listed.

## [Unreleased]

### Added

- False-positive regression corpus (`pnpm corpus`, `docs/corpus.md`): 42
  pinned browser packages and 9 default framework builds, checked in CI on
  rule changes and weekly. Every accepted finding carries a reason.

### Fixed

- `artifact/secret-like-string`: a private key block needs a base64 body;
  PEM-parsing code that only names the header (auth0-spa-js) is no longer
  a critical finding. Dotted identifiers such as `auth0.lock.getTokenSilently`
  are no longer high-entropy credentials.
- `artifact/sensitive-env-name`: URN, URL and prose values (an OAuth
  grant-type URN in auth0-spa-js) no longer count as secret-shaped.
- `artifact/internal-endpoint`: private IPs count at medium only in a URL or
  with a port; bare literals in comments and grammars are low/low, and DOIs
  and out-of-range octets no longer match.
- The release workflow installs Chromium before `pnpm check`; without it the
  layer 3 browser test fails in CI by design, which failed the v0.2.0 run
  (0.2.0 itself was published by hand and is unaffected).

## [0.2.0] - 2026-10-19

Layers 2 and 3: what each identity receives, and what each identity's
browser holds but cannot see.

### Added

- Layer 3: `evershield surface` opens configured pages as each identity in
  headless Chromium (Playwright, optional peer dependency) and records text
  with its visibility, `data-*` attributes, inline scripts and web storage.
  Rules: `surface/hidden-higher-tier-content`, `surface/obscured-content`,
  `surface/expected-absent-present`.
- `surface` block in `evershield.config.json`: identities by header, cookie
  (env references only) or Playwright storage state; per-page `waitFor`,
  `absentText` and `absentSelectors`. Ignore `path` globs match the page
  path for DOM evidence.

- `evershield init` detects the framework, build directory and package
  manager, and writes `evershield.config.json` and a GitHub workflow.
  Never overwrites without `--force`.
- Claude Code plugin (`/plugin marketplace add inviy/evershield`): an
  exposure-guard skill and an `/evershield` command.
- Layer 2: `evershield audit` calls configured endpoints as each identity
  (credentials from environment variables only) and compares responses.
  Rules: `response/expected-absent-field-present`,
  `response/sensitive-field`, `response/higher-tier-field-in-lower-tier`,
  `response/identical-across-tiers`.
- `audit` block in `evershield.config.json`; ignore `path` globs match
  `METHOD /path` for response findings.
- SARIF logical locations for response evidence.

### Fixed

- The release workflow skips `npm publish` when the tagged version is
  already on npm, so re-tagging a published version no longer fails.
- `evershield init` passes `version: 10` to `pnpm/action-setup` when
  package.json has no `packageManager` field; the action fails without one.

## [0.1.0] - 2026-10-16

First release: layer 1, the built-artifact scan.

### Added

- `evershield scan <dir>` scans a directory of built files for what should
  not reach the browser.
- Rules, each with a documented severity/confidence rationale and
  true-positive and false-positive tests:
  - `artifact/secret-like-string`: AWS, GitHub, Stripe, Slack, OpenAI and
    Anthropic key formats, private key blocks, Supabase `service_role` JWTs,
    and name-based high-entropy values.
  - `artifact/source-map-published`: shipped `.map` files and inline maps.
  - `artifact/sensitive-env-name`: server-only variable names, with or
    without an adjacent secret-shaped value.
  - `artifact/internal-endpoint`: private IPs, internal hostnames,
    development fallbacks.
- Adapters: `nextjs` (scans only browser-facing files of a `.next/` build)
  and `plain`.
- Output: text, `--format json`, `--format sarif` (2.1.0); `--output <file>`.
- Gate: `--fail-on` and `--min-confidence`, default severity ≥ high with
  confidence ≥ medium. Exit codes 0 / 1 / 2.
- `evershield.config.json`: gate override and ignore rules that each
  require a reason; ignored findings stay counted.
- GitHub Action (`inviy/evershield@v0`) that scans, uploads SARIF to code
  scanning, then fails on blocking findings.
- Matched values are redacted in every output format.

[Unreleased]: https://github.com/inviy/evershield/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/inviy/evershield/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/inviy/evershield/releases/tag/v0.1.0
