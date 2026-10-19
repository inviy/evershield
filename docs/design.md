# evershield design

Status: draft v0 (2026-10-16). This document fixes the problem, the principles
and the shape of the tool before the first scanner lands. Expect it to change;
each change should say why.

## The problem

Everything a browser receives is public. HTML, JavaScript bundles, source maps,
API responses, the DOM after render: a user with DevTools can read all of it,
and tools now automate the reading. [REA](https://github.com/morluto/rea), for
one, attaches to a running Chrome over the DevTools Protocol and recovers
module graphs, API routes, hidden fields and storage keys from any site in
minutes. Such tools cannot be detected or blocked: from the server's point of
view they are an ordinary visitor.

So the only defence that works is to control what you ship. In practice teams
fail this in three recurring ways:

1. **Artifacts leak.** API keys, internal hostnames, prompts, business rules
   and debug code end up in the production bundle. Source maps are published.
2. **Responses leak.** An endpoint returns the full object and the client
   decides what to show. Free users receive paid data; regular users receive
   admin fields. The paywall or permission check exists only in the UI.
3. **The rendered surface leaks.** Data is "hidden" with `blur`,
   `display:none`, opacity or a locked overlay, but the real values sit in the
   DOM and in storage.

Secret scanners (gitleaks, trufflehog) look at repositories, not at what is
served. Artifact scanners cover the first failure. Almost nothing covers the
second and third, which is where paying customers, authorization and
business logic are actually lost. evershield covers all three, before deploy.

## Principles

- **Defensive only.** evershield audits targets its operator owns. Live
  checks run only against origins listed in the config; there is no
  discovery mode and no way to point it at an arbitrary third party from the
  command line. The README states this and the licence does not change it,
  but the design should make misuse inconvenient as well as unwelcome.
- **Local only.** Nothing leaves the machine. No telemetry, no upload of
  findings, no remote rule fetching at scan time.
- **Evidence first.** Every finding carries where it was seen (file and line,
  response path, DOM selector) and a confidence. A finding without evidence
  is a bug. False positives cost more than false negatives: a noisy tool is
  switched off within a week.
- **Framework agnostic.** Input is a directory of built files, a set of HTTP
  endpoints, or a URL. Next.js, Vite, Astro, Rails asset pipelines and
  hand-written HTML are all just files and responses.
- **CI first.** The primary user is a pipeline, not a dashboard. Exit codes
  are stable, output has a machine format (JSON) and a reporting format
  (SARIF), and a scan must finish in the time a lint step takes.
- **Small core, explicit rules.** Each rule is a documented unit with its
  own identifier, severity, confidence rationale and remediation text.

## Three layers

### Layer 1: artifact scan (static)

Input: a directory of built files (`dist/`, `.next/`, `build/`, `out/`).

Looks for:

- secret-like strings: provider key formats, JWTs, private keys, high-entropy
  tokens, with provider-specific validators to keep confidence honest
- published source maps, and `sourceMappingURL` comments pointing at them
- internal hostnames, private IP ranges, staging and admin URLs
- environment variables that should never be public, detected by name
  (`SERVICE_ROLE`, `SECRET`, `PRIVATE`) and by value shape
- large natural-language blocks that look like LLM prompts or scoring rules
- debug and development leftovers: `console.log` of tokens, `debugger`,
  source files served verbatim

Framework adapters add context (for example a Next.js adapter knows which
chunks are client-side and that `NEXT_PUBLIC_*` is public by design), but
every rule must also work on a plain directory.

### Layer 2: privilege-differential response audit

Input: a list of endpoints and two or more **identities** (anonymous, free,
paid, admin, ...). Credentials are referenced from environment variables,
never written in the config file.

For each endpoint, evershield calls it as each identity and compares the
response shapes. It reports:

- fields present for a lower identity that are absent for a higher one
  (usually a bug in the other direction, still worth a look)
- fields present for a lower identity whose **name or value** marks them as
  belonging to a higher tier: `premium`, `pro_only`, `admin`, `internal`,
  `cost`, nested objects that are `null` for the lower tier elsewhere
- identical responses across identities on an endpoint the config declares
  as tiered: the gate is missing entirely

The operator declares expectations (`"free" must not receive "report.detail"`)
and evershield turns them into tests that run on every deploy. This is the
layer that would have caught the Passit case that started this project: a
"Pro only" metric blurred in the UI but present in every response.

### Layer 3: rendered-surface audit

Input: URLs plus identities, driven through a headless browser the operator
controls.

Looks for:

- elements hidden by `filter: blur`, `opacity: 0`, `visibility: hidden`,
  `display: none` or clipping that contain non-placeholder data
- locked or paywalled regions whose real values are present in the DOM, in
  `data-*` attributes, or in `localStorage` / `sessionStorage`
- client-side gating: a value rendered first and removed after an
  entitlement check resolves

Layer 3 is the slowest and the most prone to false positives; it ships last
and is opt-in: a separate `evershield surface` command with its own config
block, and Playwright as an optional peer dependency the other layers never
load. False positives are contained by comparing tiers: the main rule only
fires for text the top tier sees and a lower tier holds hidden, so UI hidden
for everyone (tabs, menus, dialogs) never counts. Detecting values rendered
then removed after an entitlement check is left for later.

## Finding model

```ts
interface Finding {
  ruleId: string;        // "artifact/secret-like-string"
  layer: "artifact" | "response" | "surface";
  severity: "critical" | "high" | "medium" | "low" | "info";
  confidence: "high" | "medium" | "low";
  message: string;       // one actionable sentence
  evidence: Evidence[];  // file:line, response path, or DOM selector
  remediation?: string;
  helpUri?: string;
}
```

Severity says how bad it is if real; confidence says how sure we are. CI
gating defaults to "fail on high severity with high or medium confidence",
and the operator can tighten or loosen per rule. Low-confidence findings are
reported but never fail a build by default.

## Interfaces

- **CLI**: `evershield scan <dir|app>` (layer 1), `evershield audit` (layer
  2) and `evershield surface` (layer 3), the last two from config.
  `evershield recon <dir|app>` presents layer 1 from the attacker's side:
  what is worth taking, the map any tool reconstructs anyway, and with
  `--rea` whether REA's own analysis recovers each finding. Output: human-readable by default, `--format json`,
  `--format sarif`. Exit codes: 0 clean, 1 findings above the gate, 2 usage
  or runtime error.
- **Config**: `evershield.config.json` (or `.ts`), with targets, identities
  as env var references, endpoints, tier expectations, and per-rule
  overrides and allowlists with a required `reason` field.
- **GitHub Action**: thin wrapper that runs the CLI and uploads SARIF to
  code scanning.
- **Agent surface**: `evershield mcp`, an MCP server over stdio (no
  dependencies) whose tools wrap the CLI's JSON output, and a Claude Code
  plugin with an agent skill, so coding agents run the scan while they
  write the code, not after.

## Non-goals

- Obfuscation, anti-debugging, DevTools detection: they do not work against
  the threat model and they punish legitimate users.
- Scanning or auditing third-party sites.
- Replacing secret scanners for repositories; run both.
- Runtime protection (WAF, rate limiting). evershield finds the gap; fixing
  it is the application's job.

## Roadmap

- **v0.1**: layer 1 on a plain directory, Next.js and Vite adapters, CLI
  with JSON and SARIF output, GitHub Action. Validated against Passit's
  production build.
- **v0.2**: layer 2 with config-driven identities and tier expectations.
- **v0.3**: layer 3 behind an opt-in flag.
- **v0.4**: MCP server and agent skill; rule documentation site.

## Prior art and how this differs

| Tool | Scope | Difference |
|---|---|---|
| gitleaks, trufflehog | secrets in repositories and history | evershield scans what is served, not what is committed |
| tovellan/surfaceguard | policy scanner for built web artifacts | overlaps with layer 1; evershield adds response and surface audits |
| REA | reverse engineering from the attacker's seat | the problem evershield exists to make boring |
