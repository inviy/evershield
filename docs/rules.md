# Rules

Every rule carries a default **severity** (how bad if real) and **confidence**
(how sure we are), with the reasoning written here and in the rule's source.
Individual matches may override the defaults when the pattern is more or less
certain than the rule as a whole. The CI gate defaults to failing on
`severity ≥ high` with `confidence ≥ medium`.

## Layer 1: artifact

### artifact/secret-like-string

Credentials in shipped files.

| Match | Severity | Confidence | Why |
|---|---|---|---|
| AWS access key ID, GitHub token, Stripe live secret key, Slack token, Anthropic key, OpenAI key, private key block | critical | high | Provider formats are structurally unambiguous and grant server-side access |
| Supabase JWT with `role: service_role` | critical | high | Bypasses row-level security entirely |
| Stripe test secret key | medium | high | Not live, still should not ship |
| Google API key (`AIza…`) | medium | medium | Browser keys are expected; the risk is a missing origin restriction |
| JWT with no `role` claim | low | medium | Often a fixture, sometimes a live token |
| Name-based (`apiKey: "…"`) with entropy ≥ 3.5 bits/char and a credential-shaped value | high | low | Depends on the name and the value's shape, not a known format |

Not reported: Stripe publishable keys, Supabase `anon`/`authenticated` JWTs,
values under a framework-public prefix (`NEXT_PUBLIC_`, `VITE_`, …),
placeholder values (`your_…`, `xxxx`, `changeme`), and values shaped like
CSS custom properties or paths (`--brand-color-hover`, `spacing.large.default`).

Reports never print the matched value in full; evidence shows the first and
last four characters.

### artifact/source-map-published

A `.map` file in the shipped set, or an inline `data:` source map.

| Match | Severity | Confidence |
|---|---|---|
| Shipped `.map` file | high | high |
| Inline `sourceMappingURL=data:` | high | high |

A `sourceMappingURL` comment pointing at a file that is not shipped leaks
nothing and is not reported. The Next.js adapter excludes `server/` maps for
the same reason: they never leave the host.

### artifact/sensitive-env-name

Environment variable names that denote server-only material:
`SERVICE_ROLE`, `*_SECRET`, `PRIVATE_KEY`, `PASSWORD`, `DATABASE_URL`,
`CONNECTION_STRING`, `ACCESS_TOKEN`, `REFRESH_TOKEN`, `SIGNING_KEY`,
`MASTER_KEY`.

| Match | Severity | Confidence | Why |
|---|---|---|---|
| Name with an adjacent secret-shaped literal (12+ chars, mixed classes, not `UPPER_CASE`) | high | medium | The value is almost certainly the secret |
| Bare name, strong keywords only (`SERVICE_ROLE`, `SECRET`, `PRIVATE_KEY`, `DATABASE_URL`, `CONNECTION_STRING`, `SIGNING_KEY`, `MASTER_KEY`) | low | low | Usually an error message or a runtime read |

`PASSWORD`, `ACCESS_TOKEN` and `REFRESH_TOKEN` are everyday vocabulary in
client auth code (`PASSWORD_RECOVERY` is a supabase-js event name), so they
are reported only with a secret-shaped value. Names under a framework-public
prefix are never reported.

### artifact/internal-endpoint

Addresses that map your infrastructure.

| Match | Severity | Confidence |
|---|---|---|
| Private IP (`10/8`, `172.16/12`, `192.168/16`) | medium | medium |
| `.internal` / `.local` / `.corp` / `.lan` / `.intranet` host | medium | high |
| `localhost` / `127.0.0.1` URL | low | low |
| `staging.` / `dev.` / `admin.` / `preprod.` / `uat.` host | low | low |

Version strings (`v10.0.0.1`) do not match: the IP pattern requires a word
boundary before the first octet. Library defaults do match: supabase-js
ships `http://localhost:9999` as its fallback auth URL, which is why that
match is low/low and never blocks.

## Layer 2: response

Each rule inspects one endpoint observed as every configured identity.
Only 2xx JSON responses are evaluated.

### response/expected-absent-field-present

The config says identity X must not receive path P, and it did (non-null).
The operator's own contract makes this **high / high**. A path covers
everything nested under it. `null` counts as withheld, so a server that
sends `"perplexity": null` to free users passes.

### response/sensitive-field

A field whose name is credential-like (`password`, `password_hash`,
`secret`, `api_key`, `access_token`, `refresh_token`, `private_key`, `ssn`,
`card_number`, `cvv`, camelCase variants) with a non-boolean value, in any
identity's response. **High / high**: over-fetching the whole record.
Reported once per path. `has_password: true` is not a finding.

### response/higher-tier-field-in-lower-tier

A field present for a tier below the top whose name marks it as privileged:
`premium_*`, `pro_*`, `pro_only`, `paid_*`, `plus_*`, `enterprise_*`,
`admin_*`, `internal_*`, `private_*`, `debug_*`, `cost*`, `margin*`,
`staff_*`, `owner_only`, `*_premium`, `*_internal`, `*_cost`. Name-based,
so **medium / medium**. Boolean flags (`is_premium: false`) are not
findings. Promote a confirmed case to that identity's `expect.absent` and
it becomes high/high.

### response/identical-across-tiers

Every identity that answered 2xx JSON received a structurally identical
body.

| Endpoint | Severity | Confidence | Why |
|---|---|---|---|
| declared `tiered: true` | high | medium | The tier check is not applied |
| not declared | low | low | A prompt to declare it if it should differ |

## Adapters

| Adapter | Detected by | Shipped files |
|---|---|---|
| `nextjs` | `BUILD_ID` and `static/` present | `static/**`, `server/**/*.{html,rsc,body}` |
| `plain` | fallback | every text-like file outside `node_modules` |

Pass `--adapter plain` to scan a Next.js directory in full, for example to
audit what a misconfigured host would serve.
