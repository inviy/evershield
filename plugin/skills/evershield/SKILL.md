---
name: evershield
description: Use when changing anything that reaches the browser — API response fields, paid/free or role branches in the UI, public env vars (NEXT_PUBLIC_, VITE_, PUBLIC_), bundler config, or files under public/ — or before a release. Checks that the server, not the client, enforces what each user may see, and runs evershield to scan the build.
---

# Client exposure guard

Everything the browser receives is public: bundles, source maps, inlined env
vars, and every field of every JSON response. Blur, `display: none`, a
disabled button or a client-side `if (plan === "pro")` hides data from the
screen, not from DevTools or a script. The boundary is what the server sends.

## Checklist for the change in front of you

1. **Response fields.** For each field added or changed, which identities
   receive it (anonymous, free, paid, admin)? If a lower tier must not have
   it, the server must omit it or send `null` for that tier. A UI lock card
   on top is fine; it is not the protection.
2. **Client plan/role branches.** A branch that hides data the response
   already contains is a leak. Move the decision into the server response.
3. **Public env vars.** Anything prefixed `NEXT_PUBLIC_`, `VITE_`,
   `PUBLIC_`, `REACT_APP_`, `NUXT_PUBLIC_` is inlined into the bundle. Only
   publishable keys belong there, never secrets or internal URLs.
4. **Build config and `public/`.** Source maps in production
   (`productionBrowserSourceMaps`, `build.sourcemap`) publish your source.
   Files in `public/` are served as is.
5. **Over-fetching.** Select the fields the client needs; never serialize a
   whole user/record (password hashes, tokens, internal ids).

## Verify

Build the app, then scan the output (adjust the directory to the framework:
`.next`, `dist`, `build`, `.output/public`):

```bash
npx evershield scan <build-dir>
```

If the project has an `audit` block in `evershield.config.json`, also run
`npx evershield audit` against a non-production base URL. It calls each
endpoint as each identity and reports fields a lower tier should not get.

Exit codes: 0 clean, 1 blocking findings, 2 usage/runtime error. Fix
findings at the source. Only a confirmed-safe match goes into `ignore` in
`evershield.config.json`, and every entry needs a `reason`.

No CI yet? `npx evershield init` writes the config and a GitHub workflow.
