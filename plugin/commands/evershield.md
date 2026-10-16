---
description: Build the app and scan what it ships to the browser with evershield
argument-hint: "[build-dir]"
---

Scan this project with evershield.

1. Find the build output directory. Use `$ARGUMENTS` if given; otherwise
   detect it from the framework (`.next` for Next.js, `dist` for Vite/Astro,
   `build` for SvelteKit/CRA, `.output/public` for Nuxt).
2. If it does not exist or is stale, run the project's build script.
3. Run `npx evershield scan <build-dir>`. If `evershield.config.json` has an
   `audit` block, ask before running `npx evershield audit`, since it sends
   real requests.
4. Report the findings grouped by severity. For each one, point to the
   source that produced it and propose a fix at the source. Do not add
   `ignore` entries unless the user confirms the match is safe, and always
   include a reason.
5. If the project has no `.github/workflows/evershield.yml`, offer
   `npx evershield init`.
