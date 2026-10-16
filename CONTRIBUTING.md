# Contributing to evershield

Thanks for helping build a shield for everyone. A few ground rules keep the
project trustworthy, which matters more than usual for a security tool.

## Before you start

- Read [docs/design.md](docs/design.md). Proposals that change a principle
  (defensive only, local only, evidence first) need a design discussion in an
  issue before code.
- Search existing issues. If none fits, open one describing the leak you want
  to catch, with a minimal example of the artifact or response.

## Development

```bash
pnpm install
pnpm check        # typecheck, test, build
```

Node 22 or newer. Tests use the built-in `node:test` runner and import
TypeScript directly, so there is no build step before testing.

## Rules

Every detection rule must ship with:

1. a stable `ruleId` (`<layer>/<kebab-name>`),
2. a severity and a confidence **with a written rationale** in the rule's doc
   comment,
3. tests for at least one true positive and one plausible false positive,
4. remediation text a developer can act on without opening the docs.

A rule that cannot point at a file, a response path or a DOM selector is not
a rule.

## Pull requests

- One change per PR. Keep the diff reviewable.
- Describe what leaks, how the change catches it, and how you checked it.
- CI must be green. Do not skip or weaken a test to get there.
- Commits are plain; no badge-farming, no drive-by reformatting.

## Conduct

Be direct and kind. Disagree with the idea, not the person. Maintainers may
close discussions that stop being about the work.
