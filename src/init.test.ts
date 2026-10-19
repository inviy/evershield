import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { detectProject, renderWorkflow, runInit } from "./init.ts";
import { withTempDir } from "./test-support.ts";

const pkg = (deps: Record<string, string>, build = true) =>
  JSON.stringify({ dependencies: deps, scripts: build ? { build: "x" } : {} });

test("detects common frameworks, build dirs and package managers", async () => {
  const cases: Array<[Record<string, string>, string, string, string]> = [
    [{ "package.json": pkg({ next: "16" }), "pnpm-lock.yaml": "" }, "nextjs", ".next", "pnpm"],
    [{ "package.json": pkg({ vite: "6" }), "yarn.lock": "" }, "vite", "dist", "yarn"],
    [{ "package.json": pkg({ "react-scripts": "5" }) }, "create-react-app", "build", "npm"],
    [{ "package.json": pkg({ astro: "5" }), "bun.lock": "" }, "astro", "dist", "bun"],
    [{ "package.json": pkg({ "@sveltejs/kit": "2" }) }, "sveltekit", "build", "npm"],
    [{ "package.json": pkg({ nuxt: "3" }) }, "nuxt", ".output/public", "npm"],
    [{}, "unknown", "dist", "npm"],
  ];
  for (const [files, framework, buildDir, pm] of cases) {
    await withTempDir(files, async (root) => {
      const detection = await detectProject(root);
      assert.equal(detection.framework, framework);
      assert.equal(detection.buildDir, buildDir);
      assert.equal(detection.packageManager, pm);
    });
  }
});

test("the workflow uses the detected build and grants only what the SARIF upload needs", () => {
  const workflow = renderWorkflow({ framework: "nextjs", buildDir: ".next", packageManager: "pnpm", buildCommand: "pnpm build" });
  assert.match(workflow, /pnpm install --frozen-lockfile/);
  assert.match(workflow, /run: pnpm build/);
  assert.match(workflow, /uses: inviy\/evershield@v0\n\s+with:\n\s+path: \.next/);
  assert.match(workflow, /security-events: write/);
  assert.doesNotMatch(workflow, /contents: write/);
});

test("a project without a build script gets a step that fails loudly instead of scanning nothing", async () => {
  await withTempDir({ "package.json": pkg({ vite: "6" }, false) }, async (root) => {
    const detection = await detectProject(root);
    assert.match(detection.buildCommand, /exit 1/);
  });
});

test("init writes both files and never overwrites without --force", async () => {
  await withTempDir({ "package.json": pkg({ vite: "6" }) }, async (root) => {
    const first = await runInit(root);
    assert.deepEqual(first.written, ["evershield.config.json", ".github/workflows/evershield.yml"]);
    const config = JSON.parse(await readFile(`${root}/evershield.config.json`, "utf8")) as { ignore: unknown[] };
    assert.deepEqual(config.ignore, []);

    const second = await runInit(root);
    assert.deepEqual(second.written, []);
    assert.equal(second.skipped.length, 2);

    const forced = await runInit(root, { force: true });
    assert.equal(forced.written.length, 2);
  });
});

test("pnpm/action-setup gets a version unless package.json pins one in packageManager", () => {
  const base = { framework: "vite", buildDir: "dist", packageManager: "pnpm", buildCommand: "pnpm build" } as const;
  assert.match(renderWorkflow(base), /pnpm\/action-setup@v4\n\s+with:\n\s+version: 10/);
  assert.doesNotMatch(renderWorkflow({ ...base, packageManagerPinned: true }), /version: 10/);
});
