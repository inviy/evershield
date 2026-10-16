import assert from "node:assert/strict";
import test from "node:test";

import { withTempDir } from "../test-support.ts";
import { detectAdapter, nextjsAdapter, plainAdapter } from "./adapters.ts";
import { collectFiles } from "./files.ts";

test("a Next.js build is detected and only browser-facing files are collected", async () => {
  await withTempDir(
    {
      BUILD_ID: "abc",
      "static/chunks/app.js": "client",
      "server/chunks/ssr.js": "server secret code",
      "server/chunks/ssr.js.map": "{}",
      "server/app/page.html": "<html></html>",
      "cache/webpack/x.json": "{}",
      "trace": "binary\u0000data",
    },
    async (root) => {
      const adapter = await detectAdapter(root);
      assert.equal(adapter.name, "nextjs");
      const files = await collectFiles(root, adapter);
      assert.deepEqual(
        files.map((file) => file.relativePath),
        ["server/app/page.html", "static/chunks/app.js"],
      );
    },
  );
});

test("a plain directory collects every text file and skips binaries and node_modules", async () => {
  await withTempDir(
    {
      "assets/index-abc.js": "client",
      "index.html": "<html></html>",
      "logo.png": "\u0089PNG\u0000\u0000",
      "node_modules/x/index.js": "dep",
    },
    async (root) => {
      const adapter = await detectAdapter(root);
      assert.equal(adapter.name, "plain");
      const files = await collectFiles(root, adapter);
      assert.deepEqual(
        files.map((file) => file.relativePath),
        ["assets/index-abc.js", "index.html"],
      );
    },
  );
});

test("adapters agree on which env prefixes are public", () => {
  assert.ok(nextjsAdapter.publicEnvPrefixes.includes("NEXT_PUBLIC_"));
  assert.ok(plainAdapter.publicEnvPrefixes.includes("VITE_"));
});
