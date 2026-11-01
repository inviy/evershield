import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import { withTempDir } from "../test-support.ts";
import { scanArtifact } from "../scan/artifact.ts";
import { sensitivePath } from "../scan/sensitive-paths.ts";

test("sensitivePath: credentials, keystores, git metadata and agent config; not templates or look-alikes", () => {
  assert.equal(sensitivePath(".env")?.severity, "high");
  assert.equal(sensitivePath("deploy/.env.production")?.confidence, "medium");
  assert.equal(sensitivePath("keys/id_ed25519")?.severity, "critical");
  assert.equal(sensitivePath("android/release.keystore")?.kind, "a signing keystore");
  assert.ok(sensitivePath(".git/config"));
  assert.ok(sensitivePath(".mcp.json"));
  assert.ok(sensitivePath(".claude/settings.local.json"));
  for (const benign of [".env.example", ".env.sample", "env.js", "environment.ts", "id_rsa.pub", ".git/objects/ab/cdef", "config.json", ".envrc"]) {
    assert.equal(sensitivePath(benign), null, benign);
  }
});

test("a deploy directory that copied the project root: .env, .git/HEAD and a binary keystore are reported", async () => {
  await withTempDir({ "index.html": "<p>hi</p>", ".env": "DATABASE_URL=postgres://localhost/app", ".env.example": "DATABASE_URL=" }, async (root) => {
    await mkdir(path.join(root, ".git"));
    await writeFile(path.join(root, ".git", "HEAD"), "ref: refs/heads/main\n");
    await writeFile(path.join(root, "release.keystore"), Buffer.from([0xfe, 0xed, 0xfe, 0xed, 0, 0, 0, 2]));
    const result = await scanArtifact(root);
    const flagged = result.findings.filter((f) => f.ruleId === "artifact/sensitive-file-shipped").map((f) => (f.evidence[0]?.kind === "file" ? f.evidence[0].path : ""));
    assert.deepEqual(flagged.sort(), [".env", ".git/HEAD", "release.keystore"]);
    assert.ok(!JSON.stringify(result).includes("postgres://"), "file content is not quoted");
  });
});

test("a Next.js build only reports what static/ serves", async () => {
  await withTempDir({ "BUILD_ID": "x", "static/chunks/a.js": "1", ".env": "SECRET=1", "static/.env": "SECRET=1" }, async (root) => {
    const result = await scanArtifact(root);
    const flagged = result.findings.filter((f) => f.ruleId === "artifact/sensitive-file-shipped").map((f) => (f.evidence[0]?.kind === "file" ? f.evidence[0].path : ""));
    assert.deepEqual(flagged, ["static/.env"]);
  });
});
