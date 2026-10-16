import assert from "node:assert/strict";
import test from "node:test";

import { run } from "./cli.ts";
import { VERSION } from "./index.ts";
import { fake, withTempDir } from "./test-support.ts";

test("prints help with no arguments and exits 0", async () => {
  const result = await run([]);
  assert.equal(result.code, 0);
  assert.match(result.stdout, /Usage:/);
  assert.equal(result.stderr, "");
});

test("prints the version", async () => {
  for (const flag of ["--version", "-v", "version"]) {
    const result = await run([flag]);
    assert.equal(result.code, 0);
    assert.equal(result.stdout, `${VERSION}\n`);
  }
});

test("usage errors exit 2 and show help", async () => {
  for (const argv of [["scan"], ["frobnicate"], ["scan", ".", "--format", "yaml"], ["scan", ".", "--fail-on", "sometimes"]]) {
    const result = await run(argv);
    assert.equal(result.code, 2, argv.join(" "));
    assert.match(result.stderr, /Usage:/);
  }
});

test("a missing directory is a runtime error, exit 2", async () => {
  const result = await run(["scan", "/definitely/not/here"]);
  assert.equal(result.code, 2);
  assert.match(result.stderr, /not a directory/);
});

test("a clean artifact exits 0 and says so", async () => {
  await withTempDir({ "assets/app.js": 'console.log("hello");' }, async (root) => {
    const result = await run(["scan", root]);
    assert.equal(result.code, 0);
    assert.match(result.stdout, /No findings/);
  });
});

test("a planted credential exits 1 in text mode and is redacted", async () => {
  const secret = fake.anthropicKey();
  await withTempDir({ "assets/app.js": `const k = "${secret}";` }, async (root) => {
    const result = await run(["scan", root]);
    assert.equal(result.code, 1);
    assert.match(result.stdout, /✖ \[critical\/high\] Anthropic API key/);
    assert.ok(!result.stdout.includes(secret));
  });
});

test("json output is parseable and carries the gate", async () => {
  await withTempDir({ "assets/app.js": `const k = "${fake.awsAccessKeyId()}";` }, async (root) => {
    const result = await run(["scan", root, "--format", "json"]);
    assert.equal(result.code, 1);
    const parsed = JSON.parse(result.stdout) as { findings: unknown[]; blocking: number; gate: { failOn: string } };
    assert.equal(parsed.findings.length, 1);
    assert.equal(parsed.blocking, 1);
    assert.equal(parsed.gate.failOn, "high");
  });
});

test("low-confidence findings never fail the build by default; the gate can be tightened or disabled", async () => {
  await withTempDir({ "assets/app.js": `const config = { apiKey: "${fake.highEntropy()}" };` }, async (root) => {
    const lenient = await run(["scan", root]);
    assert.equal(lenient.code, 0);
    assert.match(lenient.stdout, /1 finding\(s\), 0 blocking/);

    const strict = await run(["scan", root, "--min-confidence", "low"]);
    assert.equal(strict.code, 1);

    const off = await run(["scan", root, "--fail-on", "none"]);
    assert.equal(off.code, 0);
  });
});
