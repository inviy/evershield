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

test("sarif format and --output write a report file and summarise on stdout", async () => {
  await withTempDir({ "assets/app.js": `const k = "${fake.awsAccessKeyId()}";` }, async (root) => {
    const result = await run(["scan", root, "--format", "sarif", "--output", `${root}/report.sarif`]);
    assert.equal(result.code, 1);
    assert.match(result.stdout, /1 finding\(s\), 1 blocking, 0 ignored · sarif report written to/);
    const { readFile } = await import("node:fs/promises");
    const sarif = JSON.parse(await readFile(`${root}/report.sarif`, "utf8")) as { version: string; runs: Array<{ results: unknown[] }> };
    assert.equal(sarif.version, "2.1.0");
    assert.equal(sarif.runs[0]!.results.length, 1);
  });
});

test("config ignores remove findings with a reason and can set the gate; CLI flags win", async () => {
  const files = {
    "build/app.js": `const base = "http://localhost:3000"; const k = "${fake.anthropicKey()}";`,
    "cfg.json": JSON.stringify({
      gate: { failOn: "none" },
      ignore: [{ ruleId: "artifact/internal-endpoint", match: "localhost:3000", reason: "dev fallback, unreachable in prod" }],
    }),
  };
  await withTempDir(files, async (root) => {
    const relaxed = await run(["scan", `${root}/build`, "--config", `${root}/cfg.json`]);
    assert.equal(relaxed.code, 0, "config gate none disables failing");
    assert.match(relaxed.stdout, /1 finding\(s\), 0 blocking .*1 finding\(s\) ignored by config/);
    assert.ok(!relaxed.stdout.includes("localhost"));

    const strict = await run(["scan", `${root}/build`, "--config", `${root}/cfg.json`, "--fail-on", "high"]);
    assert.equal(strict.code, 1, "CLI flag overrides config gate");
  });
});

test("a config without reasons or a missing explicit config is a usage error", async () => {
  await withTempDir(
    { "build/app.js": "ok", "cfg.json": JSON.stringify({ ignore: [{ ruleId: "*" }] }) },
    async (root) => {
      const noReason = await run(["scan", `${root}/build`, "--config", `${root}/cfg.json`]);
      assert.equal(noReason.code, 2);
      assert.match(noReason.stderr, /reason is required/);

      const missing = await run(["scan", `${root}/build`, "--config", `${root}/absent.json`]);
      assert.equal(missing.code, 2);
      assert.match(missing.stderr, /cannot read config/);
    },
  );
});

test("audit without an audit block is a config error; with one it runs and gates", async () => {
  const noBlock = await run(["audit", "--config", "/definitely/not/here.json"]);
  assert.equal(noBlock.code, 2);
  assert.match(noBlock.stderr, /cannot read config/);

  await withTempDir({ "cfg.json": JSON.stringify({ ignore: [] }) }, async (root) => {
    const result = await run(["audit", "--config", `${root}/cfg.json`]);
    assert.equal(result.code, 2);
    assert.match(result.stderr, /no "audit" block/);
  });

  const unreachable = { audit: { baseUrl: "http://127.0.0.1:9", tiers: ["a"], identities: { a: {} }, endpoints: [{ path: "/x" }], timeoutMs: 2000 } };
  await withTempDir({ "cfg.json": JSON.stringify(unreachable) }, async (root) => {
    const result = await run(["audit", "--config", `${root}/cfg.json`]);
    assert.equal(result.code, 2, "an audit that evaluated nothing must not pass");
    assert.match(result.stderr, /nothing was audited/);
  });

  const { createServer } = await import("node:http");
  const server = createServer((req, res) => {
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ plan: req.headers.authorization ? "pro" : "free", premium_report: { pages: 3 } }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as { port: number };
  process.env.EVERSHIELD_TEST_CLI = "t";
  try {
    const config = {
      audit: {
        baseUrl: `http://127.0.0.1:${port}`,
        tiers: ["free", "pro"],
        identities: { free: {}, pro: { headers: { Authorization: "Bearer ${EVERSHIELD_TEST_CLI}" } } },
        endpoints: [{ path: "/api/report", expect: { free: { absent: ["premium_report"] } } }],
      },
    };
    await withTempDir({ "cfg.json": JSON.stringify(config) }, async (root) => {
      const result = await run(["audit", "--config", `${root}/cfg.json`]);
      assert.equal(result.code, 1);
      assert.match(result.stdout, /response audit · 1 endpoint\(s\) × 2 identities \(free < pro\)/);
      assert.match(result.stdout, /✖ \[high\/high\] GET \/api\/report returns "premium_report" to free/);
      assert.match(result.stdout, /• \[medium\/medium\] .*the name suggests a higher tier's data/);
    });
  } finally {
    delete process.env.EVERSHIELD_TEST_CLI;
    server.close();
  }
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

test("surface without a surface block is a config error", async () => {
  await withTempDir({ "cfg.json": JSON.stringify({ ignore: [] }) }, async (root) => {
    const result = await run(["surface", "--config", `${root}/cfg.json`]);
    assert.equal(result.code, 2);
    assert.match(result.stderr, /no "surface" block/);
  });
  const extra = await run(["surface", "oops"]);
  assert.equal(extra.code, 2);
  assert.match(extra.stderr, /surface: unexpected argument "oops"/);
});
