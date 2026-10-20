import assert from "node:assert/strict";
import test from "node:test";

import { applyIgnores, ConfigError, globToRegExp, loadConfig, parseConfig } from "./config.ts";
import type { Finding } from "./index.ts";
import { withTempDir } from "./test-support.ts";

const finding = (ruleId: string, filePath: string, message: string, excerpt?: string): Finding => ({
  ruleId,
  layer: "artifact",
  severity: "low",
  confidence: "low",
  message,
  evidence: [excerpt === undefined ? { kind: "file", path: filePath } : { kind: "file", path: filePath, excerpt }],
});

test("globToRegExp: ** spans directories, * and ? stay inside a segment", () => {
  assert.ok(globToRegExp("static/**/*.js").test("static/chunks/deep/app.js"));
  assert.ok(globToRegExp("static/**/*.js").test("static/app.js"));
  assert.ok(!globToRegExp("static/*.js").test("static/chunks/app.js"));
  assert.ok(globToRegExp("app.?s").test("app.js"));
  assert.ok(!globToRegExp("app.?s").test("app.mjs"));
  assert.ok(globToRegExp("**/vendor.js").test("vendor.js"));
  assert.ok(!globToRegExp("a.b").test("aXb"), "dots are literal");
});

test("parseConfig rejects ignores without a reason and bad gates", () => {
  assert.throws(() => parseConfig({ ignore: [{ ruleId: "artifact/internal-endpoint" }] }, "cfg"), ConfigError);
  assert.throws(() => parseConfig({ ignore: [{ ruleId: "x", reason: "   " }] }, "cfg"), /reason is required/);
  assert.throws(() => parseConfig({ gate: { failOn: "sometimes" } }, "cfg"), /gate.failOn/);
  assert.throws(() => parseConfig({ gate: { minConfidence: "certain" } }, "cfg"), /gate.minConfidence/);
  assert.throws(() => parseConfig([], "cfg"), /expected a JSON object/);
});

test("parseConfig accepts a complete config", () => {
  const config = parseConfig(
    { gate: { failOn: "medium" }, ignore: [{ ruleId: "*", path: "static/vendor/**", reason: "third-party" }] },
    "cfg",
  );
  assert.deepEqual(config.gate, { failOn: "medium" });
  assert.equal(config.ignore.length, 1);
  assert.equal(config.ignore[0]!.path, "static/vendor/**");
});

test("applyIgnores matches on rule, path glob and message substring", () => {
  const findings = [
    finding("artifact/internal-endpoint", "static/chunks/a.js", "localhost URL in static/chunks/a.js: http://localhost:9999", "http://localhost:9999"),
    finding("artifact/internal-endpoint", "static/chunks/a.js", "Private IP address in static/chunks/a.js: 10.0.0.5", "10.0.0.5"),
    finding("artifact/source-map-published", "static/vendor/lib.js.map", "Source map shipped"),
    finding("artifact/source-map-published", "static/chunks/app.js.map", "Source map shipped"),
  ];
  const { kept, ignored } = applyIgnores(findings, [
    { ruleId: "artifact/internal-endpoint", match: "localhost:9999", reason: "supabase-js default" },
    { ruleId: "*", path: "static/vendor/**", reason: "vendored, maps are public upstream" },
  ]);
  assert.equal(ignored.length, 2);
  assert.deepEqual(
    kept.map((item) => item.message),
    ["Private IP address in static/chunks/a.js: 10.0.0.5", "Source map shipped"],
  );
  assert.equal(kept[1]!.evidence[0]!.kind === "file" ? kept[1]!.evidence[0]!.path : "", "static/chunks/app.js.map");
});

test("audit config: validates shape and refuses literal credentials", () => {
  const good = parseConfig(
    {
      audit: {
        baseUrl: "https://api.example.com/ignored/path",
        tiers: ["anonymous", "pro"],
        identities: { anonymous: {}, pro: { headers: { Authorization: "Bearer ${EVERSHIELD_PRO}" } } },
        endpoints: [{ method: "post", path: "/api/x", body: { a: 1 }, tiered: true, expect: { anonymous: { absent: ["detail"] } } }],
      },
    },
    "cfg",
  );
  assert.equal(good.audit?.baseUrl, "https://api.example.com");
  assert.equal(good.audit?.endpoints[0]?.method, "POST");
  assert.deepEqual(good.audit?.endpoints[0]?.expect, { anonymous: { absent: ["detail"] } });

  const base = { baseUrl: "https://api.example.com", tiers: ["a"], identities: { a: {} }, endpoints: [{ path: "/x" }] };
  assert.throws(() => parseConfig({ audit: { ...base, identities: { a: { headers: { Authorization: "Bearer abc123" } } } } }, "cfg"), /literal credentials/);
  assert.throws(() => parseConfig({ audit: { ...base, tiers: ["ghost"] } }, "cfg"), /"ghost" which is not in identities/);
  assert.throws(() => parseConfig({ audit: { ...base, baseUrl: "ftp://x" } }, "cfg"), /http or https/);
  assert.throws(() => parseConfig({ audit: { ...base, endpoints: [{ path: "api/x" }] } }, "cfg"), /must start with/);
  assert.throws(() => parseConfig({ audit: { ...base, endpoints: [{ path: "/x", expect: { nobody: {} } }] } }, "cfg"), /not a defined identity/);
});

test("ignore path globs match response endpoints too", () => {
  const responseFinding: Finding = {
    ruleId: "response/identical-across-tiers",
    layer: "response",
    severity: "low",
    confidence: "low",
    message: "GET /health returns the same body",
    evidence: [{ kind: "response", endpoint: "GET /health", identity: "anonymous", jsonPath: "$" }],
  };
  const { ignored } = applyIgnores([responseFinding], [{ ruleId: "*", path: "GET /health", reason: "health check is public" }]);
  assert.equal(ignored.length, 1);
});

test("loadConfig: default file is optional, explicit file is not, invalid JSON is a ConfigError", async () => {
  await withTempDir({}, async (root) => {
    const missing = await loadConfig(`${root}/nope.json`).catch((error: unknown) => error);
    assert.ok(missing instanceof ConfigError);
  });
  await withTempDir({ "bad.json": "{ not json" }, async (root) => {
    const bad = await loadConfig(`${root}/bad.json`).catch((error: unknown) => error);
    assert.ok(bad instanceof ConfigError);
    assert.match((bad as Error).message, /invalid JSON/);
  });
  // PowerShell 5's Set-Content -Encoding utf8 and Notepad write a byte order mark.
  await withTempDir({ "bom.json": `\uFEFF${JSON.stringify({ ignore: [{ ruleId: "*", reason: "test" }] })}` }, async (root) => {
    const { config } = await loadConfig(`${root}/bom.json`);
    assert.equal(config.ignore.length, 1);
  });
  await withTempDir({ "ok.json": JSON.stringify({ ignore: [{ ruleId: "*", reason: "test" }] }) }, async (root) => {
    const { config, source } = await loadConfig(`${root}/ok.json`);
    assert.equal(config.ignore.length, 1);
    assert.ok(source?.endsWith("ok.json"));
  });
});
