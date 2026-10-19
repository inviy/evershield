import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import test from "node:test";

import { parseConfig } from "../config.ts";
import { launchPlaywrightDriver, type SurfaceDriver } from "./driver.ts";
import { runSurface } from "./run.ts";
import type { SurfaceSnapshot } from "./types.ts";

const METRIC = "Burstiness score 0.82 (human-like)";
const RUBRIC = "Structure rubric detail 18 of 20";
const NOTE = "Interview question bank, five items";
const STORED = "Stored premium explanation text";

/** A small app with every way of faking a paywall, keyed by the x-tier header or tier cookie. */
function page(tier: string): string {
  const pro = tier === "pro";
  const hide = (style: string) => (pro ? "" : style);
  return `<!doctype html><html><head><title>Report</title>
<script>localStorage.setItem("result", JSON.stringify({ explanation: ["Stored premium", "explanation text"].join(" ") }));</script>
</head><body>
<h1>Your report summary</h1>
<p id="metric" style="${hide("filter: blur(6px)")}">${METRIC}</p>
<section style="${hide("display:none")}"><p>${RUBRIC}</p></section>
<div style="${hide("max-height:0; overflow:hidden")}"><p>${NOTE}</p></div>
${pro ? `<p>${STORED}</p>` : ""}
<div role="tabpanel" hidden><p>Settings tab content for all</p></div>
<p style="filter: blur(4px)">${pro ? "" : "●●●●●●"}</p>
<p class="upsell">${pro ? "Thanks for being Pro" : "Upgrade to Pro"}</p>
</body></html>`;
}

async function withApp(body: (baseUrl: string) => Promise<void>): Promise<void> {
  const server: Server = createServer((request, response) => {
    const cookieTier = /(?:^|; )tier=(\w+)/.exec(request.headers.cookie ?? "")?.[1];
    const tier = String(request.headers["x-tier"] ?? cookieTier ?? "anonymous");
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end(page(tier));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    await body(`http://127.0.0.1:${(server.address() as AddressInfo).port}`);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

async function tryDriver(): Promise<SurfaceDriver | string> {
  try {
    return await launchPlaywrightDriver();
  } catch (error) {
    return error instanceof Error ? error.message.split("\n")[0]! : String(error);
  }
}

test("against a real browser: every cosmetic paywall is found, shared hidden UI and placeholders are not", async (t) => {
  const driver = await tryDriver();
  if (typeof driver === "string") {
    // CI installs Chromium, so this must not skip there.
    if (process.env.CI !== undefined) throw new Error(`Chromium is required in CI: ${driver}`);
    t.skip(`no Chromium available for Playwright: ${driver}`);
    return;
  }
  try {
    await withApp(async (baseUrl) => {
      const config = parseConfig(
        {
          surface: {
            baseUrl,
            tiers: ["free", "pro"],
            identities: { free: { cookies: { tier: "${EVERSHIELD_TEST_FREE_COOKIE}" } }, pro: { headers: { "x-tier": "pro" } } },
            pages: [{ path: "/report", expect: { free: { absentSelectors: ["#metric"] } } }],
          },
        },
        "test",
      ).surface!;
      const result = await runSurface(config, { driver, env: { EVERSHIELD_TEST_FREE_COOKIE: "free" } });
      assert.equal(result.snapshotsEvaluated, 2, result.warnings.join("\n"));

      const byRule = (id: string) => result.findings.filter((finding) => finding.ruleId === id);
      const hidden = byRule("surface/hidden-higher-tier-content").map((finding) => finding.message);
      assert.equal(hidden.length, 4, hidden.join("\n"));
      assert.ok(hidden.some((message) => message.includes("Burstiness") && message.includes("blur")));
      assert.ok(hidden.some((message) => message.includes("Structure rubric") && message.includes("display")));
      assert.ok(hidden.some((message) => message.includes("Interview question") && message.includes("clipped")));
      assert.ok(hidden.some((message) => message.includes("Stored premium") && message.includes("localStorage")));
      assert.ok(!hidden.some((message) => message.includes("Settings tab")));

      const obscured = byRule("surface/obscured-content");
      assert.equal(obscured.length, 1);
      assert.equal(obscured[0]!.evidence.length, 1, "the ●●● placeholder is not evidence");

      assert.equal(byRule("surface/expected-absent-present").length, 1);
    });
  } finally {
    await driver.close();
  }
});

test("pages that redirect off the audited origin are reported, not evaluated", async () => {
  const driver: SurfaceDriver = {
    async capture(request): Promise<SurfaceSnapshot> {
      return { identity: request.identityName, url: request.url, finalUrl: "https://login.other.test/", status: 200, blocks: [], attributes: [], scripts: [], storage: [], selectorMatches: [] };
    },
    async close() {},
  };
  const config = parseConfig(
    { surface: { baseUrl: "https://app.test", tiers: ["free"], identities: { free: {} }, pages: [{ path: "/" }] } },
    "test",
  ).surface!;
  const result = await runSurface(config, { driver });
  assert.equal(result.snapshotsEvaluated, 0);
  assert.match(result.warnings[0]!, /redirected off the audited origin/);
});

test("surface config rejects literal cookie credentials and unknown identities", () => {
  const base = { baseUrl: "https://app.test", tiers: ["free"], pages: [{ path: "/" }] };
  assert.throws(() => parseConfig({ surface: { ...base, identities: { free: { cookies: { session: "abc123" } } } } }, "c"), /must reference an environment variable/);
  assert.throws(() => parseConfig({ surface: { ...base, identities: { free: { headers: { Authorization: "Bearer abc" } } } } }, "c"), /literal credentials/);
  assert.throws(
    () => parseConfig({ surface: { ...base, identities: { free: {} }, pages: [{ path: "/", expect: { pro: { absentText: ["x"] } } }] } }, "c"),
    /not a defined identity/,
  );
  assert.throws(() => parseConfig({ surface: { ...base, identities: { free: {} }, minTextLength: 2 } }, "c"), /minTextLength/);
});
