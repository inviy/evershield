// Builds the demo app twice (leaky, then fixed as evershield recommends),
// points REA at each the way an attacker would, runs evershield on each, and
// writes results.json and results.md. Nothing leaves 127.0.0.1.
//
//   npm install && node run.mjs
//
// Needs a Chromium: set CHROMIUM=/path/to/chrome, or Playwright's is used.
import { execFile, spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { build } from "vite";

const run = promisify(execFile);
const here = import.meta.dirname;
const evershield = path.resolve(here, "../../dist/bin.js");
const rea = path.join(here, "node_modules/.bin/rea");
const chromium = process.env.CHROMIUM ?? (await import("playwright-core").then((pw) => pw.chromium.executablePath()).catch(() => "chromium"));

// Assembled at runtime so no secret-shaped string is ever committed.
const FAKE_KEY = ["sk", "live", "Ex4mpl3NotARealKey0000000000"].join("_");
const INTERNAL = "http://10.0.3.7:8080/admin";

const LEAKS = [
  { id: "secret", what: `Stripe secret key in the bundle`, marker: FAKE_KEY },
  { id: "internal", what: "Internal API address in the bundle", marker: "10.0.3.7" },
  { id: "source", what: "Original source via a published source map (comments, file layout)", marker: "INTERNAL-NOTE" },
  { id: "paid-dom", what: "Pro metric in the free user's page, hidden by blur", marker: "Burstiness score 0.82" },
  // Matched on the free user's raw response, not on REA's output: the field
  // name is in the client code either way, and REA's passive window opens
  // after the page has already fetched. DevTools or curl see it all the same.
  { id: "paid-api", what: "Pro fields in the free user's API response", marker: '"burstiness":0.82', responseOnly: true },
];

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(url, tries = 50) {
  for (let i = 0; i < tries; i += 1) {
    try {
      const response = await fetch(url);
      if (response.ok) return response;
    } catch {}
    await sleep(200);
  }
  throw new Error(`${url} never came up`);
}

async function reaJson(args) {
  try {
    const { stdout } = await run(rea, [...args, "--format", "json"], { maxBuffer: 256 * 1024 * 1024, env: { ...process.env, NO_COLOR: "1" } });
    return stdout;
  } catch (error) {
    return `${error.stdout ?? ""}${error.stderr ?? ""}`;
  }
}

async function evershieldRun(args, env = {}) {
  try {
    const { stdout } = await run("node", [evershield, ...args, "--format", "json"], { env: { ...process.env, ...env }, cwd: here });
    return JSON.parse(stdout);
  } catch (error) {
    if (error.code === 1) return JSON.parse(error.stdout);
    throw new Error(`evershield ${args.join(" ")} failed: ${error.stderr}`);
  }
}

async function one(mode, port, cdpPort) {
  const leaky = mode === "leaky";
  await writeFile(
    path.join(here, "app/config.js"),
    leaky
      ? `export const BILLING_KEY = "${FAKE_KEY}";\nexport const INTERNAL_API = "${INTERNAL}";\n`
      : `// The billing key lives on the server; the client calls same-origin /api.\nexport const BILLING_KEY = undefined;\nexport const INTERNAL_API = "/api";\n`,
  );
  const outDir = path.join(here, `dist-${mode}`);
  await build({ root: path.join(here, "app"), logLevel: "silent", build: { outDir, emptyOutDir: true, sourcemap: leaky } });

  const server = spawn("node", [path.join(here, "server.mjs")], { env: { ...process.env, MODE: mode, PORT: String(port) }, stdio: "ignore" });
  const profile = await mkdtemp(path.join(tmpdir(), "rea-profile-"));
  const origin = `http://127.0.0.1:${port}`;
  const browser = spawn(chromium, ["--headless=new", "--no-sandbox", `--remote-debugging-port=${cdpPort}`, `--user-data-dir=${profile}`, "--password-store=basic", `${origin}/`], { stdio: "ignore" });
  try {
    await waitFor(`${origin}/`);
    const endpoint = `http://127.0.0.1:${cdpPort}`;
    const targets = await (await waitFor(`${endpoint}/json/list`)).json();
    const target = targets.find((t) => t.type === "page" && t.url.startsWith(origin));
    if (target === undefined) throw new Error("no page target");
    await sleep(1500); // let the page fetch /api/report and render

    // What REA recovers, as an attacker would run it.
    const reaOut = {
      inspect: await reaJson(["inspect-web-page", endpoint, target.id, "--include-script-sources", "--include-accessibility-text", "--include-json-body-shapes", "--include-storage-keys", "--observation-ms", "1500"]),
      bundle: await reaJson(["analyze-web-bundle", endpoint, target.id, "--fetch-source-maps", "--observation-ms", "1500"]),
      static: await reaJson(["analyze-javascript-application", outDir]),
    };
    // The free user's raw API response, as DevTools' network tab shows it.
    const api = await (await fetch(`${origin}/api/report`)).text();
    const recovered = Object.fromEntries(
      LEAKS.map((leak) => {
        const where = leak.responseOnly ? [] : Object.entries(reaOut).filter(([, text]) => text.includes(leak.marker)).map(([name]) => `rea ${name}`);
        if (leak.responseOnly && api.includes(leak.marker)) where.push("free user's response");
        return [leak.id, where];
      }),
    );

    // What evershield reports on the same build and server.
    const env = { EVERSHIELD_DEMO_PRO: "pro-demo" };
    const config = {
      ignore: [],
      audit: {
        baseUrl: origin,
        tiers: ["free", "pro"],
        identities: { free: {}, pro: { headers: { Authorization: "Bearer ${EVERSHIELD_DEMO_PRO}" } } },
        endpoints: [{ path: "/api/report", tiered: true, expect: { free: { absent: ["burstiness", "perplexity"] } } }],
      },
      surface: {
        baseUrl: origin,
        tiers: ["free", "pro"],
        identities: { free: {}, pro: { headers: { Authorization: "Bearer ${EVERSHIELD_DEMO_PRO}" } } },
        pages: [{ path: "/", waitFor: "#pro p" }],
      },
    };
    const configPath = path.join(here, `evershield-${mode}.config.json`);
    await writeFile(configPath, JSON.stringify(config, null, 2));
    const findings = [
      ...(await evershieldRun(["scan", outDir, "--config", configPath])).findings,
      ...(await evershieldRun(["audit", "--config", configPath], env)).findings,
      ...(await evershieldRun(["surface", "--config", configPath], env)).findings,
    ];
    await rm(configPath);
    return { recovered, findings: findings.map((f) => ({ ruleId: f.ruleId, severity: f.severity, confidence: f.confidence, message: f.message })) };
  } finally {
    browser.kill();
    server.kill();
    await sleep(300);
    await rm(profile, { recursive: true, force: true });
  }
}

const results = { leaky: await one("leaky", 4173, 9333), fixed: await one("fixed", 4174, 9334) };
await rm(path.join(here, "app/config.js"));
await writeFile(path.join(here, "results.json"), `${JSON.stringify({ rea: "rea-agents 6.5.0", leaks: LEAKS.map(({ marker, responseOnly, ...rest }) => rest), ...results }, null, 2)}\n`);

const yes = (list) => (list.length > 0 ? `yes (${list.join(", ")})` : "no");
const lines = [
  "| Leak | Recovered from the leaky app | evershield flags it | Recovered after the fix |",
  "|---|---|---|---|",
  ...LEAKS.map((leak) => {
    const rule = { secret: "artifact/secret-like-string", internal: "artifact/internal-endpoint", source: "artifact/source-map-published", "paid-dom": "surface/", "paid-api": "response/" }[leak.id];
    const flagged = results.leaky.findings.filter((f) => f.ruleId.startsWith(rule)).map((f) => `\`${f.ruleId}\` ${f.severity}/${f.confidence}`);
    return `| ${leak.what} | ${yes(results.leaky.recovered[leak.id])} | ${flagged.length > 0 ? [...new Set(flagged)].join("<br>") : "no"} | ${yes(results.fixed.recovered[leak.id])} |`;
  }),
  "",
  `evershield findings on the fixed app: ${results.fixed.findings.length}.`,
];
await writeFile(path.join(here, "results.md"), `${lines.join("\n")}\n`);
console.log(lines.join("\n"));
