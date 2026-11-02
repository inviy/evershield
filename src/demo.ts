/**
 * `evershield demo`: the whole tool on a deliberately leaky app, with no
 * config, no accounts and no build step.
 *
 * The app is a tiny "essay report" with a free and a Pro plan. In the leaky
 * version the server sends the Pro metrics to everyone and the page hides
 * them with `filter: blur()`, the bundle carries a billing key and an
 * internal address, and a source map is published. `--fixed` serves the same
 * app after following evershield's remediation, which should report nothing.
 *
 * Everything runs on 127.0.0.1 and is torn down before the command returns.
 */
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";

import { runAudit } from "./audit/run.ts";
import { parseConfig } from "./config.ts";
import type { Finding } from "./index.ts";
import { type Gate, isBlocking, renderText, type Report } from "./report/index.ts";
import { scanArtifact } from "./scan/artifact.ts";
import { PLAYWRIGHT_MISSING } from "./surface/driver.ts";
import { runSurface } from "./surface/run.ts";

export type DemoMode = "leaky" | "fixed";

// Assembled at runtime so no secret-shaped string sits in the source or the
// published package: evershield scans its own build output in CI.
const FAKE_BILLING_KEY = ["sk", "live", "Ex4mpl3NotARealKey0000000000"].join("_");
const INTERNAL_API = ["http://10", "0", "3", "7:8080/admin"].join(".");
const PRO_TOKEN = "pro-demo";

function pageHtml(): string {
  return `<!doctype html>
<html lang="en">
  <head><meta charset="utf-8" /><title>Essay report</title></head>
  <body>
    <h1>Your essay report</h1>
    <p>Total score: <span id="total">…</span></p>
    <section id="pro"></section>
    <p>Upgrade to Pro to see the detailed metrics.</p>
    <script type="module" src="/assets/main.js"></script>
  </body>
</html>
`;
}

function mainJs(mode: DemoMode): string {
  const config =
    mode === "leaky"
      ? `const BILLING_KEY = "${FAKE_BILLING_KEY}";\nconst INTERNAL_API = "${INTERNAL_API}";\n`
      : `const BILLING_KEY = undefined;\nconst INTERNAL_API = "/api";\n`;
  const sourceMap = mode === "leaky" ? "\n//# sourceMappingURL=main.js.map\n" : "\n";
  return `${config}async function load() {
  const report = await (await fetch("/api/report")).json();
  document.getElementById("total").textContent = String(report.total);
  const pro = document.getElementById("pro");
  pro.innerHTML = report.burstiness !== undefined
    ? "<p>Burstiness score " + report.burstiness + " (human-like)</p><p>Perplexity " + report.perplexity + "</p>"
    : "<p>Burstiness score ●●●●</p><p>Perplexity ●●●●</p>";
  if (report.plan !== "pro") pro.style.filter = "blur(6px)";
  window.__debug = { billing: BILLING_KEY, api: INTERNAL_API };
}
load();${sourceMap}`;
}

const SOURCE_MAP = JSON.stringify({
  version: 3,
  file: "main.js",
  sources: ["src/main.ts"],
  sourcesContent: ["// INTERNAL-NOTE: scoring weights are 0.42 structure / 0.33 evidence / 0.25 tone.\n"],
  mappings: "",
});

/** Serve the demo app on an ephemeral 127.0.0.1 port. */
export async function startDemoServer(mode: DemoMode): Promise<{ origin: string; close: () => Promise<void> }> {
  const server: Server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://demo.invalid");
    if (url.pathname === "/api/report") {
      const plan = req.headers.authorization === `Bearer ${PRO_TOKEN}` ? "pro" : "free";
      const body: Record<string, unknown> = { total: 78, plan };
      if (mode === "leaky" || plan === "pro") Object.assign(body, { burstiness: 0.82, perplexity: 41.2 });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
      return;
    }
    if (url.pathname === "/assets/main.js") {
      res.writeHead(200, { "content-type": "text/javascript" });
      res.end(mainJs(mode));
      return;
    }
    if (url.pathname === "/assets/main.js.map" && mode === "leaky") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(SOURCE_MAP);
      return;
    }
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(pageHtml());
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    origin: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

/** The built files a user of the demo app would receive, written to a temp dir for layer 1. */
async function writeBuild(mode: DemoMode, dir: string): Promise<void> {
  await mkdir(path.join(dir, "assets"), { recursive: true });
  await writeFile(path.join(dir, "index.html"), pageHtml());
  await writeFile(path.join(dir, "assets/main.js"), mainJs(mode));
  if (mode === "leaky") await writeFile(path.join(dir, "assets/main.js.map"), SOURCE_MAP);
}

export interface DemoLayer {
  name: "surface" | "response" | "artifact";
  title: string;
  report?: Report;
  skipped?: string;
}

export interface DemoResult {
  mode: DemoMode;
  layers: DemoLayer[];
  findings: Finding[];
}

export interface DemoOptions {
  /** Skip layer 3 even if Playwright is installed (used in tests). */
  noBrowser?: boolean;
}

export async function runDemo(mode: DemoMode, options: DemoOptions = {}): Promise<DemoResult> {
  const server = await startDemoServer(mode);
  let buildDir: string | undefined;
  // Config refuses literal credentials, as it should; the demo passes its
  // token the same way a user would, through an environment variable.
  const env = { ...process.env, EVERSHIELD_DEMO_PRO_TOKEN: PRO_TOKEN };
  const identities = { free: {}, pro: { headers: { Authorization: "Bearer ${EVERSHIELD_DEMO_PRO_TOKEN}" } } };

  const layers: DemoLayer[] = [];
  try {
    const config = parseConfig(
      {
        audit: {
          baseUrl: server.origin,
          tiers: ["free", "pro"],
          identities,
          endpoints: [{ path: "/api/report", tiered: true, expect: { free: { absent: ["burstiness", "perplexity"] } } }],
        },
        surface: {
          baseUrl: server.origin,
          tiers: ["free", "pro"],
          identities,
          pages: [{ path: "/", waitFor: "#pro p" }],
        },
      },
      "demo",
    );
    const surfaceLayer: DemoLayer = { name: "surface", title: "Layer 3 · what the free user's page holds but cannot see" };
    if (options.noBrowser === true) {
      surfaceLayer.skipped = "skipped (--no-browser)";
    } else {
      try {
        surfaceLayer.report = await runSurface(config.surface!, { env });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        // Only a missing Playwright gets the install hint; a missing browser or
        // any other launch failure shows its own first line, which says what to fix.
        surfaceLayer.skipped =
          message === PLAYWRIGHT_MISSING
            ? [
                "skipped: this layer opens the page in a browser and needs Playwright.",
                "   It is the one that finds the blurred Pro numbers sitting in the free user's DOM. To see it:",
                "     npx playwright install chromium            # once, downloads the browser",
                "     npx -p evershield -p playwright evershield demo",
              ].join("\n")
            : `skipped: ${message.split("\n")[0]}`;
      }
    }
    layers.push(surfaceLayer);
    layers.push({ name: "response", title: "Layer 2 · what the free user's API response carries", report: await runAudit(config.audit!, { env }) });
    buildDir = await mkdtemp(path.join(tmpdir(), "evershield-demo-"));
    await writeBuild(mode, buildDir);
    layers.push({ name: "artifact", title: "Layer 1 · what the shipped bundle gives away", report: await scanArtifact(buildDir) });
  } finally {
    await server.close();
    if (buildDir !== undefined) await rm(buildDir, { recursive: true, force: true });
  }

  return { mode, layers, findings: layers.flatMap((layer) => layer.report?.findings ?? []) };
}

export function renderDemoText(result: DemoResult, gate: Gate): string {
  const intro =
    result.mode === "leaky"
      ? [
          "evershield demo · a small SaaS report page with a free and a Pro plan",
          "",
          "The Pro metrics look locked: the free user sees them blurred.",
          "Here is what that free user actually receives.",
        ]
      : ["evershield demo --fixed · the same app after following evershield's fixes"];
  const lines = [...intro, ""];
  for (const layer of result.layers) {
    lines.push(`━━ ${layer.title}`);
    if (layer.report === undefined) {
      lines.push(`   ${layer.skipped ?? "skipped"}`, "");
      continue;
    }
    // Drop the per-layer header lines (version, target): the demo prints its own.
    const body = renderText(layer.report, gate).split("\n").slice(3).join("\n").trimEnd();
    lines.push(body, "");
  }
  const blocking = result.findings.filter((finding) => isBlocking(finding, gate)).length;
  if (result.mode === "leaky") {
    lines.push(
      `${result.findings.length} finding(s), ${blocking} blocking. The paywall was CSS; the data was already in the free user's hands.`,
      "",
      "See the same app after the fixes:   npx evershield demo --fixed",
      "Check your own app:                 npx evershield init",
    );
  } else {
    lines.push(`${result.findings.length} finding(s). Withheld on the server, placeholders behind the blur, no key or map shipped.`);
  }
  return `${lines.join("\n")}\n`;
}

export function renderDemoJson(result: DemoResult, gate: Gate): string {
  const layers = result.layers.map((layer) => ({
    layer: layer.name,
    ...(layer.skipped === undefined ? {} : { skipped: layer.skipped }),
    findings: layer.report?.findings ?? [],
  }));
  const blocking = result.findings.filter((finding) => isBlocking(finding, gate)).length;
  return `${JSON.stringify({ demo: result.mode, layers, gate, blocking }, null, 2)}\n`;
}
