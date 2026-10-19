/**
 * False-positive regression corpus.
 *
 *   node --experimental-strip-types scripts/corpus.ts [--apps] [--update] [--report docs/corpus.md]
 *
 * Downloads each pinned package in corpus/packages.json (cached in
 * .corpus-cache/), scans the code a browser could receive, and compares the
 * findings with corpus/expected.json. With --apps it also generates and
 * builds the default apps in corpus/apps.json and scans their output with
 * the adapter a user would use. Every expected finding carries a
 * reason. Exit 1 when a finding appears that is not expected, or an
 * expected one disappears: either way a rule changed behaviour on real code
 * and a person should look. `--update` rewrites expected.json, keeping
 * existing reasons and marking new entries "UNREVIEWED".
 */
import { execFileSync } from "node:child_process";
import { cp, mkdir, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";

import type { Finding } from "../src/index.ts";
import { ADAPTERS } from "../src/scan/adapters.ts";
import { scanArtifact } from "../src/scan/artifact.ts";
import { PACKAGED } from "../src/scan/files.ts";

interface App {
  name: string;
  create: string;
  /** Defaults to installing dependencies and running the build script. */
  build?: string;
  output: string;
  adapter: "plain" | "nextjs";
}

interface Target {
  spec: string;
  dir: string;
  adapter: "plain" | "nextjs";
  files: number;
  bytes: number;
}

interface Expected {
  ruleId: string;
  path: string;
  severity: string;
  confidence: string;
  reason: string;
}

const root = path.resolve(import.meta.dirname, "..");
const cache = path.join(root, ".corpus-cache");
const SHIPPED = /\.(?:m?js|cjs|css|html?)$/i;
const NOT_SHIPPED = /(?:\.d\.[mc]?ts$|\.map$|(?:^|\/)(?:test|tests|__tests__|spec)\/)/i;

/** Content hashes in build file names change with every dependency bump; compare without them. */
function stablePath(filePath: string): string {
  return filePath.replace(/([-.])[0-9a-f]{8,}(?=[.-])/g, "$1<hash>");
}

function key(entry: { ruleId: string; path: string }): string {
  return `${entry.ruleId} ${stablePath(entry.path)}`;
}

async function fetchPackage(spec: string): Promise<string> {
  const dir = path.join(cache, spec.replace(/[/@]/g, "_"));
  try {
    await stat(path.join(dir, "package", "package.json"));
    return path.join(dir, "package");
  } catch {
    // Not cached yet.
  }
  await mkdir(dir, { recursive: true });
  const out = execFileSync("npm", ["pack", spec, "--json", "--pack-destination", dir], { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] });
  const filename = (JSON.parse(out) as Array<{ filename: string }>)[0]?.filename;
  if (filename === undefined) throw new Error(`npm pack ${spec} returned no tarball`);
  execFileSync("tar", ["-xzf", path.join(dir, filename), "-C", dir]);
  await rm(path.join(dir, filename));
  return path.join(dir, "package");
}

/** Copy only what a browser could receive into a staging directory, preserving paths. */
async function stage(packageDir: string, into: string): Promise<{ files: number; bytes: number }> {
  await rm(into, { recursive: true, force: true });
  let files = 0;
  let bytes = 0;
  for (const entry of await readdir(packageDir, { recursive: true, withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const abs = path.join(entry.parentPath, entry.name);
    const rel = path.relative(packageDir, abs).split(path.sep).join("/");
    if (!SHIPPED.test(rel) || NOT_SHIPPED.test(rel)) continue;
    await mkdir(path.dirname(path.join(into, rel)), { recursive: true });
    await cp(abs, path.join(into, rel));
    files += 1;
    bytes += (await stat(abs)).size;
  }
  return { files, bytes };
}

/** Generate and build one app; the build is cached by name. */
async function buildApp(app: App): Promise<Target> {
  const dir = path.join(cache, "apps", app.name);
  const out = path.join(dir, "app", app.output);
  try {
    await stat(out);
  } catch {
    await rm(dir, { recursive: true, force: true });
    await mkdir(dir, { recursive: true });
    const env = { ...process.env, CI: "1", NEXT_TELEMETRY_DISABLED: "1", ASTRO_TELEMETRY_DISABLED: "1", EXPO_NO_TELEMETRY: "1", npm_config_yes: "true" };
    const run = (command: string, cwd: string) => execFileSync("sh", ["-c", command], { cwd, env, stdio: ["ignore", "ignore", "inherit"] });
    run(app.create, dir);
    run(app.build ?? "npm install --no-audit --no-fund --loglevel=error && npm run build", path.join(dir, "app"));
  }
  // Count what the adapter scans, not the whole build directory (.next holds caches and server code).
  const adapter = ADAPTERS[app.adapter];
  let files = 0;
  let bytes = 0;
  for (const entry of await readdir(out, { recursive: true, withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const abs = path.join(entry.parentPath, entry.name);
    const rel = path.relative(out, abs).split(path.sep).join("/");
    if (!adapter.includes(rel) && !PACKAGED.test(rel)) continue;
    files += 1;
    bytes += (await stat(abs)).size;
  }
  return { spec: `app:${app.name}`, dir: out, adapter: app.adapter, files, bytes };
}

async function main(): Promise<number> {
  const args = process.argv.slice(2);
  const update = args.includes("--update");
  const withApps = args.includes("--apps");
  const reportAt = args.indexOf("--report");
  const reportPath = reportAt >= 0 ? args[reportAt + 1] : undefined;

  const { packages } = JSON.parse(await readFile(path.join(root, "corpus/packages.json"), "utf8")) as { packages: string[] };
  const expectedFile = path.join(root, "corpus/expected.json");
  let expected: Record<string, Expected[]> = {};
  try {
    expected = JSON.parse(await readFile(expectedFile, "utf8")) as Record<string, Expected[]>;
  } catch {
    // First run.
  }

  const targets: Target[] = [];
  for (const spec of packages) {
    const staged = path.join(cache, "_staged", spec.replace(/[/@]/g, "_"));
    targets.push({ spec, dir: staged, adapter: "plain", ...(await stage(await fetchPackage(spec), staged)) });
  }
  if (withApps) {
    const { apps } = JSON.parse(await readFile(path.join(root, "corpus/apps.json"), "utf8")) as { apps: App[] };
    for (const app of apps) targets.push(await buildApp(app));
  }

  const rows: Array<{ spec: string; files: number; bytes: number; findings: Finding[] }> = [];
  const unexpected: string[] = [];
  const missing: string[] = [];
  // Entries for targets not scanned this run (apps without --apps) are kept as they are.
  const next: Record<string, Expected[]> = Object.fromEntries(
    Object.entries(expected).filter(([spec]) => !targets.some((target) => target.spec === spec)),
  );

  for (const { spec, dir, adapter, files, bytes } of targets) {
    const result = await scanArtifact(dir, { adapter });
    rows.push({ spec, files, bytes, findings: result.findings });

    const known = new Map((expected[spec] ?? []).map((entry) => [key(entry), entry]));
    const seen = new Set<string>();
    const entries: Expected[] = [];
    for (const finding of result.findings) {
      const first = finding.evidence[0];
      const filePath = stablePath(first?.kind === "file" ? first.path : "");
      const k = key({ ruleId: finding.ruleId, path: filePath });
      if (seen.has(k)) continue;
      seen.add(k);
      const prior = known.get(k);
      if (prior === undefined) unexpected.push(`${spec}: [${finding.severity}/${finding.confidence}] ${finding.ruleId} at ${filePath}: ${finding.message}`);
      entries.push({ ruleId: finding.ruleId, path: filePath, severity: finding.severity, confidence: finding.confidence, reason: prior?.reason ?? "UNREVIEWED" });
    }
    for (const [k] of known) if (!seen.has(k)) missing.push(`${spec}: ${k}`);
    if (entries.length > 0) next[spec] = entries;
  }

  const totalFiles = rows.reduce((sum, row) => sum + row.files, 0);
  const totalBytes = rows.reduce((sum, row) => sum + row.bytes, 0);
  const all = rows.flatMap((row) => row.findings);
  const blocking = all.filter((f) => ["critical", "high"].includes(f.severity) && ["high", "medium"].includes(f.confidence));
  console.log(`corpus: ${rows.length} targets, ${totalFiles} files, ${(totalBytes / 1024 / 1024).toFixed(1)} MiB, ${all.length} finding(s), ${blocking.length} blocking at the default gate`);
  for (const line of unexpected) console.log(`  NEW      ${line}`);
  for (const line of missing) console.log(`  MISSING  ${line}`);

  const truePositives = Object.values(next)
    .flat()
    .filter((entry) => entry.reason.startsWith("True positive") && ["critical", "high"].includes(entry.severity) && ["high", "medium"].includes(entry.confidence)).length;

  if (update) await writeFile(expectedFile, `${JSON.stringify(next, null, 2)}\n`);

  if (reportPath !== undefined) {
    const lines = [
      "# False-positive corpus",
      "",
      "Generated by `scripts/corpus.ts`; do not edit by hand.",
      "",
      `${rows.filter((row) => !row.spec.startsWith("app:")).length} pinned npm packages (every JS, CSS and HTML file in each tarball; source maps and type declarations excluded) and ${rows.filter((row) => row.spec.startsWith("app:")).length} default apps from pinned generators, built and scanned as deployed: ${totalFiles} files, ${(totalBytes / 1024 / 1024).toFixed(1)} MiB.`,
      "",
      `**False positives at the default gate (severity ≥ high, confidence ≥ medium): ${blocking.length - truePositives}.** ${truePositives} blocking finding(s) are true positives, recorded with their reason. The other ${all.length - blocking.length} finding(s) are low-severity hints that never fail a build; each is listed in \`corpus/expected.json\` with the reason it is benign here.`,
      "",
      "| Target | Files | KiB | Blocking | All findings |",
      "|---|---:|---:|---:|---:|",
      ...rows.map((row) => {
        const rowBlocking = row.findings.filter((f) => ["critical", "high"].includes(f.severity) && ["high", "medium"].includes(f.confidence)).length;
        return `| \`${row.spec}\` | ${row.files} | ${Math.round(row.bytes / 1024)} | ${rowBlocking} | ${row.findings.length} |`;
      }),
      "",
    ];
    await writeFile(path.resolve(root, reportPath), lines.join("\n"));
  }

  return update ? 0 : unexpected.length + missing.length > 0 ? 1 : 0;
}

process.exitCode = await main();
