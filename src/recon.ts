/**
 * `evershield recon`: the attacker's view of a build or app package.
 *
 * Reverse-engineering tools such as REA cannot be blocked: they run in the
 * attacker's own browser or on their own copy of the app. What can be
 * controlled is what they get. recon lists it in two parts:
 *
 * - **Worth taking**: findings an attacker can use directly (credentials,
 *   original source, internal addresses). The gate applies to these, so a
 *   passing recon means the tools come back empty-handed.
 * - **Map**: what any tool reconstructs from shipped code no matter what
 *   (hosts, API paths, source map coverage, public env names). Informational:
 *   it is the attack surface to keep server-side checks on.
 *
 * With `--rea`, REA's static JavaScript analyzer runs on the same target and
 * each finding's unredacted value is looked up in REA's output, in memory
 * only, to show whether the tool actually recovers it.
 */
import { execFile } from "node:child_process";
import path from "node:path";

import type { Finding } from "./index.ts";
import { VERSION } from "./index.ts";
import { type CollectedTarget, collectTarget, runArtifactRules } from "./scan/artifact.ts";
import type { ScannedFile } from "./scan/files.ts";

export type ReconCategory = "credential" | "source" | "internal-address" | "other";

export interface ReconItem {
  category: ReconCategory;
  finding: Finding;
  /** true: REA's output contains the value; false: it does not; null: not checked. */
  reaRecovered: boolean | null;
}

export interface ReconMap {
  /** Hosts referenced by absolute URLs, most frequent first. */
  hosts: Array<{ host: string; count: number }>;
  /** API-looking paths in string literals. */
  apiPaths: string[];
  sourceMaps: { files: number; originalSources: number; withContent: number };
  /** Framework-public env names still present in the output. */
  publicEnvNames: string[];
}

export interface ReconRea {
  status: "not-run" | "ran" | "skipped" | "failed";
  detail?: string;
}

export interface ReconResult {
  version: string;
  layer: "recon";
  target: string;
  adapter: CollectedTarget["adapterName"];
  filesScanned: number;
  startedAt: string;
  finishedAt: string;
  items: ReconItem[];
  /** The same findings, for the gate, ignores and SARIF. */
  findings: Finding[];
  ignored: number;
  map: ReconMap;
  rea: ReconRea;
}

export interface ReconOptions {
  adapter?: "nextjs" | "plain";
  /** Run REA's static analyzer; the executable name or path. */
  reaBin?: string;
  reaTimeoutMs?: number;
}

function categorize(finding: Finding): ReconCategory {
  if (finding.ruleId === "artifact/source-map-published") return "source";
  if (finding.ruleId === "artifact/internal-endpoint") return "internal-address";
  if (finding.ruleId === "artifact/secret-like-string" || finding.ruleId === "artifact/sensitive-env-name") return "credential";
  return "other";
}

const URL_HOST = /\bhttps?:\/\/((?:[a-z0-9-]+\.)+[a-z]{2,}|localhost|\d{1,3}(?:\.\d{1,3}){3})(?::\d{2,5})?/gi;
const API_PATH = /["'`](\/(?:api|graphql|rest|rpc|trpc|admin|internal|v\d+)(?:\/[\w\-.:{}$]*)*)(?=["'`?])/g;
const PUBLIC_ENV = /\b(?:NEXT_PUBLIC|VITE|PUBLIC|REACT_APP|NUXT_PUBLIC|EXPO_PUBLIC|GATSBY|VUE_APP)_[A-Z0-9_]{2,}\b/g;
const INLINE_MAP = /sourceMappingURL=data:application\/json[^,]*;base64,([A-Za-z0-9+/=]+)/g;

function countSources(json: string, into: ReconMap["sourceMaps"]): void {
  try {
    const map = JSON.parse(json) as { sources?: unknown[]; sourcesContent?: unknown[] };
    into.files += 1;
    into.originalSources += Array.isArray(map.sources) ? map.sources.length : 0;
    into.withContent += Array.isArray(map.sourcesContent) ? map.sourcesContent.filter((content) => typeof content === "string").length : 0;
  } catch {
    // Not a parseable map; the source-map rule still reports the file.
  }
}

export function buildMap(files: ScannedFile[]): ReconMap {
  const hosts = new Map<string, number>();
  const apiPaths = new Set<string>();
  const publicEnvNames = new Set<string>();
  const sourceMaps = { files: 0, originalSources: 0, withContent: 0 };
  for (const file of files) {
    if (file.relativePath.endsWith(".map")) {
      countSources(file.text, sourceMaps);
      continue;
    }
    for (const match of file.text.matchAll(URL_HOST)) {
      const host = match[1]!.toLowerCase();
      hosts.set(host, (hosts.get(host) ?? 0) + 1);
    }
    for (const match of file.text.matchAll(API_PATH)) if (apiPaths.size < 200) apiPaths.add(match[1]!);
    for (const match of file.text.matchAll(PUBLIC_ENV)) publicEnvNames.add(match[0]);
    for (const match of file.text.matchAll(INLINE_MAP)) countSources(Buffer.from(match[1]!, "base64").toString("utf8"), sourceMaps);
  }
  return {
    hosts: [...hosts.entries()].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).slice(0, 50).map(([host, count]) => ({ host, count })),
    apiPaths: [...apiPaths].sort(),
    sourceMaps,
    publicEnvNames: [...publicEnvNames].sort(),
  };
}

/**
 * npm installs `rea` on Windows as `rea.cmd`, which only a shell can run, so
 * Windows goes through cmd.exe with every argument quoted.
 */
function reaInvocation(bin: string, args: string[]): { file: string; args: string[]; shell: boolean } {
  if (process.platform !== "win32") return { file: bin, args, shell: false };
  const quote = (value: string) => `"${value.replace(/"/g, '""')}"`;
  return { file: quote(bin), args: args.map(quote), shell: true };
}

function runRea(bin: string, target: string, timeoutMs: number): Promise<{ ok: true; output: string } | { ok: false; detail: string }> {
  const invocation = reaInvocation(bin, ["analyze-javascript-application", target, "--format", "json"]);
  return new Promise((resolve) => {
    execFile(
      invocation.file,
      invocation.args,
      { maxBuffer: 1024 * 1024 * 1024, timeout: timeoutMs, env: { ...process.env, NO_COLOR: "1" }, shell: invocation.shell },
      (error, stdout, stderr) => {
        // cmd.exe reports a missing command as exit code 1 with "is not recognized" on stderr.
        const missing = (error as NodeJS.ErrnoException | null)?.code === "ENOENT" || (invocation.shell && /not recognized|cannot find/i.test(stderr));
        if (error !== null && missing) {
          resolve({ ok: false, detail: `"${bin}" not found; install REA (npm install --global rea-agents) or pass --rea-bin <path>` });
        } else if (error !== null && stdout.length === 0) {
          resolve({ ok: false, detail: `REA failed: ${(stderr || error.message).trim().split("\n")[0]}` });
        } else {
          resolve({ ok: true, output: stdout });
        }
      },
    );
  });
}

export async function runRecon(target: string, options: ReconOptions = {}): Promise<ReconResult> {
  const startedAt = new Date().toISOString();
  const collected = await collectTarget(target, options.adapter === undefined ? {} : { adapter: options.adapter });
  // Unredacted values stay in this map and are only compared, never written.
  const raw = new Map<Finding, string>();
  const findings = runArtifactRules(collected.files, collected.adapter, (finding, value) => raw.set(finding, value));

  let rea: ReconRea = { status: "not-run" };
  let reaOutput: string | null = null;
  if (options.reaBin !== undefined) {
    const isAsar = collected.adapterName === "electron";
    if (collected.adapterName === "android" || collected.adapterName === "ios") {
      rea = { status: "skipped", detail: "REA's JavaScript analyzer takes a directory or an .asar; scan the extracted bundle directory with --rea" };
    } else {
      const result = await runRea(options.reaBin, isAsar ? collected.root : path.resolve(collected.root), options.reaTimeoutMs ?? 600_000);
      if (result.ok) {
        rea = { status: "ran" };
        reaOutput = result.output;
      } else {
        rea = { status: "failed", detail: result.detail };
      }
    }
  }

  const items: ReconItem[] = findings.map((finding) => {
    const category = categorize(finding);
    let reaRecovered: boolean | null = null;
    if (reaOutput !== null && category !== "source") {
      const first = finding.evidence[0];
      const value = raw.get(finding) ?? (category === "internal-address" && first?.kind === "file" ? first.excerpt : undefined);
      if (value !== undefined) reaRecovered = reaOutput.includes(value) || reaOutput.includes(JSON.stringify(value).slice(1, -1));
    }
    return { category, finding, reaRecovered };
  });

  return {
    version: VERSION,
    layer: "recon",
    target: collected.root,
    adapter: collected.adapterName,
    filesScanned: collected.files.length,
    startedAt,
    finishedAt: new Date().toISOString(),
    items,
    findings,
    ignored: 0,
    map: buildMap(collected.files),
    rea,
  };
}
