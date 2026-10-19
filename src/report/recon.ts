import type { ReconItem, ReconResult } from "../recon.ts";
import type { ArtifactScanResult } from "../scan/artifact.ts";
import { type Gate, isBlocking } from "./index.ts";
import { renderSarif } from "./sarif.ts";

const KIND: Record<ReconResult["adapter"], string> = {
  nextjs: "Next.js build",
  plain: "build directory",
  android: "Android package",
  ios: "iOS package",
  electron: "Electron archive",
};

function reaLabel(item: ReconItem, ran: boolean): string {
  if (!ran) return "";
  if (item.reaRecovered === true) return "  · REA: recovered";
  if (item.reaRecovered === false) return "  · REA: not in its output";
  return "  · REA: not checked";
}

function list(values: string[], max: number): string {
  if (values.length === 0) return "none";
  const shown = values.slice(0, max).join(", ");
  return values.length > max ? `${shown}, … (${values.length} total)` : shown;
}

export function renderReconText(result: ReconResult, gate: Gate): string {
  const ran = result.rea.status === "ran";
  const blocking = result.items.filter((item) => isBlocking(item.finding, gate));
  const lines = [
    `evershield ${result.version} · recon · ${KIND[result.adapter]} · ${result.filesScanned} files`,
    `target: ${result.target}`,
    "What reverse-engineering tools recover from this target.",
    "",
    `Worth taking: ${blocking.length} blocking, ${result.items.length} total${result.ignored > 0 ? ` (${result.ignored} ignored by config)` : ""}`,
  ];
  for (const item of result.items) {
    const first = item.finding.evidence[0];
    lines.push(`${isBlocking(item.finding, gate) ? "✖" : "•"} [${item.finding.severity}/${item.finding.confidence}] ${item.finding.message}${reaLabel(item, ran)}`);
    if (first?.kind === "file") lines.push(`    at ${first.line === undefined ? first.path : `${first.path}:${first.line}:${first.column ?? 1}`}`);
    if (item.finding.remediation !== undefined) lines.push(`    fix: ${item.finding.remediation}`);
  }
  const { map } = result;
  lines.push(
    "",
    "Map (informational: any tool reconstructs this from shipped code; keep server-side checks on it)",
    `  hosts: ${list(map.hosts.map((h) => `${h.host} (${h.count})`), 8)}`,
    `  API paths: ${list(map.apiPaths, 12)}`,
    `  source maps: ${map.sourceMaps.files} file(s), ${map.sourceMaps.originalSources} original source(s), ${map.sourceMaps.withContent} with full content`,
    `  public env names: ${list(map.publicEnvNames, 8)}`,
    "",
    result.rea.status === "ran"
      ? "REA: ran its static JavaScript analysis on the same target; each value above was looked up in its output (values are never printed)."
      : result.rea.status === "not-run"
        ? "REA: not run (add --rea to check each finding against REA's own output)."
        : `REA: ${result.rea.status}: ${result.rea.detail ?? ""}`,
    "",
    blocking.length > 0
      ? `Verdict: ${blocking.length} item(s) worth taking. Anyone running a reverse-engineering tool on this target gets them.`
      : "Verdict: nothing worth taking at this gate. Tools still reconstruct the map above, and nothing more.",
  );
  return `${lines.join("\n")}\n`;
}

export function renderReconJson(result: ReconResult, gate: Gate): string {
  const blocking = result.findings.filter((finding) => isBlocking(finding, gate)).length;
  const { findings: _findings, ...rest } = result;
  return `${JSON.stringify({ ...rest, gate, blocking }, null, 2)}\n`;
}

export function renderReconSarif(result: ReconResult, gate: Gate): string {
  const artifact: ArtifactScanResult = {
    version: result.version,
    layer: "artifact",
    target: result.target,
    adapter: result.adapter,
    filesScanned: result.filesScanned,
    ignored: result.ignored,
    startedAt: result.startedAt,
    finishedAt: result.finishedAt,
    findings: result.findings,
  };
  return renderSarif(artifact, gate);
}
