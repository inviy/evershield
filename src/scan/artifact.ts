import { stat } from "node:fs/promises";
import path from "node:path";

import { type Finding, type ScanSummary, VERSION } from "../index.ts";
import { ARTIFACT_RULES } from "../rules/index.ts";
import type { RuleContext } from "../rules/types.ts";
import { type Adapter, ADAPTERS, detectAdapter } from "./adapters.ts";
import { type ArchiveKind, collectArchive } from "./archive.ts";
import { collectFiles, type ScannedFile } from "./files.ts";

export interface ArtifactScanOptions {
  /** Force an adapter instead of detecting one from the directory. */
  adapter?: Adapter["name"];
  /** See RuleContext.onMatch. */
  onMatch?: RuleContext["onMatch"];
}

export interface ArtifactScanResult extends ScanSummary {
  layer: "artifact";
  target: string;
  /** Directory adapter, or the kind of app package scanned. */
  adapter: Adapter["name"] | ArchiveKind;
  filesScanned: number;
  /** Findings removed by config ignore rules; they are not in `findings`. */
  ignored: number;
}

const SEVERITY_RANK: Record<Finding["severity"], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const CONFIDENCE_RANK: Record<Finding["confidence"], number> = {
  high: 0,
  medium: 1,
  low: 2,
};

/** Worst first, then surest first, then by location so output is stable. */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const bySeverity = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    if (bySeverity !== 0) return bySeverity;
    const byConfidence = CONFIDENCE_RANK[a.confidence] - CONFIDENCE_RANK[b.confidence];
    if (byConfidence !== 0) return byConfidence;
    const aPath = a.evidence[0]?.kind === "file" ? a.evidence[0].path : "";
    const bPath = b.evidence[0]?.kind === "file" ? b.evidence[0].path : "";
    if (aPath !== bPath) return aPath < bPath ? -1 : 1;
    const aLine = a.evidence[0]?.kind === "file" ? (a.evidence[0].line ?? 0) : 0;
    const bLine = b.evidence[0]?.kind === "file" ? (b.evidence[0].line ?? 0) : 0;
    return aLine - bLine;
  });
}

export interface CollectedTarget {
  root: string;
  adapter: Adapter;
  /** Directory adapter, or the kind of app package. */
  adapterName: ArtifactScanResult["adapter"];
  files: ScannedFile[];
}

/** Read what a target ships: a build directory through its adapter, or an app package in memory. */
export async function collectTarget(target: string, options: Pick<ArtifactScanOptions, "adapter"> = {}): Promise<CollectedTarget> {
  const root = path.resolve(target);
  const info = await stat(root).catch(() => null);
  if (info === null || (!info.isDirectory() && !info.isFile())) {
    throw new Error(`not a directory or app package: ${target}`);
  }
  if (info.isFile()) {
    // An app package ships everything inside it; there is nothing for a web adapter to filter.
    const archive = await collectArchive(root);
    return { root, adapter: ADAPTERS.plain, adapterName: archive.kind, files: archive.files };
  }
  const adapter = options.adapter ? ADAPTERS[options.adapter] : await detectAdapter(root);
  return { root, adapter, adapterName: adapter.name, files: await collectFiles(root, adapter) };
}

/** package.json `license` of an npm tarball, or null (missing, or the legacy object form without a type). */
function packageLicense(files: ScannedFile[]): string | null {
  const manifest = files.find((file) => file.relativePath === "package.json");
  if (manifest === undefined) return null;
  try {
    const license = (JSON.parse(manifest.text) as { license?: unknown }).license;
    if (typeof license === "string") return license;
    if (typeof license === "object" && license !== null && typeof (license as { type?: unknown }).type === "string") return (license as { type: string }).type;
  } catch {
    // An unreadable manifest is treated as unlicensed.
  }
  return null;
}

const MAX_GROUPED_EVIDENCE = 10;

/**
 * A package can ship thousands of maps (next ships one per module). One
 * finding per severity and confidence, listing the first files, says the
 * same thing without burying the rest of the report.
 */
function groupSourceMaps(findings: Finding[]): Finding[] {
  const groups = new Map<string, Finding[]>();
  const rest: Finding[] = [];
  for (const finding of findings) {
    if (finding.ruleId !== "artifact/source-map-published") rest.push(finding);
    else {
      const key = `${finding.severity}/${finding.confidence}`;
      groups.set(key, [...(groups.get(key) ?? []), finding]);
    }
  }
  for (const group of groups.values()) {
    if (group.length === 1) {
      rest.push(group[0]!);
      continue;
    }
    const embedded = group.filter((finding) => finding.message.includes("sourcesContent")).length;
    rest.push({
      ...group[0]!,
      message: `${group.length} source maps ship in this package${embedded > 0 ? ` (${embedded} embed the original source)` : ""}`,
      evidence: group.slice(0, MAX_GROUPED_EVIDENCE).flatMap((finding) => finding.evidence),
    });
  }
  return rest;
}

export function runArtifactRules(
  files: ScannedFile[],
  adapter: Adapter,
  onMatch?: RuleContext["onMatch"],
  kind?: ArtifactScanResult["adapter"],
): Finding[] {
  const context: RuleContext = {
    adapter,
    shippedPaths: new Set(files.map((file) => file.relativePath)),
    ...(onMatch === undefined ? {} : { onMatch }),
    ...(kind === "npm" ? { npmPackage: { license: packageLicense(files) } } : {}),
  };
  const findings: Finding[] = [];
  for (const file of files) {
    for (const rule of ARTIFACT_RULES) findings.push(...rule.check(file, context));
  }
  return sortFindings(kind === "npm" ? groupSourceMaps(findings) : findings);
}

/** Layer 1: scan a directory of built files, or an app package, for what should not ship. */
export async function scanArtifact(
  target: string,
  options: ArtifactScanOptions = {},
): Promise<ArtifactScanResult> {
  const startedAt = new Date().toISOString();
  const collected = await collectTarget(target, options);
  return {
    version: VERSION,
    layer: "artifact",
    target: collected.root,
    adapter: collected.adapterName,
    filesScanned: collected.files.length,
    ignored: 0,
    startedAt,
    finishedAt: new Date().toISOString(),
    findings: runArtifactRules(collected.files, collected.adapter, options.onMatch, collected.adapterName),
  };
}
