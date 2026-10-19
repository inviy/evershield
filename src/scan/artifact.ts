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

/** Layer 1: scan a directory of built files, or an app package, for what should not ship. */
export async function scanArtifact(
  target: string,
  options: ArtifactScanOptions = {},
): Promise<ArtifactScanResult> {
  const startedAt = new Date().toISOString();
  const root = path.resolve(target);

  const info = await stat(root).catch(() => null);
  if (info === null || (!info.isDirectory() && !info.isFile())) {
    throw new Error(`not a directory or app package: ${target}`);
  }

  let adapter: Adapter;
  let adapterName: ArtifactScanResult["adapter"];
  let files: ScannedFile[];
  if (info.isFile()) {
    // An app package ships everything inside it; there is nothing for a web adapter to filter.
    const archive = await collectArchive(root);
    adapter = ADAPTERS.plain;
    adapterName = archive.kind;
    files = archive.files;
  } else {
    adapter = options.adapter ? ADAPTERS[options.adapter] : await detectAdapter(root);
    adapterName = adapter.name;
    files = await collectFiles(root, adapter);
  }
  const context: RuleContext = {
    adapter,
    shippedPaths: new Set(files.map((file) => file.relativePath)),
  };

  const findings: Finding[] = [];
  for (const file of files) {
    for (const rule of ARTIFACT_RULES) {
      findings.push(...rule.check(file, context));
    }
  }

  return {
    version: VERSION,
    layer: "artifact",
    target: root,
    adapter: adapterName,
    filesScanned: files.length,
    ignored: 0,
    startedAt,
    finishedAt: new Date().toISOString(),
    findings: sortFindings(findings),
  };
}
