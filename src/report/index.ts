import type { Confidence, Finding, Severity } from "../index.ts";
import type { ArtifactScanResult } from "../scan/artifact.ts";

export type Format = "text" | "json";

export const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];
export const CONFIDENCES: readonly Confidence[] = ["high", "medium", "low"];

export interface Gate {
  /** Findings at this severity or worse can fail the build. "none" never fails. */
  failOn: Severity | "none";
  /** Findings below this confidence never fail the build, whatever their severity. */
  minConfidence: Confidence;
}

export const DEFAULT_GATE: Gate = { failOn: "high", minConfidence: "medium" };

export function isBlocking(finding: Finding, gate: Gate): boolean {
  if (gate.failOn === "none") return false;
  const severeEnough = SEVERITIES.indexOf(finding.severity) <= SEVERITIES.indexOf(gate.failOn);
  const sureEnough = CONFIDENCES.indexOf(finding.confidence) <= CONFIDENCES.indexOf(gate.minConfidence);
  return severeEnough && sureEnough;
}

function location(finding: Finding): string {
  const first = finding.evidence[0];
  if (first === undefined) return "";
  if (first.kind === "file") {
    return first.line === undefined ? first.path : `${first.path}:${first.line}:${first.column ?? 1}`;
  }
  if (first.kind === "response") return `${first.endpoint} as ${first.identity} → ${first.jsonPath}`;
  return `${first.url} ${first.selector}`;
}

export function renderText(result: ArtifactScanResult, gate: Gate): string {
  const lines: string[] = [];
  lines.push(`evershield ${result.version} · artifact scan · ${result.adapter} adapter · ${result.filesScanned} files`);
  lines.push(`target: ${result.target}`);
  lines.push("");

  if (result.findings.length === 0) {
    lines.push("No findings. Nothing in the shipped files matched a rule.");
    return `${lines.join("\n")}\n`;
  }

  let blocking = 0;
  for (const finding of result.findings) {
    const blocks = isBlocking(finding, gate);
    if (blocks) blocking += 1;
    const marker = blocks ? "✖" : "•";
    lines.push(`${marker} [${finding.severity}/${finding.confidence}] ${finding.message}`);
    lines.push(`    at ${location(finding)}`);
    const excerpt = finding.evidence[0]?.excerpt;
    if (excerpt !== undefined && finding.evidence[0]?.kind === "file" && finding.evidence[0].line !== undefined) {
      lines.push(`    evidence: ${excerpt}`);
    }
    if (finding.remediation !== undefined) lines.push(`    fix: ${finding.remediation}`);
    lines.push(`    rule: ${finding.ruleId}`);
    lines.push("");
  }

  const gateText = gate.failOn === "none" ? "gate disabled" : `gate: severity ≥ ${gate.failOn}, confidence ≥ ${gate.minConfidence}`;
  lines.push(`${result.findings.length} finding(s), ${blocking} blocking (${gateText}).`);
  return `${lines.join("\n")}\n`;
}

export function renderJson(result: ArtifactScanResult, gate: Gate): string {
  const blocking = result.findings.filter((finding) => isBlocking(finding, gate)).length;
  return `${JSON.stringify({ ...result, gate, blocking }, null, 2)}\n`;
}
