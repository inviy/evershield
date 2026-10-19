import type { AuditResult } from "../audit/run.ts";
import type { Confidence, Finding, Severity } from "../index.ts";
import type { ArtifactScanResult } from "../scan/artifact.ts";
import type { SurfaceResult } from "../surface/run.ts";

export type Format = "text" | "json" | "sarif";

/** Any layer's result. Renderers switch on `layer` for the header only. */
export type Report = ArtifactScanResult | AuditResult | SurfaceResult;

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
  return `${first.url}${first.identity === undefined ? "" : ` as ${first.identity}`} → ${first.selector}`;
}

function header(result: Report): string[] {
  if (result.layer === "artifact") {
    return [
      `evershield ${result.version} · artifact scan · ${result.adapter} adapter · ${result.filesScanned} files`,
      `target: ${result.target}`,
    ];
  }
  if (result.layer === "surface") {
    return [
      `evershield ${result.version} · surface audit · ${result.pagesAudited} page(s) × ${result.identities.length} identities (${result.identities.join(" < ")}) · ${result.snapshotsEvaluated} page loads evaluated`,
      `target: ${result.target}`,
    ];
  }
  return [
    `evershield ${result.version} · response audit · ${result.endpointsAudited} endpoint(s) × ${result.identities.length} identities (${result.identities.join(" < ")}) · ${result.responsesEvaluated} responses evaluated`,
    `target: ${result.target}`,
  ];
}

export function renderText(result: Report, gate: Gate): string {
  const lines: string[] = [...header(result), ""];

  if (result.layer !== "artifact" && result.warnings.length > 0) {
    for (const warning of result.warnings) lines.push(`! ${warning}`);
    lines.push("");
  }

  const ignoredNote = result.ignored > 0 ? ` ${result.ignored} finding(s) ignored by config.` : "";

  if (result.findings.length === 0) {
    const what =
      result.layer === "artifact"
        ? "Nothing in the shipped files matched a rule."
        : result.layer === "surface"
          ? "No identity's page held content it could not see."
          : "Every identity received only what it should.";
    lines.push(`No findings. ${what}${ignoredNote}`);
    return `${lines.join("\n")}\n`;
  }

  let blocking = 0;
  for (const finding of result.findings) {
    const blocks = isBlocking(finding, gate);
    if (blocks) blocking += 1;
    const marker = blocks ? "✖" : "•";
    lines.push(`${marker} [${finding.severity}/${finding.confidence}] ${finding.message}`);
    lines.push(`    at ${location(finding)}`);
    const first = finding.evidence[0];
    const excerpt = first?.excerpt;
    if (excerpt !== undefined && first !== undefined && (first.kind !== "file" || first.line !== undefined)) {
      lines.push(`    evidence: ${excerpt}`);
    }
    if (finding.remediation !== undefined) lines.push(`    fix: ${finding.remediation}`);
    lines.push(`    rule: ${finding.ruleId}`);
    lines.push("");
  }

  const gateText = gate.failOn === "none" ? "gate disabled" : `gate: severity ≥ ${gate.failOn}, confidence ≥ ${gate.minConfidence}`;
  lines.push(`${result.findings.length} finding(s), ${blocking} blocking (${gateText}).${ignoredNote}`);
  return `${lines.join("\n")}\n`;
}

export function renderJson(result: Report, gate: Gate): string {
  const blocking = result.findings.filter((finding) => isBlocking(finding, gate)).length;
  return `${JSON.stringify({ ...result, gate, blocking }, null, 2)}\n`;
}
