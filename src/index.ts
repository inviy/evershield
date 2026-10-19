/**
 * evershield public API.
 *
 * The scanner itself lands in later releases; this module fixes the shapes
 * every layer reports in, so CLI, GitHub Action and MCP surfaces can share
 * one finding model from day one. See docs/design.md for the rationale.
 */

export const VERSION = "0.3.2";

/** How sure evershield is that a finding is real. Drives exit codes and CI gating. */
export type Confidence = "high" | "medium" | "low";

/** How bad it is if the finding is real. */
export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** Which analysis layer produced the finding. */
export type Layer = "artifact" | "response" | "surface";

/** Where in the shipped output the evidence was observed. */
export type Evidence =
  | { kind: "file"; path: string; line?: number; column?: number; excerpt?: string }
  | { kind: "response"; endpoint: string; identity: string; jsonPath: string; excerpt?: string }
  | { kind: "dom"; url: string; selector: string; identity?: string; excerpt?: string };

export interface Finding {
  /** Stable rule identifier, e.g. "artifact/secret-like-string". */
  ruleId: string;
  layer: Layer;
  severity: Severity;
  confidence: Confidence;
  /** One sentence a developer can act on without opening docs. */
  message: string;
  evidence: Evidence[];
  /** Concrete fix, phrased for the person who will apply it. */
  remediation?: string;
  /** Rule documentation URL. */
  helpUri?: string;
}

export interface ScanSummary {
  version: string;
  startedAt: string;
  finishedAt: string;
  findings: Finding[];
}
