/**
 * SARIF 2.1.0 output, the format GitHub code scanning and most security
 * dashboards ingest. One run per scan; one rule entry per distinct ruleId;
 * one result per finding with its first evidence as the primary location.
 *
 * Paths are relative to the scanned directory, not the repository root,
 * because build output is usually not committed. Consumers that need
 * repository paths can post-process `artifactLocation.uri`.
 */
import { type Finding, VERSION } from "../index.ts";
import { ARTIFACT_RULES } from "../rules/index.ts";
import { helpUri } from "../rules/types.ts";
import type { ArtifactScanResult } from "../scan/artifact.ts";
import { type Gate, isBlocking } from "./index.ts";

type SarifLevel = "error" | "warning" | "note";

function level(finding: Finding): SarifLevel {
  switch (finding.severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    default:
      return "note";
  }
}

function location(finding: Finding): object[] {
  const first = finding.evidence[0];
  if (first === undefined || first.kind !== "file") return [];
  const region =
    first.line === undefined ? {} : { region: { startLine: first.line, startColumn: first.column ?? 1 } };
  return [{ physicalLocation: { artifactLocation: { uri: first.path }, ...region } }];
}

export function renderSarif(result: ArtifactScanResult, gate: Gate): string {
  const ruleIds = [...new Set(result.findings.map((finding) => finding.ruleId))].sort();
  const knownRules = new Map(ARTIFACT_RULES.map((rule) => [rule.id, rule]));

  const rules = ruleIds.map((id) => {
    const rule = knownRules.get(id);
    return {
      id,
      name: id.split("/").pop() ?? id,
      shortDescription: { text: id },
      helpUri: helpUri(id),
      defaultConfiguration: {
        level: rule === undefined ? "warning" : level({ severity: rule.defaultSeverity } as Finding),
      },
      properties: rule === undefined ? {} : { defaultSeverity: rule.defaultSeverity, defaultConfidence: rule.defaultConfidence },
    };
  });

  const results = result.findings.map((finding) => ({
    ruleId: finding.ruleId,
    ruleIndex: ruleIds.indexOf(finding.ruleId),
    level: level(finding),
    message: { text: finding.remediation === undefined ? finding.message : `${finding.message}. ${finding.remediation}` },
    locations: location(finding),
    properties: {
      severity: finding.severity,
      confidence: finding.confidence,
      blocking: isBlocking(finding, gate),
    },
  }));

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "evershield",
            version: VERSION,
            informationUri: "https://github.com/inviy/evershield",
            rules,
          },
        },
        invocations: [
          {
            executionSuccessful: true,
            startTimeUtc: result.startedAt,
            endTimeUtc: result.finishedAt,
            properties: { adapter: result.adapter, filesScanned: result.filesScanned, ignored: result.ignored, gate },
          },
        ],
        results,
      },
    ],
  };

  return `${JSON.stringify(sarif, null, 2)}\n`;
}
