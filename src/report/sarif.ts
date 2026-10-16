/**
 * SARIF 2.1.0 output, the format GitHub code scanning and most security
 * dashboards ingest. One run per scan; one rule entry per distinct ruleId;
 * one result per finding with its first evidence as the primary location.
 *
 * File paths are relative to the scanned directory, not the repository
 * root, because build output is usually not committed. Response evidence
 * has no file, so it is reported as a logical location (endpoint, identity
 * and JSON path).
 */
import { RESPONSE_RULES } from "../audit/rules.ts";
import { type Confidence, type Finding, type Severity, VERSION } from "../index.ts";
import { ARTIFACT_RULES } from "../rules/index.ts";
import { helpUri } from "../rules/types.ts";
import { type Gate, isBlocking, type Report } from "./index.ts";

type SarifLevel = "error" | "warning" | "note";

function levelFor(severity: Severity): SarifLevel {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    default:
      return "note";
  }
}

function locations(finding: Finding): object[] {
  const first = finding.evidence[0];
  if (first === undefined) return [];
  if (first.kind === "file") {
    const region = first.line === undefined ? {} : { region: { startLine: first.line, startColumn: first.column ?? 1 } };
    return [{ physicalLocation: { artifactLocation: { uri: first.path }, ...region } }];
  }
  if (first.kind === "response") {
    return [
      {
        logicalLocations: [
          { name: first.jsonPath, fullyQualifiedName: `${first.endpoint} as ${first.identity} → ${first.jsonPath}`, kind: "member" },
        ],
      },
    ];
  }
  return [{ logicalLocations: [{ name: first.selector, fullyQualifiedName: `${first.url} ${first.selector}`, kind: "element" }] }];
}

interface RuleMeta {
  defaultSeverity: Severity;
  defaultConfidence: Confidence;
}

const KNOWN_RULES = new Map<string, RuleMeta>([
  ...ARTIFACT_RULES.map((rule): [string, RuleMeta] => [rule.id, rule]),
  ...RESPONSE_RULES.map((rule): [string, RuleMeta] => [rule.id, rule]),
]);

function invocationProperties(result: Report, gate: Gate): Record<string, unknown> {
  if (result.layer === "artifact") {
    return { layer: result.layer, adapter: result.adapter, filesScanned: result.filesScanned, ignored: result.ignored, gate };
  }
  return {
    layer: result.layer,
    identities: result.identities,
    endpointsAudited: result.endpointsAudited,
    responsesEvaluated: result.responsesEvaluated,
    warnings: result.warnings,
    ignored: result.ignored,
    gate,
  };
}

export function renderSarif(result: Report, gate: Gate): string {
  const ruleIds = [...new Set(result.findings.map((finding) => finding.ruleId))].sort();

  const rules = ruleIds.map((id) => {
    const meta = KNOWN_RULES.get(id);
    return {
      id,
      name: id.split("/").pop() ?? id,
      shortDescription: { text: id },
      helpUri: helpUri(id),
      defaultConfiguration: { level: meta === undefined ? "warning" : levelFor(meta.defaultSeverity) },
      properties: meta === undefined ? {} : { defaultSeverity: meta.defaultSeverity, defaultConfidence: meta.defaultConfidence },
    };
  });

  const results = result.findings.map((finding) => ({
    ruleId: finding.ruleId,
    ruleIndex: ruleIds.indexOf(finding.ruleId),
    level: levelFor(finding.severity),
    message: { text: finding.remediation === undefined ? finding.message : `${finding.message}. ${finding.remediation}` },
    locations: locations(finding),
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
            properties: invocationProperties(result, gate),
          },
        ],
        results,
      },
    ],
  };

  return `${JSON.stringify(sarif, null, 2)}\n`;
}
