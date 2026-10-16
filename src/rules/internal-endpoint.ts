/**
 * artifact/internal-endpoint
 *
 * Addresses that should not be in a public bundle. Private IP ranges and
 * `.internal`/`.local`/`.corp` names are rarely legitimate in client code,
 * so confidence is medium–high; severity is medium because they aid an
 * attacker rather than grant access. `localhost` and `staging`/`admin`
 * hostnames are common development fallbacks, so they are reported at low
 * severity and low confidence: worth a look, not worth failing a build.
 */
import type { Confidence, Finding, Severity } from "../index.ts";
import { lineColumn } from "../scan/text.ts";
import { helpUri, MAX_FINDINGS_PER_FILE, type Rule } from "./types.ts";

interface EndpointPattern {
  name: string;
  pattern: RegExp;
  severity: Severity;
  confidence: Confidence;
  remediation: string;
}

const PATTERNS: EndpointPattern[] = [
  {
    name: "Private IP address",
    pattern: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/g,
    severity: "medium",
    confidence: "medium",
    remediation: "Replace with a public hostname resolved server-side, or remove the reference.",
  },
  {
    name: "Internal hostname",
    pattern: /\bhttps?:\/\/[a-z0-9.-]+\.(?:internal|local|corp|lan|intranet)(?::\d+)?\b/gi,
    severity: "medium",
    confidence: "high",
    remediation: "Internal names map your infrastructure for an attacker. Proxy the call through a public endpoint.",
  },
  {
    name: "localhost URL",
    pattern: /\bhttps?:\/\/(?:localhost|127\.0\.0\.1)(?::\d+)?\b/gi,
    severity: "low",
    confidence: "low",
    remediation: "Usually a development fallback that leaked into production config. Confirm it is unreachable in production.",
  },
  {
    name: "Staging or admin hostname",
    pattern: /\bhttps?:\/\/(?:[a-z0-9-]+\.)*(?:staging|stage|dev|admin|preprod|uat)\.[a-z0-9.-]+\b/gi,
    severity: "low",
    confidence: "low",
    remediation: "Confirm the environment is meant to be reachable from the public bundle.",
  },
];

export const internalEndpoint: Rule = {
  id: "artifact/internal-endpoint",
  defaultSeverity: "medium",
  defaultConfidence: "medium",

  check(file) {
    const findings: Finding[] = [];
    const seen = new Set<string>();

    for (const entry of PATTERNS) {
      for (const match of file.text.matchAll(entry.pattern)) {
        const value = match[0];
        if (seen.has(value) || findings.length >= MAX_FINDINGS_PER_FILE) continue;
        seen.add(value);
        const { line, column } = lineColumn(file.text, match.index);
        findings.push({
          ruleId: internalEndpoint.id,
          layer: "artifact",
          severity: entry.severity,
          confidence: entry.confidence,
          message: `${entry.name} in ${file.relativePath}: ${value}`,
          evidence: [{ kind: "file", path: file.relativePath, line, column, excerpt: value }],
          remediation: entry.remediation,
          helpUri: helpUri(internalEndpoint.id),
        });
      }
    }

    return findings;
  },
};
