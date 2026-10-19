/**
 * artifact/internal-endpoint
 *
 * Addresses that should not be in a public bundle. Private IPs in URLs or
 * with a port, and
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

const OCTET = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
const PRIVATE_IP = `(?:10\\.${OCTET}\\.${OCTET}\\.${OCTET}|192\\.168\\.${OCTET}\\.${OCTET}|172\\.(?:1[6-9]|2\\d|3[01])\\.${OCTET}\\.${OCTET})`;

const PATTERNS: EndpointPattern[] = [
  {
    // In a URL or with a port, a private IP is an address the code talks to.
    name: "Private IP address",
    pattern: new RegExp(`(?<=://|@)${PRIVATE_IP}(?![.\\d])|(?<![\\w.])${PRIVATE_IP}(?=:\\d{2,5}\\b)`, "g"),
    severity: "medium",
    confidence: "medium",
    remediation: "Replace with a public hostname resolved server-side, or remove the reference.",
  },
  {
    // A bare one is as often an example, a doc comment or a CIDR in a language grammar.
    name: "Private IP literal",
    pattern: new RegExp(`(?<![\\w.:@/])${PRIVATE_IP}(?![.\\d:])`, "g"),
    severity: "low",
    confidence: "low",
    remediation: "If the client connects to this address, route it through a public endpoint instead.",
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
