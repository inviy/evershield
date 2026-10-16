/**
 * Response rules. Each inspects one endpoint observed as every identity.
 *
 * - response/expected-absent-field-present: the operator said identity X
 *   must not receive path P, and it did. The operator's own contract makes
 *   this high severity and high confidence. This is the rule that catches
 *   "Pro-only metric present in every free user's JSON".
 * - response/higher-tier-field-in-lower-tier: a field whose name marks it
 *   as privileged (`premium`, `pro_only`, `admin`, `internal`, `cost`, …)
 *   is present for a lower tier. Name-based, so medium confidence.
 * - response/sensitive-field: a password, secret, token or key field with a
 *   non-boolean value in any response. Over-fetching; high on both.
 * - response/identical-across-tiers: every identity got the same body. On
 *   an endpoint declared `tiered`, the gate is missing (high/medium);
 *   otherwise a low/low prompt to declare it if it should differ.
 */
import type { Confidence, Finding, Severity } from "../index.ts";
import { redact } from "../scan/text.ts";
import { deepEqual, isUnder, leafName, presentPaths } from "./json-paths.ts";
import type { EndpointObservation, ResponseObservation } from "./types.ts";

export interface ResponseRuleMeta {
  id: string;
  defaultSeverity: Severity;
  defaultConfidence: Confidence;
}

export interface ResponseRule extends ResponseRuleMeta {
  check(observation: EndpointObservation): Finding[];
}

const RULES_DOC = "https://github.com/inviy/evershield/blob/main/docs/rules.md";
const help = (id: string) => `${RULES_DOC}#${id.replace("/", "")}`;

const PRIVILEGED_NAME = /^(?:is_?)?(?:premium|pro|pro_?only|paid|plus|enterprise|admin|internal|private|debug|cost|margin|staff|owner_?only)(?:_|$)|_(?:premium|pro|paid|internal|admin|cost)$/i;
const SENSITIVE_NAME =
  /(?:^|_)(?:password(?:_?hash)?|hashed_?password|passwd|secret|api_?key|access_?token|refresh_?token|private_?key|ssn|card_?number|cvv)$|^(?:apiKey|accessToken|refreshToken|privateKey|cardNumber|passwordHash)$/i;

/** Array element paths ("items[]") share their leaf with the array itself; checking both would double-report. */
function isElementPath(path: string): boolean {
  return path.endsWith("[]");
}

function excerptOf(value: unknown): string {
  if (typeof value === "string") return redact(value);
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return `array(${value.length})`;
  if (typeof value === "object" && value !== null) return `object{${Object.keys(value).slice(0, 5).join(",")}}`;
  return String(value);
}

function okJson(response: ResponseObservation | undefined): response is ResponseObservation & { isJson: true } {
  return response !== undefined && response.error === undefined && response.status >= 200 && response.status < 300 && response.isJson;
}

export const expectedAbsentFieldPresent: ResponseRule = {
  id: "response/expected-absent-field-present",
  defaultSeverity: "high",
  defaultConfidence: "high",
  check(observation) {
    const findings: Finding[] = [];
    for (const [identity, expectation] of Object.entries(observation.endpoint.expect ?? {})) {
      const response = observation.responses.get(identity);
      if (!okJson(response)) continue;
      const present = presentPaths(response.json);
      for (const prefix of expectation.absent ?? []) {
        const hit = [...present.entries()].find(([path]) => isUnder(path, prefix));
        if (hit === undefined) continue;
        const [path, value] = hit;
        findings.push({
          ruleId: expectedAbsentFieldPresent.id,
          layer: "response",
          severity: "high",
          confidence: "high",
          message: `${observation.label} returns "${prefix}" to ${identity}, which the config says must not receive it`,
          evidence: [{ kind: "response", endpoint: observation.label, identity, jsonPath: path, excerpt: excerptOf(value) }],
          remediation: "Withhold the field on the server for this tier (omit it or send null). Hiding it in the UI is not a boundary.",
          helpUri: help(expectedAbsentFieldPresent.id),
        });
      }
    }
    return findings;
  },
};

export const higherTierFieldInLowerTier: ResponseRule = {
  id: "response/higher-tier-field-in-lower-tier",
  defaultSeverity: "medium",
  defaultConfidence: "medium",
  check(observation) {
    const findings: Finding[] = [];
    const top = observation.tiers.length - 1;
    observation.tiers.forEach((identity, index) => {
      if (index >= top) return;
      const response = observation.responses.get(identity);
      if (!okJson(response)) return;
      for (const [path, value] of presentPaths(response.json)) {
        if (isElementPath(path)) continue;
        const leaf = leafName(path);
        if (!PRIVILEGED_NAME.test(leaf) || typeof value === "boolean") continue;
        findings.push({
          ruleId: higherTierFieldInLowerTier.id,
          layer: "response",
          severity: "medium",
          confidence: "medium",
          message: `${observation.label} returns "${path}" to ${identity}; the name suggests a higher tier's data`,
          evidence: [{ kind: "response", endpoint: observation.label, identity, jsonPath: path, excerpt: excerptOf(value) }],
          remediation: "If this belongs to a higher tier, withhold it server-side and add it to that identity's `expect.absent` so the audit enforces it.",
          helpUri: help(higherTierFieldInLowerTier.id),
        });
      }
    });
    return findings;
  },
};

export const sensitiveField: ResponseRule = {
  id: "response/sensitive-field",
  defaultSeverity: "high",
  defaultConfidence: "high",
  check(observation) {
    const findings: Finding[] = [];
    const seen = new Set<string>();
    for (const identity of observation.tiers) {
      const response = observation.responses.get(identity);
      if (!okJson(response)) continue;
      for (const [path, value] of presentPaths(response.json)) {
        if (isElementPath(path) || !SENSITIVE_NAME.test(leafName(path)) || typeof value === "boolean" || seen.has(path)) continue;
        seen.add(path);
        findings.push({
          ruleId: sensitiveField.id,
          layer: "response",
          severity: "high",
          confidence: "high",
          message: `${observation.label} returns a sensitive field "${path}" (first seen for ${identity})`,
          evidence: [{ kind: "response", endpoint: observation.label, identity, jsonPath: path, excerpt: excerptOf(value) }],
          remediation: "Never serialize credentials or hashes. Select the fields the client needs instead of returning the whole record.",
          helpUri: help(sensitiveField.id),
        });
      }
    }
    return findings;
  },
};

export const identicalAcrossTiers: ResponseRule = {
  id: "response/identical-across-tiers",
  defaultSeverity: "low",
  defaultConfidence: "low",
  check(observation) {
    const bodies = observation.tiers
      .map((identity) => observation.responses.get(identity))
      .filter((response): response is ResponseObservation & { isJson: true } => okJson(response));
    if (bodies.length < 2) return [];
    const first = bodies[0]!;
    if (!bodies.every((response) => deepEqual(response.json, first.json))) return [];
    const identities = bodies.map((response) => response.identity).join(", ");
    const tiered = observation.endpoint.tiered === true;
    return [
      {
        ruleId: identicalAcrossTiers.id,
        layer: "response",
        severity: tiered ? "high" : "low",
        confidence: tiered ? "medium" : "low",
        message: tiered
          ? `${observation.label} is declared tiered but returns the same body to ${identities}`
          : `${observation.label} returns the same body to ${identities}`,
        evidence: [{ kind: "response", endpoint: observation.label, identity: first.identity, jsonPath: "$" }],
        remediation: tiered
          ? "The tier check is not applied on this endpoint. Verify the server reads the caller's entitlement, not a client-supplied plan."
          : "If this endpoint should differ by plan, set `tiered: true` so the audit treats sameness as a failure.",
        helpUri: help(identicalAcrossTiers.id),
      },
    ];
  },
};

export const RESPONSE_RULES: readonly ResponseRule[] = [
  expectedAbsentFieldPresent,
  sensitiveField,
  higherTierFieldInLowerTier,
  identicalAcrossTiers,
];
