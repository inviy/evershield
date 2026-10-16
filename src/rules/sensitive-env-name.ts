/**
 * artifact/sensitive-env-name
 *
 * Environment variable names that denote server-only material. Bundlers
 * normally inline values and drop names, so a name surviving into the bundle
 * means either a leaked value next to it or a code path that reads it at
 * runtime.
 *
 * Two tiers:
 * - Name with an adjacent literal that is shaped like a secret (12+ chars,
 *   mixed character classes, not an UPPER_CASE identifier): high severity,
 *   medium confidence. The shape check exists because `PASSWORD_RECOVERY:
 *   "recovery"` is an auth event enum, not a leak.
 * - Bare name: low on both, and only for the strongest keywords. `PASSWORD`,
 *   `ACCESS_TOKEN` and `REFRESH_TOKEN` are everyday vocabulary in client auth
 *   code, so on their own they are not reported at all.
 *
 * Names carrying a framework-public prefix are never reported.
 */
import type { Finding } from "../index.ts";
import { lineColumn, redact } from "../scan/text.ts";
import { helpUri, MAX_FINDINGS_PER_FILE, type Rule, type RuleContext } from "./types.ts";

const KEYWORDS = [
  "SERVICE_ROLE", "SECRET", "PRIVATE_KEY", "DATABASE_URL", "CONNECTION_STRING",
  "SIGNING_KEY", "MASTER_KEY", "PASSWORD", "ACCESS_TOKEN", "REFRESH_TOKEN",
] as const;

/** Keywords strong enough that even a bare mention deserves a look. */
const BARE_NAME_KEYWORDS = new Set<string>([
  "SERVICE_ROLE", "SECRET", "PRIVATE_KEY", "DATABASE_URL", "CONNECTION_STRING", "SIGNING_KEY", "MASTER_KEY",
]);

const SENSITIVE_NAME = new RegExp(
  `\\b((?:[A-Z][A-Z0-9]*_)*(${KEYWORDS.join("|")})(?:_[A-Z0-9]+)*)\\b(?:["']?\\s*[:=]\\s*["']([^"'\\s]{8,})["'])?`,
  "g",
);

function isPublicName(name: string, context: RuleContext): boolean {
  return context.adapter.publicEnvPrefixes.some((prefix) => name.startsWith(prefix));
}

/** Secrets are long and mix letters with digits or case; enum values and words are not. */
export function looksLikeSecretValue(value: string): boolean {
  if (value.length < 12) return false;
  if (/^[A-Z0-9_]+$/.test(value)) return false;
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/].filter((re) => re.test(value)).length;
  return classes >= 2;
}

export const sensitiveEnvName: Rule = {
  id: "artifact/sensitive-env-name",
  defaultSeverity: "low",
  defaultConfidence: "low",

  check(file, context) {
    const findings: Finding[] = [];
    const seen = new Set<string>();

    for (const match of file.text.matchAll(SENSITIVE_NAME)) {
      const name = match[1];
      const keyword = match[2];
      const value = match[3];
      if (name === undefined || keyword === undefined || isPublicName(name, context)) continue;
      if (findings.length >= MAX_FINDINGS_PER_FILE) break;
      const { line, column } = lineColumn(file.text, match.index);

      if (value !== undefined && looksLikeSecretValue(value)) {
        const key = `${name}:${value}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          ruleId: sensitiveEnvName.id,
          layer: "artifact",
          severity: "high",
          confidence: "medium",
          message: `${name} is assigned a literal value in ${file.relativePath}`,
          evidence: [{ kind: "file", path: file.relativePath, line, column, excerpt: `${name} = ${redact(value)}` }],
          remediation: "Server-only configuration must not be bundled. Read it on the server and expose only what the client needs.",
          helpUri: helpUri(sensitiveEnvName.id),
        });
        continue;
      }

      if (!BARE_NAME_KEYWORDS.has(keyword)) continue;
      const key = `${name}:`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        ruleId: sensitiveEnvName.id,
        layer: "artifact",
        severity: "low",
        confidence: "low",
        message: `Server-only variable name ${name} appears in ${file.relativePath}`,
        evidence: [{ kind: "file", path: file.relativePath, line, column, excerpt: name }],
        remediation: "Check why client code references this name. If it is read at runtime, the value may be inlined elsewhere.",
        helpUri: helpUri(sensitiveEnvName.id),
      });
    }

    return findings;
  },
};
