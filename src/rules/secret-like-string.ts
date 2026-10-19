/**
 * artifact/secret-like-string
 *
 * Credentials shipped to the browser. Two tiers:
 *
 * - Provider formats (AWS, GitHub, Stripe, Slack, OpenAI, Anthropic, private
 *   key blocks, Supabase service-role JWTs) are structurally unambiguous, so
 *   confidence is high. Severity is critical: they grant server-side access.
 * - Name-based matches (`apiKey: "…"`) depend on the value's entropy and on
 *   the name not being a framework-public variable, so confidence is low.
 *   Severity stays high because when they are real they are just as bad.
 *
 * Public-by-design keys (Stripe `pk_`, Supabase anon JWTs, Google browser
 * keys) are deliberately not findings, or are reported at low severity with
 * a note, because flagging them trains people to ignore the report.
 */
import type { Confidence, Finding, Severity } from "../index.ts";
import { decodeJwtPayload, lineColumn, looksLikePlaceholder, redact, shannonEntropy } from "../scan/text.ts";
import { helpUri, MAX_FINDINGS_PER_FILE, type Rule, type RuleContext } from "./types.ts";

interface ProviderPattern {
  name: string;
  pattern: RegExp;
  severity: Severity;
  confidence: Confidence;
  remediation: string;
}

const ROTATE = "Rotate the credential now; treat it as compromised. Move its use behind a server endpoint.";

const PROVIDERS: ProviderPattern[] = [
  { name: "AWS access key ID", pattern: /\bAKIA[0-9A-Z]{16}\b/g, severity: "critical", confidence: "high", remediation: ROTATE },
  { name: "GitHub token", pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{80,}\b/g, severity: "critical", confidence: "high", remediation: ROTATE },
  { name: "Stripe secret key", pattern: /\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b/g, severity: "critical", confidence: "high", remediation: ROTATE },
  { name: "Stripe test secret key", pattern: /\b(?:sk|rk)_test_[0-9A-Za-z]{24,}\b/g, severity: "medium", confidence: "high", remediation: "Test keys should not ship either; remove and keep them server-side." },
  { name: "Slack token", pattern: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g, severity: "critical", confidence: "high", remediation: ROTATE },
  { name: "Anthropic API key", pattern: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/g, severity: "critical", confidence: "high", remediation: ROTATE },
  { name: "OpenAI API key", pattern: /\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}\b/g, severity: "critical", confidence: "high", remediation: ROTATE },
  // The header alone is how PEM-parsing code (jose, auth0-spa-js) checks its input; a real key has a base64 body.
  { name: "Private key block", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----(?:\\[rn]|\s)*[A-Za-z0-9+/=]{64,}/g, severity: "critical", confidence: "high", remediation: "Remove the key from the build and rotate it." },
  {
    name: "Google API key",
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    severity: "medium",
    confidence: "medium",
    remediation: "Browser keys are expected to ship; confirm this one is restricted to your origins and to the APIs it needs.",
  },
];

const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;

const NAMED_VALUE =
  /\b((?:[A-Za-z_][A-Za-z0-9_]*?)?(?:secret|token|api[_-]?key|apikey|password|passwd|private[_-]?key|auth[_-]?key)[A-Za-z0-9_]*)["']?\s*[:=]\s*["']([A-Za-z0-9_\-./+=]{16,})["']/gi;

const MIN_NAMED_ENTROPY = 3.5;

function isPublicName(name: string, context: RuleContext): boolean {
  const upper = name.toUpperCase();
  return context.adapter.publicEnvPrefixes.some((prefix) => upper.startsWith(prefix));
}

/**
 * Entropy alone passes CSS custom properties (`--brand-color-hover`) and
 * dotted paths (`spacing.large.default`): long, varied, and not secrets.
 * Real credentials mix letters with digits or case and do not look like
 * identifiers or paths.
 */
function looksLikeCredentialValue(value: string): boolean {
  if (value.startsWith("--") || value.startsWith("./") || value.startsWith("/")) return false;
  // Dotted or dashed identifiers made of words ("auth0.lock.getTokenSilently", "spacing.large.default")
  // are keys and paths. Each segment is letters with at most trailing digits; tokens mix digits inside.
  if (/^[A-Za-z]+\d*(?:[.\-_/:][A-Za-z]+\d*)+$/.test(value)) return false;
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/].filter((re) => re.test(value)).length;
  return classes >= 2 && shannonEntropy(value) >= MIN_NAMED_ENTROPY;
}

export const secretLikeString: Rule = {
  id: "artifact/secret-like-string",
  defaultSeverity: "high",
  defaultConfidence: "low",

  check(file, context) {
    const findings: Finding[] = [];
    const seen = new Set<string>();
    const push = (finding: Finding, key: string, raw: string) => {
      if (seen.has(key) || findings.length >= MAX_FINDINGS_PER_FILE) return;
      seen.add(key);
      findings.push(finding);
      context.onMatch?.(finding, raw);
    };

    for (const provider of PROVIDERS) {
      for (const match of file.text.matchAll(provider.pattern)) {
        const value = match[0];
        const { line, column } = lineColumn(file.text, match.index);
        push(
          {
            ruleId: secretLikeString.id,
            layer: "artifact",
            severity: provider.severity,
            confidence: provider.confidence,
            message: `${provider.name} shipped in ${file.relativePath}`,
            evidence: [{ kind: "file", path: file.relativePath, line, column, excerpt: redact(value) }],
            remediation: provider.remediation,
            helpUri: helpUri(secretLikeString.id),
          },
          `${provider.name}:${value}`,
          value,
        );
      }
    }

    for (const match of file.text.matchAll(JWT)) {
      const token = match[0];
      const payload = decodeJwtPayload(token);
      if (payload === null) continue;
      const role = typeof payload.role === "string" ? payload.role : null;
      const { line, column } = lineColumn(file.text, match.index);
      if (role === "service_role") {
        push(
          {
            ruleId: secretLikeString.id,
            layer: "artifact",
            severity: "critical",
            confidence: "high",
            message: `Supabase service_role JWT shipped in ${file.relativePath}; it bypasses row-level security`,
            evidence: [{ kind: "file", path: file.relativePath, line, column, excerpt: redact(token) }],
            remediation: "Rotate the service role key in Supabase and use the anon key in the browser.",
            helpUri: helpUri(secretLikeString.id),
          },
          `jwt:${token}`,
          token,
        );
      } else if (role === null) {
        // Not a Supabase anon/authenticated token; unknown JWTs in a bundle
        // deserve a look but are often harmless fixtures.
        push(
          {
            ruleId: secretLikeString.id,
            layer: "artifact",
            severity: "low",
            confidence: "medium",
            message: `JWT embedded in ${file.relativePath}`,
            evidence: [{ kind: "file", path: file.relativePath, line, column, excerpt: redact(token) }],
            remediation: "Confirm the token is not a live credential. Tokens belong in responses, not bundles.",
            helpUri: helpUri(secretLikeString.id),
          },
          `jwt:${token}`,
          token,
        );
      }
    }

    for (const match of file.text.matchAll(NAMED_VALUE)) {
      const name = match[1];
      const value = match[2];
      if (name === undefined || value === undefined) continue;
      if (isPublicName(name, context) || looksLikePlaceholder(value)) continue;
      if (!looksLikeCredentialValue(value)) continue;
      const { line, column } = lineColumn(file.text, match.index);
      push(
        {
          ruleId: secretLikeString.id,
          layer: "artifact",
          severity: "high",
          confidence: "low",
          message: `"${name}" is assigned a high-entropy value in ${file.relativePath}`,
          evidence: [{ kind: "file", path: file.relativePath, line, column, excerpt: `${name} = ${redact(value)}` }],
          remediation: "If this is a real credential, rotate it and move the call server-side. If it is public by design, rename it with your framework's public prefix.",
          helpUri: helpUri(secretLikeString.id),
        },
        `named:${name}:${value}`,
        value,
      );
    }

    return findings;
  },
};
