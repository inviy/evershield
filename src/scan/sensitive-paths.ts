/**
 * Files whose presence in a shipped artifact is the leak, whatever they
 * contain: credentials files, signing keystores, git metadata, coding-agent
 * config. Collectors keep these even when an adapter would skip them for
 * their extension or because they are binary, so the
 * `artifact/sensitive-file-shipped` rule can see them.
 */
import type { Confidence, Severity } from "../index.ts";

export interface SensitivePath {
  /** What the file is, for the finding message. */
  kind: string;
  severity: Severity;
  confidence: Confidence;
}

/** `.env.example` and friends are templates by convention. */
const ENV_TEMPLATE = /\.(?:example|sample|template|dist|defaults?)$/i;

const PATTERNS: ReadonlyArray<[RegExp, SensitivePath]> = [
  // Usually a private SSH key by name alone; the secret rule also fires if it is PEM.
  [/(?:^|\/)id_(?:rsa|dsa|ecdsa|ed25519)$/, { kind: "an SSH private key file", severity: "critical", confidence: "high" }],
  [/\.(?:jks|keystore|p12|pfx)$/i, { kind: "a signing keystore", severity: "high", confidence: "high" }],
  // Anyone who can fetch .git/ can rebuild the repository, history and all.
  [/(?:^|\/)\.git\/(?:config|HEAD)$/, { kind: "git metadata (the repository can be downloaded)", severity: "high", confidence: "high" }],
  [/(?:^|\/)(?:\.aws\/credentials|\.netrc|\.pgpass|\.htpasswd)$/, { kind: "a credentials file", severity: "high", confidence: "high" }],
  // Holds an auth token as often as not; a registry URL alone is harmless.
  [/(?:^|\/)\.npmrc$/, { kind: "an .npmrc (may hold a registry auth token)", severity: "high", confidence: "medium" }],
  // Coding-agent config names the tools, hooks and servers a developer trusts.
  [/(?:^|\/)(?:\.mcp\.json|\.claude\/settings(?:\.local)?\.json|\.cursor\/mcp\.json)$/, { kind: "coding-agent configuration", severity: "medium", confidence: "high" }],
];

const ENV_FILE = /(?:^|\/)\.env(?:\.[\w.-]+)?$/;

export function sensitivePath(relativePath: string): SensitivePath | null {
  if (ENV_FILE.test(relativePath) && !ENV_TEMPLATE.test(relativePath)) {
    // Server env files hold secrets by design, but a dotenv file may also hold only public values.
    return { kind: "an environment file", severity: "high", confidence: "medium" };
  }
  for (const [pattern, info] of PATTERNS) if (pattern.test(relativePath)) return info;
  return null;
}
