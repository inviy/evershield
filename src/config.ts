/**
 * evershield.config.json
 *
 * {
 *   "gate": { "failOn": "high", "minConfidence": "medium" },
 *   "ignore": [
 *     { "ruleId": "artifact/internal-endpoint", "match": "localhost:9999",
 *       "reason": "supabase-js bundles this default; unreachable in production" }
 *   ]
 * }
 *
 * Every ignore needs a reason. An allowlist without reasons rots into a
 * list nobody dares to delete; with reasons it is documentation.
 */
import { readFile } from "node:fs/promises";
import path from "node:path";

import type { AuditConfig, EndpointConfig, HttpMethod, IdentityConfig } from "./audit/types.ts";
import type { Confidence, Finding, Severity } from "./index.ts";
import { CONFIDENCES, type Gate, SEVERITIES } from "./report/index.ts";

export interface IgnoreRule {
  /** Rule id to ignore, or "*" for any rule. */
  ruleId: string;
  /** Glob over the evidence path, relative to the scan target. */
  path?: string;
  /** Substring that must appear in the finding's message or excerpt. */
  match?: string;
  /** Why this is safe. Required. */
  reason: string;
}

export interface Config {
  gate?: Partial<Gate>;
  ignore: IgnoreRule[];
  /** Layer 2 settings; `evershield audit` requires this block. */
  audit?: AuditConfig;
}

export const DEFAULT_CONFIG_FILE = "evershield.config.json";

export class ConfigError extends Error {}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Validate a parsed JSON value into a Config, with messages a human can act on. */
export function parseConfig(raw: unknown, source: string): Config {
  if (!isRecord(raw)) throw new ConfigError(`${source}: expected a JSON object`);

  const config: Config = { ignore: [] };

  if (raw.gate !== undefined) {
    if (!isRecord(raw.gate)) throw new ConfigError(`${source}: "gate" must be an object`);
    const gate: Partial<Gate> = {};
    if (raw.gate.failOn !== undefined) {
      const failOn = raw.gate.failOn;
      if (typeof failOn !== "string" || !(failOn === "none" || (SEVERITIES as readonly string[]).includes(failOn))) {
        throw new ConfigError(`${source}: "gate.failOn" must be one of ${[...SEVERITIES, "none"].join(", ")}`);
      }
      gate.failOn = failOn as Severity | "none";
    }
    if (raw.gate.minConfidence !== undefined) {
      const minConfidence = raw.gate.minConfidence;
      if (typeof minConfidence !== "string" || !(CONFIDENCES as readonly string[]).includes(minConfidence)) {
        throw new ConfigError(`${source}: "gate.minConfidence" must be one of ${CONFIDENCES.join(", ")}`);
      }
      gate.minConfidence = minConfidence as Confidence;
    }
    config.gate = gate;
  }

  if (raw.ignore !== undefined) {
    if (!Array.isArray(raw.ignore)) throw new ConfigError(`${source}: "ignore" must be an array`);
    raw.ignore.forEach((entry, index) => {
      const where = `${source}: ignore[${index}]`;
      if (!isRecord(entry)) throw new ConfigError(`${where} must be an object`);
      if (typeof entry.ruleId !== "string" || entry.ruleId.length === 0) throw new ConfigError(`${where}.ruleId is required`);
      if (typeof entry.reason !== "string" || entry.reason.trim().length === 0) {
        throw new ConfigError(`${where}.reason is required: say why this finding is safe to ignore`);
      }
      if (entry.path !== undefined && typeof entry.path !== "string") throw new ConfigError(`${where}.path must be a string`);
      if (entry.match !== undefined && typeof entry.match !== "string") throw new ConfigError(`${where}.match must be a string`);
      const rule: IgnoreRule = { ruleId: entry.ruleId, reason: entry.reason };
      if (typeof entry.path === "string") rule.path = entry.path;
      if (typeof entry.match === "string") rule.match = entry.match;
      config.ignore.push(rule);
    });
  }

  if (raw.audit !== undefined) config.audit = parseAuditConfig(raw.audit, `${source}: audit`);

  return config;
}

const METHODS: readonly HttpMethod[] = ["GET", "POST", "PUT", "PATCH", "DELETE"];
const CREDENTIAL_HEADERS = new Set(["authorization", "cookie", "x-api-key", "api-key", "x-auth-token"]);

function parseHeaders(raw: unknown, where: string): Record<string, string> {
  if (!isRecord(raw)) throw new ConfigError(`${where} must be an object of header name → value`);
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(raw)) {
    if (typeof value !== "string") throw new ConfigError(`${where}.${name} must be a string`);
    if (CREDENTIAL_HEADERS.has(name.toLowerCase()) && !/\$\{[A-Z_][A-Z0-9_]*\}/.test(value)) {
      throw new ConfigError(
        `${where}.${name} must reference an environment variable such as "Bearer \${EVERSHIELD_PRO_TOKEN}"; literal credentials are not allowed in config`,
      );
    }
    headers[name] = value;
  }
  return headers;
}

function parseAuditConfig(raw: unknown, where: string): AuditConfig {
  if (!isRecord(raw)) throw new ConfigError(`${where} must be an object`);

  if (typeof raw.baseUrl !== "string") throw new ConfigError(`${where}.baseUrl is required`);
  let base: URL;
  try {
    base = new URL(raw.baseUrl);
  } catch {
    throw new ConfigError(`${where}.baseUrl is not a valid URL`);
  }
  if (base.protocol !== "http:" && base.protocol !== "https:") throw new ConfigError(`${where}.baseUrl must be http or https`);

  if (!isRecord(raw.identities) || Object.keys(raw.identities).length === 0) {
    throw new ConfigError(`${where}.identities must define at least one identity`);
  }
  const identities: Record<string, IdentityConfig> = {};
  for (const [name, value] of Object.entries(raw.identities)) {
    if (!isRecord(value)) throw new ConfigError(`${where}.identities.${name} must be an object`);
    const identity: IdentityConfig = {};
    if (value.headers !== undefined) identity.headers = parseHeaders(value.headers, `${where}.identities.${name}.headers`);
    identities[name] = identity;
  }

  if (!Array.isArray(raw.tiers) || raw.tiers.length === 0 || !raw.tiers.every((tier) => typeof tier === "string")) {
    throw new ConfigError(`${where}.tiers must list identity names from least to most privileged`);
  }
  const tiers = raw.tiers as string[];
  for (const tier of tiers) {
    if (identities[tier] === undefined) throw new ConfigError(`${where}.tiers names "${tier}" which is not in identities`);
  }

  if (!Array.isArray(raw.endpoints) || raw.endpoints.length === 0) throw new ConfigError(`${where}.endpoints must list at least one endpoint`);
  const endpoints: EndpointConfig[] = raw.endpoints.map((entry, index) => {
    const at = `${where}.endpoints[${index}]`;
    if (!isRecord(entry)) throw new ConfigError(`${at} must be an object`);
    const method = (typeof entry.method === "string" ? entry.method : "GET").toUpperCase();
    if (!(METHODS as readonly string[]).includes(method)) throw new ConfigError(`${at}.method must be one of ${METHODS.join(", ")}`);
    if (typeof entry.path !== "string" || !entry.path.startsWith("/")) throw new ConfigError(`${at}.path must start with "/" (relative to baseUrl)`);
    const endpoint: EndpointConfig = { method: method as HttpMethod, path: entry.path };
    if (entry.headers !== undefined) endpoint.headers = parseHeaders(entry.headers, `${at}.headers`);
    if (entry.body !== undefined) endpoint.body = entry.body;
    if (entry.tiered !== undefined) {
      if (typeof entry.tiered !== "boolean") throw new ConfigError(`${at}.tiered must be a boolean`);
      endpoint.tiered = entry.tiered;
    }
    if (entry.expect !== undefined) {
      if (!isRecord(entry.expect)) throw new ConfigError(`${at}.expect must be an object keyed by identity`);
      endpoint.expect = {};
      for (const [identity, expectation] of Object.entries(entry.expect)) {
        if (identities[identity] === undefined) throw new ConfigError(`${at}.expect.${identity} is not a defined identity`);
        if (!isRecord(expectation)) throw new ConfigError(`${at}.expect.${identity} must be an object`);
        const absent = expectation.absent;
        if (absent !== undefined && !(Array.isArray(absent) && absent.every((path) => typeof path === "string" && path.length > 0))) {
          throw new ConfigError(`${at}.expect.${identity}.absent must be an array of JSON paths`);
        }
        endpoint.expect[identity] = absent === undefined ? {} : { absent: absent as string[] };
      }
    }
    return endpoint;
  });

  const audit: AuditConfig = { baseUrl: base.origin, tiers, identities, endpoints };
  if (raw.timeoutMs !== undefined) {
    if (typeof raw.timeoutMs !== "number" || raw.timeoutMs <= 0) throw new ConfigError(`${where}.timeoutMs must be a positive number`);
    audit.timeoutMs = raw.timeoutMs;
  }
  return audit;
}

/**
 * Load the config file. An explicit path must exist; the default file is
 * optional. Returns the source path alongside, for messages.
 */
export async function loadConfig(explicitPath?: string): Promise<{ config: Config; source: string | null }> {
  const filePath = path.resolve(explicitPath ?? DEFAULT_CONFIG_FILE);
  let text: string;
  try {
    text = await readFile(filePath, "utf8");
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT" && explicitPath === undefined) return { config: { ignore: [] }, source: null };
    throw new ConfigError(`cannot read config ${filePath}: ${code ?? String(error)}`);
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (error) {
    throw new ConfigError(`${filePath}: invalid JSON (${error instanceof Error ? error.message : String(error)})`);
  }
  return { config: parseConfig(raw, filePath), source: filePath };
}

/** Minimal glob: `**` spans directories, `*` and `?` stay within one segment. */
export function globToRegExp(pattern: string): RegExp {
  let out = "";
  for (let i = 0; i < pattern.length; i += 1) {
    const ch = pattern[i]!;
    if (ch === "*") {
      if (pattern[i + 1] === "*") {
        const slashFollows = pattern[i + 2] === "/";
        out += slashFollows ? "(?:.*/)?" : ".*";
        i += slashFollows ? 2 : 1;
      } else {
        out += "[^/]*";
      }
    } else if (ch === "?") {
      out += "[^/]";
    } else {
      out += ch.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    }
  }
  return new RegExp(`^${out}$`);
}

function matches(rule: IgnoreRule, finding: Finding): boolean {
  if (rule.ruleId !== "*" && rule.ruleId !== finding.ruleId) return false;
  const first = finding.evidence[0];
  if (rule.path !== undefined) {
    // For file evidence the glob matches the file path; for response
    // evidence it matches "METHOD /path" so one entry can cover an endpoint.
    const subject = first?.kind === "file" ? first.path : first?.kind === "response" ? first.endpoint : undefined;
    if (subject === undefined || !globToRegExp(rule.path).test(subject)) return false;
  }
  if (rule.match !== undefined) {
    const haystack = `${finding.message}\n${first?.excerpt ?? ""}`;
    if (!haystack.includes(rule.match)) return false;
  }
  return true;
}

/** Split findings into those kept and those an ignore rule accounts for. */
export function applyIgnores(findings: Finding[], ignore: IgnoreRule[]): { kept: Finding[]; ignored: Finding[] } {
  const kept: Finding[] = [];
  const ignored: Finding[] = [];
  for (const finding of findings) {
    (ignore.some((rule) => matches(rule, finding)) ? ignored : kept).push(finding);
  }
  return { kept, ignored };
}
