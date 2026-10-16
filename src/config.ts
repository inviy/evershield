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

  return config;
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
    if (first === undefined || first.kind !== "file" || !globToRegExp(rule.path).test(first.path)) return false;
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
