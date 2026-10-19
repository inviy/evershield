/**
 * `evershield mcp`: a Model Context Protocol server over stdio, so coding
 * agents (Claude Code, Cursor, Codex, …) can run evershield while they write
 * the code. Newline-delimited JSON-RPC 2.0, no dependencies.
 *
 * Tools wrap the CLI with `--format json`, so an agent gets exactly what a
 * CI run would. Nothing here widens what the CLI can do: `audit` and
 * `surface` still only talk to the origin in the operator's config, and
 * `recon` runs REA only from PATH, never from a path the agent chooses.
 */
import { readFile } from "node:fs/promises";
import path from "node:path";
import { createInterface } from "node:readline";

import { run } from "./cli.ts";
import { VERSION } from "./index.ts";

interface Request {
  jsonrpc: "2.0";
  id?: number | string | null;
  method: string;
  params?: Record<string, unknown>;
}

interface ToolResult {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
}

const GATE_PROPERTIES = {
  failOn: { type: "string", enum: ["critical", "high", "medium", "low", "info", "none"], description: "Severity that counts as blocking (default high)" },
  minConfidence: { type: "string", enum: ["high", "medium", "low"], description: "Findings below this confidence never block (default medium)" },
  config: { type: "string", description: "Path to evershield.config.json (default: ./evershield.config.json if present)" },
} as const;

export const TOOLS = [
  {
    name: "evershield_scan",
    description:
      "Layer 1. Scan a built web directory (dist, .next, build) or an app package (.apk, .aab, .ipa, .asar) for what should not ship: secrets, source maps, server-only env names, internal endpoints. Returns the JSON report; `blocking` is how many findings fail the gate.",
    inputSchema: {
      type: "object",
      properties: { target: { type: "string", description: "Build directory or app package, relative to the working directory" }, ...GATE_PROPERTIES },
      required: ["target"],
    },
  },
  {
    name: "evershield_recon",
    description:
      "The attacker's view of a build or app package: what reverse-engineering tools recover (worth taking, gated) and the map any tool reconstructs anyway (hosts, API paths, source map coverage). Set rea=true to also run REA from PATH and check each finding against its output.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Build directory or app package" },
        rea: { type: "boolean", description: "Run REA (must be installed as `rea` on PATH)" },
        ...GATE_PROPERTIES,
      },
      required: ["target"],
    },
  },
  {
    name: "evershield_audit",
    description:
      "Layer 2. Call the endpoints in the config's `audit` block as each identity and report fields a lower tier should not receive. Talks only to the config's baseUrl; credentials come from environment variables.",
    inputSchema: { type: "object", properties: { ...GATE_PROPERTIES } },
  },
  {
    name: "evershield_surface",
    description:
      "Layer 3. Open the pages in the config's `surface` block as each identity in headless Chromium and report content that is present but hidden (blurred paywalls, display:none, data attributes, storage). Needs Playwright.",
    inputSchema: { type: "object", properties: { ...GATE_PROPERTIES } },
  },
  {
    name: "evershield_explain_rule",
    description: "Explain one evershield rule: what it detects, why its severity and confidence are what they are, and how to fix it.",
    inputSchema: {
      type: "object",
      properties: { ruleId: { type: "string", description: 'Rule id, e.g. "artifact/secret-like-string"' } },
      required: ["ruleId"],
    },
  },
] as const;

function str(args: Record<string, unknown>, key: string): string | undefined {
  const value = args[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function gateArgs(args: Record<string, unknown>): string[] {
  const out: string[] = ["--format", "json"];
  const failOn = str(args, "failOn");
  const minConfidence = str(args, "minConfidence");
  const config = str(args, "config");
  if (failOn !== undefined) out.push("--fail-on", failOn);
  if (minConfidence !== undefined) out.push("--min-confidence", minConfidence);
  if (config !== undefined) out.push("--config", config);
  return out;
}

async function cliTool(argv: string[]): Promise<ToolResult> {
  const result = await run(argv);
  // Exit 1 means "findings at the gate": a successful call with a verdict, not a tool error.
  if (result.code === 2) return { content: [{ type: "text", text: result.stderr || result.stdout }], isError: true };
  const text = result.stderr.length > 0 ? `${result.stdout}\n${result.stderr}` : result.stdout;
  return { content: [{ type: "text", text }] };
}

/** The rule's section of docs/rules.md, shipped in the package. */
export async function explainRule(ruleId: string, docsPath = path.resolve(import.meta.dirname, "../docs/rules.md")): Promise<string | undefined> {
  const doc = (await readFile(docsPath, "utf8")).replace(/\r\n/g, "\n"); // CRLF checkouts on Windows
  const start = doc.indexOf(`### ${ruleId}\n`);
  if (start < 0) return undefined;
  const next = doc.slice(start + 4).search(/\n#{2,3} /);
  return doc.slice(start, next < 0 ? undefined : start + 4 + next).trim();
}

export async function callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
  const target = str(args, "target");
  switch (name) {
    case "evershield_scan":
      if (target === undefined) return { content: [{ type: "text", text: "target is required" }], isError: true };
      return cliTool(["scan", target, ...gateArgs(args)]);
    case "evershield_recon":
      if (target === undefined) return { content: [{ type: "text", text: "target is required" }], isError: true };
      return cliTool(["recon", target, ...(args.rea === true ? ["--rea"] : []), ...gateArgs(args)]);
    case "evershield_audit":
      return cliTool(["audit", ...gateArgs(args)]);
    case "evershield_surface":
      return cliTool(["surface", ...gateArgs(args)]);
    case "evershield_explain_rule": {
      const ruleId = str(args, "ruleId");
      const text = ruleId === undefined ? undefined : await explainRule(ruleId);
      return text === undefined
        ? { content: [{ type: "text", text: `Unknown rule "${ruleId ?? ""}". Rules are listed in docs/rules.md.` }], isError: true }
        : { content: [{ type: "text", text }] };
    }
    default:
      return { content: [{ type: "text", text: `Unknown tool "${name}"` }], isError: true };
  }
}

const SUPPORTED_PROTOCOLS = ["2025-06-18", "2025-03-26", "2024-11-05"];

/** Handle one JSON-RPC message; returns the response, or null for notifications. */
export async function handleMessage(message: Request): Promise<object | null> {
  const { id, method, params = {} } = message;
  if (id === undefined || id === null) return null; // notification (e.g. notifications/initialized)
  const reply = (result: object) => ({ jsonrpc: "2.0", id, result });
  try {
    switch (method) {
      case "initialize": {
        const requested = typeof params.protocolVersion === "string" ? params.protocolVersion : SUPPORTED_PROTOCOLS[0]!;
        return reply({
          protocolVersion: SUPPORTED_PROTOCOLS.includes(requested) ? requested : SUPPORTED_PROTOCOLS[0],
          capabilities: { tools: {} },
          serverInfo: { name: "evershield", version: VERSION },
          instructions:
            "Run evershield_scan or evershield_recon on the build output after changing anything the browser or app receives. Fix findings at the source; never add an ignore without a reason.",
        });
      }
      case "ping":
        return reply({});
      case "tools/list":
        return reply({ tools: TOOLS });
      case "tools/call": {
        const name = typeof params.name === "string" ? params.name : "";
        const args = typeof params.arguments === "object" && params.arguments !== null ? (params.arguments as Record<string, unknown>) : {};
        return reply(await callTool(name, args));
      }
      default:
        return { jsonrpc: "2.0", id, error: { code: -32601, message: `Method not found: ${method}` } };
    }
  } catch (error) {
    return { jsonrpc: "2.0", id, error: { code: -32603, message: error instanceof Error ? error.message : String(error) } };
  }
}

/** Serve on stdin/stdout until stdin closes. Logs go to stderr; stdout carries protocol messages only. */
export async function serve(input: NodeJS.ReadableStream = process.stdin, output: NodeJS.WritableStream = process.stdout): Promise<void> {
  const lines = createInterface({ input, crlfDelay: Infinity });
  const pending: Promise<void>[] = [];
  for await (const line of lines) {
    if (line.trim().length === 0) continue;
    let message: Request;
    try {
      message = JSON.parse(line) as Request;
    } catch {
      output.write(`${JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } })}\n`);
      continue;
    }
    pending.push(
      handleMessage(message).then((response) => {
        if (response !== null) output.write(`${JSON.stringify(response)}\n`);
      }),
    );
  }
  await Promise.all(pending);
}
