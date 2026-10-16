import { parseArgs } from "node:util";

import { VERSION, type Confidence, type Severity } from "./index.ts";
import { CONFIDENCES, DEFAULT_GATE, type Format, type Gate, isBlocking, renderJson, renderText, SEVERITIES } from "./report/index.ts";
import { scanArtifact } from "./scan/artifact.ts";
import { ADAPTERS, type Adapter } from "./scan/adapters.ts";

export interface CliResult {
  /** Process exit code. 0 clean, 1 blocking findings, 2 usage or runtime error. */
  code: number;
  stdout: string;
  stderr: string;
}

const HELP = `evershield ${VERSION}
Shield everything, everywhere.

Usage:
  evershield scan <dir> [options]   Scan a built web artifact directory
  evershield --version              Print version
  evershield --help                 Show this help

Scan options:
  --format <text|json>              Output format (default: text)
  --fail-on <severity|none>         Fail on findings at this severity or worse
                                    (critical|high|medium|low|info|none; default: high)
  --min-confidence <level>          Findings below this confidence never fail the build
                                    (high|medium|low; default: medium)
  --adapter <nextjs|plain>          Force an adapter instead of detecting one

Exit codes: 0 clean · 1 blocking findings · 2 usage or runtime error
Documentation: https://github.com/inviy/evershield
`;

function usageError(message: string): CliResult {
  return { code: 2, stdout: "", stderr: `evershield: ${message}\n\n${HELP}` };
}

function isOneOf<T extends string>(value: string, allowed: readonly T[]): value is T {
  return (allowed as readonly string[]).includes(value);
}

/**
 * Entry point without process side effects: takes argv (minus node and the
 * script path), returns what to print and the exit code.
 */
export async function run(argv: readonly string[]): Promise<CliResult> {
  const [command, ...rest] = argv;

  if (command === undefined || command === "--help" || command === "-h" || command === "help") {
    return { code: 0, stdout: HELP, stderr: "" };
  }
  if (command === "--version" || command === "-v" || command === "version") {
    return { code: 0, stdout: `${VERSION}\n`, stderr: "" };
  }
  if (command !== "scan") {
    return usageError(`unknown command "${command}"`);
  }

  let parsed: ReturnType<typeof parseArgs>;
  try {
    parsed = parseArgs({
      args: rest,
      allowPositionals: true,
      options: {
        format: { type: "string", default: "text" },
        "fail-on": { type: "string", default: DEFAULT_GATE.failOn },
        "min-confidence": { type: "string", default: DEFAULT_GATE.minConfidence },
        adapter: { type: "string" },
      },
    });
  } catch (error) {
    return usageError(error instanceof Error ? error.message : String(error));
  }

  const target = parsed.positionals[0];
  if (target === undefined) return usageError("scan: missing <dir>");

  const format = String(parsed.values.format);
  if (!isOneOf<Format>(format, ["text", "json"])) return usageError(`unknown --format "${format}"`);

  const failOn = String(parsed.values["fail-on"]);
  if (!isOneOf<Severity | "none">(failOn, [...SEVERITIES, "none"])) return usageError(`unknown --fail-on "${failOn}"`);

  const minConfidence = String(parsed.values["min-confidence"]);
  if (!isOneOf<Confidence>(minConfidence, CONFIDENCES)) return usageError(`unknown --min-confidence "${minConfidence}"`);

  const adapterName = parsed.values.adapter === undefined ? undefined : String(parsed.values.adapter);
  if (adapterName !== undefined && !isOneOf<Adapter["name"]>(adapterName, Object.keys(ADAPTERS) as Adapter["name"][])) {
    return usageError(`unknown --adapter "${adapterName}"`);
  }

  const gate: Gate = { failOn, minConfidence };

  try {
    const result = await scanArtifact(target, adapterName === undefined ? {} : { adapter: adapterName });
    const blocking = result.findings.some((finding) => isBlocking(finding, gate));
    const stdout = format === "json" ? renderJson(result, gate) : renderText(result, gate);
    return { code: blocking ? 1 : 0, stdout, stderr: "" };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { code: 2, stdout: "", stderr: `evershield scan: ${message}\n` };
  }
}
