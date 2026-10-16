import { writeFile } from "node:fs/promises";
import path from "node:path";
import { parseArgs } from "node:util";

import { applyIgnores, ConfigError, loadConfig } from "./config.ts";
import { VERSION, type Confidence, type Severity } from "./index.ts";
import { CONFIDENCES, DEFAULT_GATE, type Format, type Gate, isBlocking, renderJson, renderText, SEVERITIES } from "./report/index.ts";
import { renderSarif } from "./report/sarif.ts";
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
  --format <text|json|sarif>        Output format (default: text)
  --output <file>                   Write the report to a file; stdout gets a one-line summary
  --config <file>                   Config file (default: ./evershield.config.json if present)
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
 * Entry point without process side effects beyond the optional --output
 * file: takes argv (minus node and the script path), returns what to print
 * and the exit code.
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
        output: { type: "string" },
        config: { type: "string" },
        "fail-on": { type: "string" },
        "min-confidence": { type: "string" },
        adapter: { type: "string" },
      },
    });
  } catch (error) {
    return usageError(error instanceof Error ? error.message : String(error));
  }

  const target = parsed.positionals[0];
  if (target === undefined) return usageError("scan: missing <dir>");

  const format = String(parsed.values.format);
  if (!isOneOf<Format>(format, ["text", "json", "sarif"])) return usageError(`unknown --format "${format}"`);

  const failOnFlag = parsed.values["fail-on"] === undefined ? undefined : String(parsed.values["fail-on"]);
  if (failOnFlag !== undefined && !isOneOf<Severity | "none">(failOnFlag, [...SEVERITIES, "none"])) {
    return usageError(`unknown --fail-on "${failOnFlag}"`);
  }

  const minConfidenceFlag = parsed.values["min-confidence"] === undefined ? undefined : String(parsed.values["min-confidence"]);
  if (minConfidenceFlag !== undefined && !isOneOf<Confidence>(minConfidenceFlag, CONFIDENCES)) {
    return usageError(`unknown --min-confidence "${minConfidenceFlag}"`);
  }

  const adapterName = parsed.values.adapter === undefined ? undefined : String(parsed.values.adapter);
  if (adapterName !== undefined && !isOneOf<Adapter["name"]>(adapterName, Object.keys(ADAPTERS) as Adapter["name"][])) {
    return usageError(`unknown --adapter "${adapterName}"`);
  }

  const configPath = parsed.values.config === undefined ? undefined : String(parsed.values.config);
  const outputPath = parsed.values.output === undefined ? undefined : String(parsed.values.output);

  try {
    const { config } = await loadConfig(configPath);

    // Precedence: CLI flag, then config file, then defaults.
    const gate: Gate = {
      failOn: failOnFlag ?? config.gate?.failOn ?? DEFAULT_GATE.failOn,
      minConfidence: minConfidenceFlag ?? config.gate?.minConfidence ?? DEFAULT_GATE.minConfidence,
    };

    const scanned = await scanArtifact(target, adapterName === undefined ? {} : { adapter: adapterName });
    const { kept, ignored } = applyIgnores(scanned.findings, config.ignore);
    const result = { ...scanned, findings: kept, ignored: ignored.length };

    const blocking = result.findings.filter((finding) => isBlocking(finding, gate)).length;
    const report =
      format === "json" ? renderJson(result, gate) : format === "sarif" ? renderSarif(result, gate) : renderText(result, gate);

    if (outputPath === undefined) {
      return { code: blocking > 0 ? 1 : 0, stdout: report, stderr: "" };
    }

    await writeFile(path.resolve(outputPath), report);
    const summary = `evershield: ${result.findings.length} finding(s), ${blocking} blocking, ${result.ignored} ignored · ${format} report written to ${outputPath}\n`;
    return { code: blocking > 0 ? 1 : 0, stdout: summary, stderr: "" };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const prefix = error instanceof ConfigError ? "evershield config" : "evershield scan";
    return { code: 2, stdout: "", stderr: `${prefix}: ${message}\n` };
  }
}
