import { writeFile } from "node:fs/promises";
import path from "node:path";
import { parseArgs } from "node:util";

import { runAudit } from "./audit/run.ts";
import { applyIgnores, type Config, ConfigError, loadConfig } from "./config.ts";
import { runInit } from "./init.ts";
import { runRecon } from "./recon.ts";
import { renderReconJson, renderReconSarif, renderReconText } from "./report/recon.ts";
import { runSurface } from "./surface/run.ts";
import { VERSION, type Confidence, type Severity } from "./index.ts";
import { CONFIDENCES, DEFAULT_GATE, type Format, type Gate, isBlocking, renderJson, renderText, type Report, SEVERITIES } from "./report/index.ts";
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
  evershield init [--force]         Detect your framework and write evershield.config.json
                                    and a GitHub workflow that scans every pull request
  evershield scan <dir|app> [options]
                                    Layer 1: scan a built web directory, or an app package
                                    (.apk, .aab, .ipa, Electron .asar)
  evershield recon <dir|app> [--rea] [--rea-bin <path>]
                                    The attacker's view: what reverse-engineering tools such
                                    as REA recover from a build or app package. Fails when
                                    anything is worth taking; --rea checks each finding
                                    against REA's own output
  evershield audit [options]        Layer 2: call configured endpoints as each identity
                                    and compare what they receive (needs config "audit")
  evershield surface [options]      Layer 3: open configured pages as each identity in a
                                    headless browser and find content that is present but
                                    hidden (needs config "surface" and Playwright)
  evershield --version              Print version
  evershield --help                 Show this help

Options (scan, audit, surface):
  --format <text|json|sarif>        Output format (default: text)
  --output <file>                   Write the report to a file; stdout gets a one-line summary
  --config <file>                   Config file (default: ./evershield.config.json if present)
  --fail-on <severity|none>         Fail on findings at this severity or worse
                                    (critical|high|medium|low|info|none; default: high)
  --min-confidence <level>          Findings below this confidence never fail the build
                                    (high|medium|low; default: medium)

Scan options:
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

interface CommonOptions {
  positionals: string[];
  format: Format;
  outputPath: string | undefined;
  configPath: string | undefined;
  failOn: Severity | "none" | undefined;
  minConfidence: Confidence | undefined;
  adapter: Adapter["name"] | undefined;
}

function parseCommonOptions(rest: readonly string[]): CommonOptions | CliResult {
  let parsed: ReturnType<typeof parseArgs>;
  try {
    parsed = parseArgs({
      args: [...rest],
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

  const format = String(parsed.values.format);
  if (!isOneOf<Format>(format, ["text", "json", "sarif"])) return usageError(`unknown --format "${format}"`);

  const failOn = parsed.values["fail-on"] === undefined ? undefined : String(parsed.values["fail-on"]);
  if (failOn !== undefined && !isOneOf<Severity | "none">(failOn, [...SEVERITIES, "none"])) return usageError(`unknown --fail-on "${failOn}"`);

  const minConfidence = parsed.values["min-confidence"] === undefined ? undefined : String(parsed.values["min-confidence"]);
  if (minConfidence !== undefined && !isOneOf<Confidence>(minConfidence, CONFIDENCES)) return usageError(`unknown --min-confidence "${minConfidence}"`);

  const adapter = parsed.values.adapter === undefined ? undefined : String(parsed.values.adapter);
  if (adapter !== undefined && !isOneOf<Adapter["name"]>(adapter, Object.keys(ADAPTERS) as Adapter["name"][])) {
    return usageError(`unknown --adapter "${adapter}"`);
  }

  return {
    positionals: parsed.positionals,
    format,
    outputPath: parsed.values.output === undefined ? undefined : String(parsed.values.output),
    configPath: parsed.values.config === undefined ? undefined : String(parsed.values.config),
    failOn,
    minConfidence,
    adapter,
  };
}

function gateFor(options: CommonOptions, config: Config): Gate {
  // Precedence: CLI flag, then config file, then defaults.
  return {
    failOn: options.failOn ?? config.gate?.failOn ?? DEFAULT_GATE.failOn,
    minConfidence: options.minConfidence ?? config.gate?.minConfidence ?? DEFAULT_GATE.minConfidence,
  };
}

async function finish(report: Report, gate: Gate, options: CommonOptions): Promise<CliResult> {
  const blocking = report.findings.filter((finding) => isBlocking(finding, gate)).length;
  const rendered =
    options.format === "json" ? renderJson(report, gate) : options.format === "sarif" ? renderSarif(report, gate) : renderText(report, gate);
  const code = blocking > 0 ? 1 : 0;

  if (options.outputPath === undefined) return { code, stdout: rendered, stderr: "" };

  await writeFile(path.resolve(options.outputPath), rendered);
  const summary = `evershield: ${report.findings.length} finding(s), ${blocking} blocking, ${report.ignored} ignored · ${options.format} report written to ${options.outputPath}\n`;
  return { code, stdout: summary, stderr: "" };
}

function failure(command: string, error: unknown): CliResult {
  const message = error instanceof Error ? error.message : String(error);
  const prefix = error instanceof ConfigError ? "evershield config" : `evershield ${command}`;
  return { code: 2, stdout: "", stderr: `${prefix}: ${message}\n` };
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
  if (command === "init") {
    const unknown = rest.filter((arg) => arg !== "--force");
    if (unknown.length > 0) return usageError(`init: unexpected argument "${unknown[0]}"`);
    try {
      const { detection, written, skipped } = await runInit(process.cwd(), { force: rest.includes("--force") });
      const lines = [
        `evershield init · detected ${detection.framework} · build output ${detection.buildDir} · ${detection.packageManager}`,
        ...written.map((file) => `  created  ${file}`),
        ...skipped.map((file) => `  skipped  ${file} (exists; use --force to overwrite)`),
        "",
        "Next:",
        `  1. Build, then try it locally:  npx evershield scan ${detection.buildDir}`,
        "  2. Commit the workflow; every pull request is scanned and findings appear in the Security tab.",
        "  3. Known-safe matches go in evershield.config.json under \"ignore\", each with a reason.",
      ];
      if (detection.framework === "unknown") {
        lines.push("", `Could not detect a framework; edit the build step and path in .github/workflows/evershield.yml.`);
      }
      return { code: 0, stdout: `${lines.join("\n")}\n`, stderr: "" };
    } catch (error) {
      return failure("init", error);
    }
  }
  if (command === "recon") return reconCommand(rest);
  if (command !== "scan" && command !== "audit" && command !== "surface") {
    return usageError(`unknown command "${command}"`);
  }

  const options = parseCommonOptions(rest);
  if ("code" in options) return options;

  if (command === "scan") {
    const target = options.positionals[0];
    if (target === undefined) return usageError("scan: missing <dir>");
    try {
      const { config } = await loadConfig(options.configPath);
      const gate = gateFor(options, config);
      const scanned = await scanArtifact(target, options.adapter === undefined ? {} : { adapter: options.adapter });
      const { kept, ignored } = applyIgnores(scanned.findings, config.ignore);
      return await finish({ ...scanned, findings: kept, ignored: ignored.length }, gate, options);
    } catch (error) {
      return failure("scan", error);
    }
  }

  if (options.positionals.length > 0) return usageError(`${command}: unexpected argument "${options.positionals[0]}"`);

  if (command === "surface") {
    try {
      const { config, source } = await loadConfig(options.configPath);
      if (config.surface === undefined) {
        throw new ConfigError(
          source === null
            ? "surface needs a config file with a \"surface\" block (see docs/configuration.md)"
            : `${source} has no "surface" block (see docs/configuration.md)`,
        );
      }
      const gate = gateFor(options, config);
      const surfaced = await runSurface(config.surface);
      if (surfaced.snapshotsEvaluated === 0) {
        throw new Error(`no page could be evaluated, so nothing was audited:\n  ${surfaced.warnings.join("\n  ")}`);
      }
      const { kept, ignored } = applyIgnores(surfaced.findings, config.ignore);
      return await finish({ ...surfaced, findings: kept, ignored: ignored.length }, gate, options);
    } catch (error) {
      return failure("surface", error);
    }
  }

  try {
    const { config, source } = await loadConfig(options.configPath);
    if (config.audit === undefined) {
      throw new ConfigError(
        source === null
          ? "audit needs a config file with an \"audit\" block (see docs/configuration.md)"
          : `${source} has no "audit" block (see docs/configuration.md)`,
      );
    }
    const gate = gateFor(options, config);
    const audited = await runAudit(config.audit);
    if (audited.responsesEvaluated === 0) {
      // "No findings" would be a lie: nothing was looked at. Fail loudly.
      throw new Error(`no response could be evaluated, so nothing was audited:\n  ${audited.warnings.join("\n  ")}`);
    }
    const { kept, ignored } = applyIgnores(audited.findings, config.ignore);
    return await finish({ ...audited, findings: kept, ignored: ignored.length }, gate, options);
  } catch (error) {
    return failure("audit", error);
  }
}

async function reconCommand(rest: readonly string[]): Promise<CliResult> {
  const args = [...rest];
  let reaBin: string | undefined;
  const reaAt = args.indexOf("--rea");
  if (reaAt >= 0) {
    args.splice(reaAt, 1);
    reaBin = "rea";
  }
  const binAt = args.indexOf("--rea-bin");
  if (binAt >= 0) {
    const value = args[binAt + 1];
    if (value === undefined || value.startsWith("--")) return usageError("recon: --rea-bin needs a path");
    args.splice(binAt, 2);
    reaBin = value;
  }
  const options = parseCommonOptions(args);
  if ("code" in options) return options;
  const target = options.positionals[0];
  if (target === undefined) return usageError("recon: missing <dir|app>");
  try {
    const { config } = await loadConfig(options.configPath);
    const gate = gateFor(options, config);
    const result = await runRecon(target, {
      ...(options.adapter === undefined ? {} : { adapter: options.adapter }),
      ...(reaBin === undefined ? {} : { reaBin }),
    });
    const { kept, ignored } = applyIgnores(result.findings, config.ignore);
    const keptSet = new Set(kept);
    const filtered = { ...result, findings: kept, items: result.items.filter((item) => keptSet.has(item.finding)), ignored: ignored.length };
    const blocking = kept.filter((finding) => isBlocking(finding, gate)).length;
    // A requested REA check that could not run is not a pass.
    const code = result.rea.status === "failed" ? 2 : blocking > 0 ? 1 : 0;
    const rendered =
      options.format === "json" ? renderReconJson(filtered, gate) : options.format === "sarif" ? renderReconSarif(filtered, gate) : renderReconText(filtered, gate);
    const stderr = result.rea.status === "failed" ? `evershield recon: ${result.rea.detail ?? "REA failed"}\n` : "";
    if (options.outputPath === undefined) return { code, stdout: rendered, stderr };
    await writeFile(path.resolve(options.outputPath), rendered);
    return { code, stdout: `evershield recon: ${filtered.items.length} item(s), ${blocking} blocking · ${options.format} report written to ${options.outputPath}\n`, stderr };
  } catch (error) {
    return failure("recon", error);
  }
}
