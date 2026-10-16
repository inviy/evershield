import { VERSION } from "./index.ts";

export interface CliResult {
  /** Process exit code. 0 ok, 1 findings, 2 usage or runtime error. */
  code: number;
  stdout: string;
  stderr: string;
}

const HELP = `evershield ${VERSION}
Shield everything, everywhere.

Usage:
  evershield scan <dir>        Scan a built web artifact directory (not yet implemented)
  evershield --version         Print version
  evershield --help            Show this help

Documentation: https://github.com/inviy/evershield
`;

/**
 * Pure entry point: takes argv (without node and script path), returns what
 * to print and the exit code. Keeping it side-effect free makes the CLI
 * testable without spawning processes.
 */
export function run(argv: readonly string[]): CliResult {
  const [command, ...rest] = argv;

  if (command === undefined || command === "--help" || command === "-h" || command === "help") {
    return { code: 0, stdout: HELP, stderr: "" };
  }

  if (command === "--version" || command === "-v" || command === "version") {
    return { code: 0, stdout: `${VERSION}\n`, stderr: "" };
  }

  if (command === "scan") {
    const target = rest[0];
    if (target === undefined) {
      return { code: 2, stdout: "", stderr: "evershield scan: missing <dir>\n" };
    }
    return {
      code: 2,
      stdout: "",
      stderr: `evershield scan: the artifact scanner is not implemented yet (target: ${target}).\n`,
    };
  }

  return { code: 2, stdout: "", stderr: `evershield: unknown command "${command}"\n\n${HELP}` };
}
