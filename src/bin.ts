#!/usr/bin/env node
import { run } from "./cli.ts";

if (process.argv[2] === "mcp") {
  // The MCP server owns stdout for protocol messages until stdin closes.
  const { serve } = await import("./mcp.ts");
  await serve();
  process.exit(0);
}

const result = await run(process.argv.slice(2));
if (result.stdout) process.stdout.write(result.stdout);
if (result.stderr) process.stderr.write(result.stderr);
process.exitCode = result.code;
