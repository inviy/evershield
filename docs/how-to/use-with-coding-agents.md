# Use evershield from a coding agent

## Claude Code plugin

```
/plugin marketplace add inviy/evershield
/plugin install evershield@evershield
```

The plugin adds the MCP server below, an `evershield` skill (Claude checks
the server-side boundary whenever it touches response fields, plan branches,
public env vars or `public/`) and an `/evershield` command that builds and
scans the project.

## Any MCP client

`evershield mcp` is a Model Context Protocol server over stdio, so an agent
can scan the build while it writes the code. Tools: `evershield_scan`,
`evershield_recon`, `evershield_audit`, `evershield_surface`,
`evershield_explain_rule`. They return the same JSON a CI run produces;
`audit` and `surface` still talk only to the origin in your config.

```bash
# Claude Code (also included in the plugin above)
claude mcp add evershield -- npx -y evershield@latest mcp
```

```json
// Cursor: .cursor/mcp.json · other clients: their MCP config file
{ "mcpServers": { "evershield": { "command": "npx", "args": ["-y", "evershield@latest", "mcp"] } } }
```

```toml
# Codex: ~/.codex/config.toml
[mcp_servers.evershield]
command = "npx"
args = ["-y", "evershield@latest", "mcp"]
```

## What the agent receives

Reports quote what was scanned: file names, identifiers, page text. A
repository or page can be written to address the agent that reads them, so
the server treats every result as untrusted data:

- invisible and bidirectional control characters (zero-width spaces, RTL
  overrides) are removed from every string,
- each string is capped at 500 characters,
- each result ends with a note that its contents are data, not instructions.

Matched secret values never reach the agent: the report carries only the
first and last four characters, as in every other output.
