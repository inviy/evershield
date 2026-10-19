import assert from "node:assert/strict";
import path from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";

import { explainRule, handleMessage, serve, TOOLS } from "./mcp.ts";
import { fake, withTempDir } from "./test-support.ts";

const call = (name: string, args: Record<string, unknown>) =>
  handleMessage({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }) as Promise<{
    result: { content: Array<{ text: string }>; isError?: boolean };
  }>;

test("initialize negotiates a supported protocol version and advertises tools", async () => {
  const response = (await handleMessage({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26" } })) as {
    result: { protocolVersion: string; capabilities: { tools: object }; serverInfo: { name: string } };
  };
  assert.equal(response.result.protocolVersion, "2025-03-26");
  assert.deepEqual(response.result.capabilities, { tools: {} });
  assert.equal(response.result.serverInfo.name, "evershield");
  const unknown = (await handleMessage({ jsonrpc: "2.0", id: 2, method: "initialize", params: { protocolVersion: "1999-01-01" } })) as {
    result: { protocolVersion: string };
  };
  assert.equal(unknown.result.protocolVersion, "2025-06-18");
});

test("tools/list exposes every tool with a JSON schema; notifications get no reply; unknown methods are -32601", async () => {
  const list = (await handleMessage({ jsonrpc: "2.0", id: 1, method: "tools/list" })) as { result: { tools: typeof TOOLS } };
  assert.deepEqual(
    list.result.tools.map((tool) => tool.name),
    ["evershield_scan", "evershield_recon", "evershield_audit", "evershield_surface", "evershield_explain_rule"],
  );
  assert.ok(list.result.tools.every((tool) => tool.inputSchema.type === "object"));
  assert.equal(await handleMessage({ jsonrpc: "2.0", method: "notifications/initialized" }), null);
  const missing = (await handleMessage({ jsonrpc: "2.0", id: 3, method: "resources/list" })) as { error: { code: number } };
  assert.equal(missing.error.code, -32601);
});

test("evershield_scan returns the JSON report; findings are a verdict, not a tool error; the secret stays redacted", async () => {
  await withTempDir({ "dist/app.js": `const k="${fake.stripeLiveKey()}";` }, async (root) => {
    const { result } = await call("evershield_scan", { target: path.join(root, "dist") });
    assert.equal(result.isError, undefined);
    const report = JSON.parse(result.content[0]!.text) as { blocking: number; findings: unknown[] };
    assert.equal(report.blocking, 1);
    assert.ok(!result.content[0]!.text.includes(fake.stripeLiveKey()));
  });
  const { result } = await call("evershield_scan", { target: "/definitely/not/here" });
  assert.equal(result.isError, true);
  const noTarget = await call("evershield_scan", {});
  assert.equal(noTarget.result.isError, true);
});

test("evershield_recon and evershield_explain_rule", async () => {
  await withTempDir({ "dist/app.js": `fetch("/api/report")` }, async (root) => {
    const { result } = await call("evershield_recon", { target: path.join(root, "dist") });
    const report = JSON.parse(result.content[0]!.text) as { blocking: number; map: { apiPaths: string[] } };
    assert.equal(report.blocking, 0);
    assert.deepEqual(report.map.apiPaths, ["/api/report"]);
  });
  const docs = path.resolve(import.meta.dirname, "../docs/rules.md");
  const text = await explainRule("surface/obscured-content", docs);
  assert.match(text ?? "", /^### surface\/obscured-content/);
  assert.ok(!(text ?? "").includes("### surface/expected"), "stops at the next rule");
  await withTempDir({ "rules.md": "## Surface\r\n\r\n### surface/a\r\n\r\nBody.\r\n\r\n### surface/b\r\n" }, async (root) => {
    assert.equal(await explainRule("surface/a", path.join(root, "rules.md")), "### surface/a\n\nBody.", "CRLF checkouts (Windows)");
  });
  const unknown = await call("evershield_explain_rule", { ruleId: "artifact/nope" });
  assert.equal(unknown.result.isError, true);
});

test("serve speaks newline-delimited JSON-RPC over streams and reports parse errors", async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const chunks: string[] = [];
  output.on("data", (chunk: Buffer) => chunks.push(chunk.toString()));
  const done = serve(input, output);
  input.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" })}\n`);
  input.write("not json\n");
  input.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
  input.end();
  await done;
  const messages = chunks.join("").trim().split("\n").map((line) => JSON.parse(line) as { id: unknown; result?: unknown; error?: { code: number } });
  assert.equal(messages.length, 2);
  assert.deepEqual(messages.find((m) => m.id === 1)?.result, {});
  assert.equal(messages.find((m) => m.id === null)?.error?.code, -32700);
});
