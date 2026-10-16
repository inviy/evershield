import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import test from "node:test";

import { ConfigError } from "../config.ts";
import { interpolateEnv } from "./http.ts";
import { runAudit } from "./run.ts";
import type { AuditConfig } from "./types.ts";

/** A tiny API that gates by bearer token, with one deliberate leak. */
function startServer(): Promise<{ server: Server; baseUrl: string; seenAuth: string[] }> {
  const seenAuth: string[] = [];
  const server = createServer((req, res) => {
    const auth = req.headers.authorization ?? "";
    seenAuth.push(auth);
    const tier = auth === "Bearer pro-token" ? "pro" : auth === "Bearer free-token" ? "free" : "anonymous";
    let body = "";
    req.on("data", (chunk: Buffer) => (body += chunk.toString()));
    req.on("end", () => {
      if (req.url === "/api/analyze") {
        const payload = {
          status: "ok",
          echo: body ? (JSON.parse(body) as { text: string }).text.length : 0,
          perplexity: { score: 30 }, // leaked to every tier
          burstiness: tier === "pro" ? { ttr: 0.5 } : null, // correctly withheld
        };
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify(payload));
      } else if (req.url === "/api/profile") {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ plan: tier }));
      } else if (req.url === "/health") {
        res.setHeader("content-type", "text/plain");
        res.end("ok");
      } else {
        res.statusCode = 404;
        res.end();
      }
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolve({ server, baseUrl: `http://127.0.0.1:${port}`, seenAuth });
    });
  });
}

const env = { EVERSHIELD_TEST_FREE: "free-token", EVERSHIELD_TEST_PRO: "pro-token" };

test("audit calls each endpoint as each identity and reports the leak but not the correct gate", async () => {
  const { server, baseUrl, seenAuth } = await startServer();
  try {
    const config: AuditConfig = {
      baseUrl,
      tiers: ["anonymous", "free", "pro"],
      identities: {
        anonymous: {},
        free: { headers: { Authorization: "Bearer ${EVERSHIELD_TEST_FREE}" } },
        pro: { headers: { Authorization: "Bearer ${EVERSHIELD_TEST_PRO}" } },
      },
      endpoints: [
        {
          method: "POST",
          path: "/api/analyze",
          body: { text: "hello" },
          tiered: true,
          expect: { anonymous: { absent: ["perplexity", "burstiness"] }, free: { absent: ["perplexity", "burstiness"] } },
        },
        { method: "GET", path: "/api/profile" },
        { method: "GET", path: "/health" },
      ],
    };
    const result = await runAudit(config, { env });

    assert.equal(result.layer, "response");
    assert.equal(result.endpointsAudited, 3);
    // 3 endpoints × 2 authenticated identities; anonymous sends no header.
    assert.deepEqual(seenAuth.filter(Boolean).sort(), [...Array(3).fill("Bearer free-token"), ...Array(3).fill("Bearer pro-token")]);

    const expected = result.findings.filter((finding) => finding.ruleId === "response/expected-absent-field-present");
    assert.deepEqual(
      expected.map((finding) => finding.evidence[0]!.kind === "response" && `${finding.evidence[0]!.identity}:${finding.evidence[0]!.jsonPath}`),
      ["anonymous:perplexity", "free:perplexity"],
      "burstiness is null for lower tiers, so only perplexity leaks",
    );
    assert.equal(result.findings.filter((finding) => finding.ruleId === "response/identical-across-tiers").length, 0, "bodies differ in burstiness");
    assert.ok(result.warnings.some((warning) => warning.includes("/health") && warning.includes("not JSON")));
    assert.ok(!JSON.stringify(result).includes("pro-token"), "credentials never reach the report");
  } finally {
    server.close();
  }
});

test("a missing environment variable is a ConfigError that names the variable, not a value", async () => {
  assert.throws(() => interpolateEnv("Bearer ${EVERSHIELD_MISSING}", {}), (error: unknown) => {
    assert.ok(error instanceof ConfigError);
    assert.match(error.message, /EVERSHIELD_MISSING/);
    return true;
  });
});

test("an unreachable base URL becomes warnings, not a crash", async () => {
  // Bind an ephemeral port and release it, so the request meets a closed port.
  const probe = createServer();
  await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const { port } = probe.address() as AddressInfo;
  await new Promise<void>((resolve) => probe.close(() => resolve()));

  const result = await runAudit(
    { baseUrl: `http://127.0.0.1:${port}`, tiers: ["anon"], identities: { anon: {} }, endpoints: [{ method: "GET", path: "/x" }], timeoutMs: 2000 },
    { env },
  );
  assert.equal(result.findings.length, 0);
  assert.equal(result.responsesEvaluated, 0);
  assert.equal(result.warnings.length, 1);
  assert.match(result.warnings[0]!, /request failed \(fetch failed: .*ECONNREFUSED/);
});
