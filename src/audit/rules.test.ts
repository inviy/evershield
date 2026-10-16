import assert from "node:assert/strict";
import test from "node:test";

import { expectedAbsentFieldPresent, higherTierFieldInLowerTier, identicalAcrossTiers, sensitiveField } from "./rules.ts";
import type { EndpointConfig, EndpointObservation, ResponseObservation } from "./types.ts";

function observe(endpoint: Partial<EndpointConfig>, bodies: Record<string, unknown>, tiers = Object.keys(bodies)): EndpointObservation {
  const full: EndpointConfig = { method: "POST", path: "/api/analyze", ...endpoint };
  const responses = new Map<string, ResponseObservation>();
  for (const [identity, json] of Object.entries(bodies)) {
    responses.set(identity, { identity, status: 200, contentType: "application/json", json, isJson: true });
  }
  return { endpoint: full, label: `${full.method} ${full.path}`, tiers, responses };
}

test("an expected-absent field present for a lower tier is high/high", () => {
  const observation = observe(
    { expect: { free: { absent: ["perplexity", "burstiness"] } } },
    { free: { score: 70, perplexity: { score: 30 }, burstiness: null }, pro: { score: 70, perplexity: { score: 30 }, burstiness: { ttr: 0.5 } } },
  );
  const findings = expectedAbsentFieldPresent.check(observation);
  assert.equal(findings.length, 1, "burstiness is null for free, so only perplexity is a finding");
  assert.equal(findings[0]!.severity, "high");
  assert.match(findings[0]!.message, /"perplexity" to free/);
  assert.equal(findings[0]!.evidence[0]!.kind, "response");
});

test("withholding with null satisfies the expectation", () => {
  const observation = observe(
    { expect: { free: { absent: ["perplexity"] } } },
    { free: { score: 70, perplexity: null }, pro: { score: 70, perplexity: { score: 30 } } },
  );
  assert.equal(expectedAbsentFieldPresent.check(observation).length, 0);
});

test("privileged-looking names in a lower tier are medium/medium; the top tier is not checked", () => {
  const observation = observe(
    {},
    { anonymous: { plan: "free", pro_insights: ["a"], is_premium: false }, pro: { plan: "pro", pro_insights: ["a", "b"], internal_cost: 12 } },
  );
  const findings = higherTierFieldInLowerTier.check(observation);
  assert.deepEqual(findings.map((finding) => finding.evidence[0]!.kind === "response" && finding.evidence[0]!.jsonPath), ["pro_insights"]);
  assert.equal(findings[0]!.severity, "medium");
});

test("sensitive fields are reported once with a redacted excerpt; booleans are not", () => {
  const observation = observe(
    {},
    {
      free: { user: { email: "a@b.c", password_hash: "$2b$10$abcdefghijklmnopqrstuv", has_password: true } },
      pro: { user: { email: "a@b.c", password_hash: "$2b$10$abcdefghijklmnopqrstuv", has_password: true } },
    },
  );
  const findings = sensitiveField.check(observation);
  assert.equal(findings.length, 1);
  assert.ok(!JSON.stringify(findings).includes("abcdefghijklmnopqrstuv"));
});

test("identical bodies: high/medium when declared tiered, low/low otherwise, nothing when they differ", () => {
  const same = { free: { a: 1 }, pro: { a: 1 } };
  assert.equal(identicalAcrossTiers.check(observe({ tiered: true }, same))[0]!.severity, "high");
  assert.equal(identicalAcrossTiers.check(observe({}, same))[0]!.severity, "low");
  assert.equal(identicalAcrossTiers.check(observe({ tiered: true }, { free: { a: 1 }, pro: { a: 2 } })).length, 0);
});

test("non-2xx and non-JSON responses are skipped by every rule", () => {
  const observation = observe({ tiered: true, expect: { free: { absent: ["x"] } } }, { free: { x: 1 }, pro: { x: 1 } });
  observation.responses.set("free", { identity: "free", status: 401, contentType: null, json: { x: 1 }, isJson: true });
  assert.equal(expectedAbsentFieldPresent.check(observation).length, 0);
  assert.equal(identicalAcrossTiers.check(observation).length, 0);
});
