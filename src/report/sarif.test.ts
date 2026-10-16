import assert from "node:assert/strict";
import test from "node:test";

import type { Finding } from "../index.ts";
import type { ArtifactScanResult } from "../scan/artifact.ts";
import { DEFAULT_GATE } from "./index.ts";
import { renderSarif } from "./sarif.ts";

const result = (findings: Finding[]): ArtifactScanResult => ({
  version: "0.0.0",
  layer: "artifact",
  target: "/build",
  adapter: "plain",
  filesScanned: 3,
  ignored: 1,
  startedAt: "2026-10-16T00:00:00.000Z",
  finishedAt: "2026-10-16T00:00:01.000Z",
  findings,
});

const critical: Finding = {
  ruleId: "artifact/secret-like-string",
  layer: "artifact",
  severity: "critical",
  confidence: "high",
  message: "AWS access key ID shipped in app.js",
  evidence: [{ kind: "file", path: "app.js", line: 3, column: 12, excerpt: "AKIA…MPLE (20 chars)" }],
  remediation: "Rotate it.",
};

const low: Finding = {
  ruleId: "artifact/internal-endpoint",
  layer: "artifact",
  severity: "low",
  confidence: "low",
  message: "localhost URL in app.js: http://localhost:3000",
  evidence: [{ kind: "file", path: "app.js", line: 9, column: 1, excerpt: "http://localhost:3000" }],
};

test("renders SARIF 2.1.0 with one rule per ruleId and one result per finding", () => {
  const sarif = JSON.parse(renderSarif(result([critical, low, critical]), DEFAULT_GATE)) as {
    version: string;
    runs: Array<{
      tool: { driver: { name: string; rules: Array<{ id: string; helpUri: string }> } };
      results: Array<{ ruleId: string; ruleIndex: number; level: string; locations: Array<{ physicalLocation: { artifactLocation: { uri: string }; region: { startLine: number } } }>; properties: { blocking: boolean } }>;
      invocations: Array<{ properties: { ignored: number } }>;
    }>;
  };
  assert.equal(sarif.version, "2.1.0");
  const run = sarif.runs[0]!;
  assert.equal(run.tool.driver.name, "evershield");
  assert.deepEqual(run.tool.driver.rules.map((rule) => rule.id), ["artifact/internal-endpoint", "artifact/secret-like-string"]);
  assert.ok(run.tool.driver.rules.every((rule) => rule.helpUri.includes("docs/rules.md#")));
  assert.equal(run.results.length, 3);
  assert.equal(run.invocations[0]!.properties.ignored, 1);

  const first = run.results[0]!;
  assert.equal(first.ruleId, "artifact/secret-like-string");
  assert.equal(run.tool.driver.rules[first.ruleIndex]!.id, first.ruleId);
  assert.equal(first.level, "error");
  assert.equal(first.locations[0]!.physicalLocation.artifactLocation.uri, "app.js");
  assert.equal(first.locations[0]!.physicalLocation.region.startLine, 3);
  assert.equal(first.properties.blocking, true);

  const second = run.results[1]!;
  assert.equal(second.level, "note");
  assert.equal(second.properties.blocking, false);
});

test("response evidence becomes a logical location", () => {
  const finding: Finding = {
    ruleId: "response/expected-absent-field-present",
    layer: "response",
    severity: "high",
    confidence: "high",
    message: "POST /api/analyze returns \"perplexity\" to free",
    evidence: [{ kind: "response", endpoint: "POST /api/analyze", identity: "free", jsonPath: "perplexity", excerpt: "object{score}" }],
  };
  const sarif = JSON.parse(renderSarif(result([finding]), DEFAULT_GATE)) as {
    runs: Array<{ results: Array<{ locations: Array<{ logicalLocations: Array<{ fullyQualifiedName: string }> }> }> }>;
  };
  assert.equal(sarif.runs[0]!.results[0]!.locations[0]!.logicalLocations[0]!.fullyQualifiedName, "POST /api/analyze as free → perplexity");
});

test("never reproduces the matched secret: only the redacted excerpt travels", () => {
  const text = renderSarif(result([critical]), DEFAULT_GATE);
  assert.ok(!text.includes("AKIAIOSFODNN7EXAMPLE"));
  assert.ok(text.includes("Rotate it."));
});
