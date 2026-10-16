import assert from "node:assert/strict";
import test from "node:test";

import { file, plainContext } from "../test-support.ts";
import { sourceMapPublished } from "./source-map-published.ts";

test("a shipped .map file is a high/high finding", () => {
  const findings = sourceMapPublished.check(file("static/chunks/app.js.map", '{"version":3}'), plainContext);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.severity, "high");
  assert.equal(findings[0]!.confidence, "high");
  assert.match(findings[0]!.message, /Source map shipped/);
});

test("an inline data: source map is a finding", () => {
  const text = `console.log(1);\n//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ==\n`;
  const findings = sourceMapPublished.check(file("static/app.js", text), plainContext);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.evidence[0]!.kind, "file");
  assert.match(findings[0]!.message, /Inline source map/);
});

test("a sourceMappingURL comment pointing at an unshipped file is not a finding", () => {
  const text = `console.log(1);\n//# sourceMappingURL=app.js.map\n`;
  const findings = sourceMapPublished.check(file("static/app.js", text), plainContext);
  assert.equal(findings.length, 0);
});
