import assert from "node:assert/strict";
import test from "node:test";

import { run } from "./cli.ts";
import { VERSION } from "./index.ts";

test("prints help with no arguments and exits 0", () => {
  const result = run([]);
  assert.equal(result.code, 0);
  assert.match(result.stdout, /Usage:/);
  assert.equal(result.stderr, "");
});

test("prints the version", () => {
  for (const flag of ["--version", "-v", "version"]) {
    const result = run([flag]);
    assert.equal(result.code, 0);
    assert.equal(result.stdout, `${VERSION}\n`);
  }
});

test("scan without a target is a usage error", () => {
  const result = run(["scan"]);
  assert.equal(result.code, 2);
  assert.match(result.stderr, /missing <dir>/);
});

test("scan with a target reports not implemented for now", () => {
  const result = run(["scan", "./dist"]);
  assert.equal(result.code, 2);
  assert.match(result.stderr, /not implemented/);
});

test("unknown command exits 2 and shows help", () => {
  const result = run(["frobnicate"]);
  assert.equal(result.code, 2);
  assert.match(result.stderr, /unknown command "frobnicate"/);
  assert.match(result.stderr, /Usage:/);
});
