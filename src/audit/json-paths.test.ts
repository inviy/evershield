import assert from "node:assert/strict";
import test from "node:test";

import { deepEqual, flattenPaths, isUnder, leafName, presentPaths } from "./json-paths.ts";

test("flattenPaths collapses array indices and keeps the first sample", () => {
  const paths = flattenPaths({ a: { b: [{ c: 1 }, { c: 2 }] }, d: null });
  assert.deepEqual([...paths.keys()], ["a", "a.b", "a.b[]", "a.b[].c", "d"]);
  assert.equal(paths.get("a.b[].c"), 1);
});

test("presentPaths drops null and undefined values", () => {
  const present = presentPaths({ perplexity: null, burstiness: undefined, score: 0, detail: { x: "" } });
  assert.deepEqual([...present.keys()], ["score", "detail", "detail.x"]);
});

test("leafName and isUnder handle nesting and arrays", () => {
  assert.equal(leafName("report.items[].cost"), "cost");
  assert.equal(leafName("items[]"), "items");
  assert.ok(isUnder("report.detail.text", "report.detail"));
  assert.ok(isUnder("items[].id", "items"));
  assert.ok(!isUnder("reporting", "report"));
});

test("deepEqual is structural and key-order independent", () => {
  assert.ok(deepEqual({ a: 1, b: [1, { c: 2 }] }, { b: [1, { c: 2 }], a: 1 }));
  assert.ok(!deepEqual({ a: 1 }, { a: 1, b: 2 }));
  assert.ok(!deepEqual([1, 2], [2, 1]));
});
