import assert from "node:assert/strict";
import test from "node:test";

import { fake } from "../test-support.ts";
import { decodeJwtPayload, lineColumn, looksLikePlaceholder, redact, shannonEntropy } from "./text.ts";

test("lineColumn is 1-based and counts newlines before the offset", () => {
  const text = "ab\ncde\nf";
  assert.deepEqual(lineColumn(text, 0), { line: 1, column: 1 });
  assert.deepEqual(lineColumn(text, 3), { line: 2, column: 1 });
  assert.deepEqual(lineColumn(text, 5), { line: 2, column: 3 });
  assert.deepEqual(lineColumn(text, 7), { line: 3, column: 1 });
});

test("redact keeps only the ends of a value", () => {
  assert.equal(redact("abcdefghijklmnop"), "abcd…mnop (16 chars)");
  assert.equal(redact("short"), "*****");
});

test("entropy separates random tokens from prose and repeats", () => {
  assert.ok(shannonEntropy(fake.highEntropy()) > 4);
  assert.ok(shannonEntropy("aaaaaaaaaaaaaaaa") < 0.1);
  assert.ok(shannonEntropy("the quick brown fox") < 4);
});

test("placeholders are recognised", () => {
  for (const value of ["xxxxxxxxxxxxxxxx", "your_api_key_here", "CHANGEME1234567890", "<insert-key>", "0000000000000000"]) {
    assert.ok(looksLikePlaceholder(value), value);
  }
  assert.ok(!looksLikePlaceholder(fake.highEntropy()));
});

test("decodeJwtPayload reads the payload and rejects non-JWTs", () => {
  assert.deepEqual(decodeJwtPayload(fake.jwt({ role: "anon" })), { role: "anon" });
  assert.equal(decodeJwtPayload("not.a.jwt"), null);
  assert.equal(decodeJwtPayload("eyJhbGciOiJIUzI1NiJ9"), null);
});
