import assert from "node:assert/strict";
import test from "node:test";

import { file, plainContext } from "../test-support.ts";
import { internalEndpoint } from "./internal-endpoint.ts";

const check = (text: string) => internalEndpoint.check(file("static/app.js", text), plainContext);

test("private IPs and internal hostnames are medium severity", () => {
  const findings = check(`fetch("http://10.0.0.5:8080/health"); fetch("https://api.payments.internal/v1");`);
  assert.equal(findings.length, 2);
  assert.ok(findings.every((finding) => finding.severity === "medium"));
  const internal = findings.find((finding) => finding.message.includes("Internal hostname"));
  assert.equal(internal?.confidence, "high");
});

test("localhost and staging hosts are low severity and low confidence", () => {
  const findings = check(`const base = "http://localhost:3000"; const s = "https://staging.example.com";`);
  assert.equal(findings.length, 2);
  assert.ok(findings.every((finding) => finding.severity === "low" && finding.confidence === "low"));
});

test("version strings and public hosts are not findings", () => {
  const clean = [
    `const version = "v10.0.0.1";`,
    `const semver = "1.10.0";`,
    `fetch("https://api.example.com/v1")`,
    `const ip = "192.168.0";`,
  ];
  for (const text of clean) {
    assert.equal(check(text).length, 0, text);
  }
});

test("bare private IPs are low/low; DOIs and longer dotted numbers are not IPs", () => {
  // three.js cites a DOI; axios documents NO_PROXY in a comment; highlight.js has a RouterOS grammar.
  assert.deepEqual(check(`// https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.7.6968&rep=rep1`), []);
  const bare = check("// `NO_PROXY=192.168.1.5` would not match");
  assert.equal(bare.length, 1);
  assert.equal(bare[0]!.severity, "low");
  assert.equal(bare[0]!.confidence, "low");
  assert.deepEqual(check(`const v = "10.300.1.1";`), []);
  const port = check(`connect("192.168.0.12:5432")`);
  assert.equal(port[0]?.severity, "medium");
});
