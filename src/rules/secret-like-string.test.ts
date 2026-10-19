import assert from "node:assert/strict";
import test from "node:test";

import { fake, file, plainContext } from "../test-support.ts";
import { secretLikeString } from "./secret-like-string.ts";

const check = (text: string, name = "static/chunks/app.js") => secretLikeString.check(file(name, text), plainContext);

test("provider-format keys are critical with high confidence and never printed in full", () => {
  const cases: Array<[string, string]> = [
    ["AWS access key ID", fake.awsAccessKeyId()],
    ["Anthropic API key", fake.anthropicKey()],
    ["OpenAI API key", fake.openAiKey()],
    ["Stripe secret key", fake.stripeLiveKey()],
    ["Private key block", fake.privateKeyBlock()],
  ];
  for (const [label, secret] of cases) {
    const findings = check(`const k = "${secret}";`);
    assert.equal(findings.length, 1, label);
    const finding = findings[0]!;
    assert.equal(finding.severity, "critical", label);
    assert.equal(finding.confidence, "high", label);
    assert.match(finding.message, new RegExp(label), label);
    assert.ok(!JSON.stringify(finding).includes(secret), `${label} must be redacted`);
  }
});

test("an Anthropic key is reported once, not also as an OpenAI key", () => {
  const findings = check(`"${fake.anthropicKey()}"`);
  assert.equal(findings.length, 1);
  assert.match(findings[0]!.message, /Anthropic/);
});

test("Supabase service_role JWT is critical; anon JWT is not a finding", () => {
  const service = check(`const key = "${fake.jwt({ role: "service_role", iss: "supabase" })}";`);
  assert.equal(service.length, 1);
  assert.equal(service[0]!.severity, "critical");
  assert.match(service[0]!.message, /service_role/);

  const anon = check(`const key = "${fake.jwt({ role: "anon", iss: "supabase" })}";`);
  assert.equal(anon.length, 0);
});

test("a JWT without a role is reported at low severity", () => {
  const findings = check(`"${fake.jwt({ sub: "123", exp: 1 })}"`);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.severity, "low");
  assert.equal(findings[0]!.confidence, "medium");
});

test("named high-entropy values are high severity but low confidence", () => {
  const findings = check(`const config = { apiKey: "${fake.highEntropy()}" };`);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.severity, "high");
  assert.equal(findings[0]!.confidence, "low");
  assert.match(findings[0]!.evidence[0]!.excerpt ?? "", /apiKey = Zq8v…/);
});

test("public-by-design and placeholder values are not findings", () => {
  const clean = [
    `apiKey: "your_api_key_here_ok"`,
    `password: "aaaaaaaaaaaaaaaaaaaa"`,
    `NEXT_PUBLIC_API_KEY: "${fake.highEntropy()}"`,
    `VITE_TOKEN = "${fake.highEntropy()}"`,
    `const publishable = "${fake.stripePublishableKey()}";`,
    // design tokens and paths: long and varied, not credentials
    `{ token: "--passit-color-primary-hover" }`,
    `token: "spacing.large.default.value"`,
    `authToken: "./tokens/current/active.json"`,
  ];
  for (const text of clean) {
    assert.equal(check(text).length, 0, text);
  }
});

test("Google browser keys are medium severity with a restriction note", () => {
  const findings = check(`key: "${fake.googleKey()}"`);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.severity, "medium");
  assert.match(findings[0]!.remediation ?? "", /restricted/);
});

test("the same secret in one file is reported once", () => {
  const secret = fake.awsAccessKeyId();
  const findings = check(`"${secret}" "${secret}" "${secret}"`);
  assert.equal(findings.length, 1);
});

test("PEM-parsing code that names the header without a key body is not a finding", () => {
  // From @auth0/auth0-spa-js 2.28.4 (bundled jose).
  const header = ["-----BEGIN", " PRIVATE KEY-----"].join("");
  const code = `if("string"!=typeof e||0!==e.indexOf("${header}"))throw new TypeError('"pkcs8" must be PKCS#8 formatted string');`;
  assert.deepEqual(check(code), []);
  assert.deepEqual(check(`e.replace(/(?:-----(?:BEGIN|END) PRIVATE KEY-----|\\s)/g,"")`), []);
});

test("dotted identifiers are storage keys, not credentials", () => {
  // From @auth0/auth0-spa-js 2.28.4.
  assert.deepEqual(check(`const GET_TOKEN_SILENTLY_LOCK_KEY = 'auth0.lock.getTokenSilently';`), []);
  assert.equal(check(`const apiKey = "Zq8vN2pL.5tR9wX3yB7cD1fG4hJ6kM0nPaE";`).length, 1);
});
