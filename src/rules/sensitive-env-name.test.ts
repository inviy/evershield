import assert from "node:assert/strict";
import test from "node:test";

import { file, plainContext } from "../test-support.ts";
import { sensitiveEnvName } from "./sensitive-env-name.ts";

const check = (text: string) => sensitiveEnvName.check(file("static/app.js", text), plainContext);

test("a server-only name with an adjacent literal is high/medium and redacted", () => {
  const findings = check(`{"SUPABASE_SERVICE_ROLE_KEY":"abcdefgh12345678"}`);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.severity, "high");
  assert.equal(findings[0]!.confidence, "medium");
  assert.ok(!JSON.stringify(findings).includes("abcdefgh12345678"));
});

test("a bare server-only name is low/low", () => {
  const findings = check(`throw new Error("DATABASE_URL is required")`);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.severity, "low");
  assert.equal(findings[0]!.confidence, "low");
});

test("auth vocabulary without a secret-shaped value is not a finding", () => {
  const clean = [
    // supabase-js auth event enum, as bundled
    `PASSWORD_RECOVERY:"PASSWORD_RECOVERY"`,
    `if (event === "PASSWORD_RECOVERY") {}`,
    `const MIN_PASSWORD_LENGTH = 8;`,
    `params.set("ACCESS_TOKEN", token)`,
    `REFRESH_TOKEN: "refresh"`,
  ];
  for (const text of clean) {
    assert.equal(check(text).length, 0, text);
  }
});

test("framework-public names and unrelated names are not findings", () => {
  const clean = [
    `NEXT_PUBLIC_WIDGET_SECRET = "abcdefgh12345678"`,
    `VITE_ACCESS_TOKEN_TTL = "3600000000"`,
    `const SUPABASE_ANON_KEY = "x";`,
    `const theme = "SECRETARY";`,
  ];
  for (const text of clean) {
    assert.equal(check(text).length, 0, text);
  }
});
