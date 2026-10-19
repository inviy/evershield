import assert from "node:assert/strict";
import test from "node:test";

import { expectedAbsentPresent, hiddenHigherTierContent, obscuredContent } from "./rules.ts";
import type { PageConfig, PageObservation, SurfaceSnapshot, TextBlock } from "./types.ts";

function snap(identity: string, blocks: TextBlock[], extra: Partial<SurfaceSnapshot> = {}): SurfaceSnapshot {
  return {
    identity,
    url: "https://app.test/report",
    finalUrl: "https://app.test/report",
    status: 200,
    blocks,
    attributes: [],
    scripts: [],
    storage: [],
    selectorMatches: [],
    ...extra,
  };
}

function observe(page: PageConfig, ...snapshots: SurfaceSnapshot[]): PageObservation {
  return {
    page,
    url: "https://app.test/report",
    tiers: snapshots.map((snapshot) => snapshot.identity),
    snapshots: new Map(snapshots.map((snapshot) => [snapshot.identity, snapshot])),
    minTextLength: 12,
  };
}

const visible = (selector: string, text: string): TextBlock => ({ selector, text, hiddenBy: null });
const hidden = (selector: string, text: string, by: TextBlock["hiddenBy"]): TextBlock => ({ selector, text, hiddenBy: by });

test("hidden-higher-tier-content: text pro sees, hidden in free's page, is reported with how it was hidden", () => {
  const findings = hiddenHigherTierContent.check(
    observe(
      { path: "/report" },
      snap("free", [visible("h1", "Your report summary"), hidden(".pro > p", "Burstiness score 0.82 (human-like)", "blur")]),
      snap("pro", [visible("h1", "Your report summary"), visible(".pro > p", "Burstiness score 0.82 (human-like)")]),
    ),
  );
  assert.equal(findings.length, 1);
  assert.match(findings[0]!.message, /hidden for free \(text hidden by blur\)/);
  assert.equal(findings[0]!.evidence[0]?.kind === "dom" && findings[0]!.evidence[0].identity, "free");
});

test("hidden-higher-tier-content: also finds the text in data attributes, inline scripts and storage", () => {
  const secret = "Detailed rubric: structure 18/20";
  const pro = snap("pro", [visible("p", secret)]);
  for (const extra of [
    { attributes: [{ selector: "div", name: "data-detail", value: secret }] },
    { scripts: [{ selector: "script#__NEXT_DATA__", text: `{"props":{"detail":"${secret}"}}` }] },
    { storage: [{ area: "sessionStorage" as const, key: "result", value: `{"detail":"${secret}"}` }] },
  ]) {
    const findings = hiddenHigherTierContent.check(observe({ path: "/report" }, snap("free", [], extra), pro));
    assert.equal(findings.length, 1, JSON.stringify(extra));
  }
});

test("hidden-higher-tier-content: tabs and menus hidden for every tier, or shared visible text, never fire", () => {
  const findings = hiddenHigherTierContent.check(
    observe(
      { path: "/report" },
      snap("free", [hidden("nav li", "Account settings menu", "display"), visible("p", "Shared paragraph for everyone")]),
      snap("pro", [hidden("nav li", "Account settings menu", "display"), visible("p", "Shared paragraph for everyone")]),
    ),
  );
  assert.deepEqual(findings, []);
});

test("hidden-higher-tier-content: text a lower tier simply does not receive is the correct fix, not a finding", () => {
  const findings = hiddenHigherTierContent.check(
    observe({ path: "/report" }, snap("free", [visible("p", "Upgrade to see the details")]), snap("pro", [visible("p", "Burstiness score 0.82")])),
  );
  assert.deepEqual(findings, []);
});

test("hidden-higher-tier-content: short strings below minTextLength are not compared", () => {
  const findings = hiddenHigherTierContent.check(
    observe({ path: "/report" }, snap("free", [hidden("span", "0.82", "blur")]), snap("pro", [visible("span", "0.82")])),
  );
  assert.deepEqual(findings, []);
});

test("obscured-content: blurred real text in a lower tier fires once per page; placeholders do not", () => {
  const findings = obscuredContent.check(
    observe(
      { path: "/report" },
      snap("free", [hidden("p:nth-of-type(1)", "Perplexity 41.2", "blur"), hidden("p:nth-of-type(2)", "Burstiness 0.82", "transparent-text"), hidden("p:nth-of-type(3)", "●●●●", "blur"), hidden("p:nth-of-type(4)", "Lorem ipsum dolor", "blur")]),
      snap("pro", [visible("p", "Perplexity 41.2")]),
    ),
  );
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.confidence, "medium");
  assert.equal(findings[0]!.evidence.length, 2);
});

test("obscured-content: display:none (menus, dialogs) is not obscuring", () => {
  const findings = obscuredContent.check(observe({ path: "/" }, snap("free", [hidden("dialog p", "Delete your account?", "display")]), snap("pro", [])));
  assert.deepEqual(findings, []);
});

test("expected-absent-present: configured text and selectors, hidden or not, are high/high", () => {
  const page: PageConfig = { path: "/report", expect: { free: { absentText: ["perplexity"], absentSelectors: ["[data-pro]"] } } };
  const findings = expectedAbsentPresent.check(
    observe(
      page,
      snap("free", [], {
        storage: [{ area: "localStorage", key: "passit_result", value: '{"perplexity":41.2}' }],
        selectorMatches: [{ selector: "[data-pro]", text: "Pro metrics" }, { selector: "a[", text: "(invalid selector)" }],
      }),
      snap("pro", []),
    ),
  );
  assert.equal(findings.length, 2);
  assert.ok(findings.every((finding) => finding.severity === "high" && finding.confidence === "high"));
  assert.match(findings[0]!.message, /localStorage/);
});

test("snapshots that failed or returned an error status are skipped", () => {
  const page: PageConfig = { path: "/report", expect: { free: { absentText: ["x"] } } };
  const findings = [
    ...expectedAbsentPresent.check(observe(page, snap("free", [visible("p", "x")], { status: 500 }), snap("pro", []))),
    ...obscuredContent.check(observe(page, snap("free", [hidden("p", "Perplexity 41.2", "blur")], { error: "timeout" }), snap("pro", []))),
  ];
  assert.deepEqual(findings, []);
});
