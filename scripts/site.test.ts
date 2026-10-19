import assert from "node:assert/strict";
import test from "node:test";

import { rewriteLink, ruleSections, slug } from "./site.ts";

test("site: GitHub-style heading anchors, so links written for GitHub keep working", () => {
  assert.equal(slug("artifact/secret-like-string"), "artifactsecret-like-string");
  assert.equal(slug("surface (layer 3)"), "surface-layer-3");
  assert.equal(slug("Leave reverse engineers empty-handed"), "leave-reverse-engineers-empty-handed");
});

test("site: links between documented files map to site paths; everything else points at GitHub", () => {
  assert.equal(rewriteLink("docs/rules.md#layer-3-surface", "README.md", ""), "rules/#layer-3-surface");
  assert.equal(rewriteLink("configuration.md", "docs/rules.md", "rules"), "../configuration/");
  assert.equal(rewriteLink("../../docs/corpus.md", "experiments/rea/README.md", "rea"), "../corpus/");
  assert.equal(rewriteLink("docs/assets/banner.svg", "README.md", ""), "assets/banner.svg");
  assert.equal(rewriteLink("CONTRIBUTING.md", "README.md", ""), "https://github.com/inviy/evershield/blob/main/CONTRIBUTING.md");
  assert.equal(rewriteLink("https://example.com/x", "README.md", ""), "https://example.com/x");
  assert.equal(rewriteLink("#why", "README.md", ""), "#why");
});

test("site: every rule section becomes its own page and stops at the next heading", () => {
  const sections = ruleSections("## Layer 1\n\n### artifact/a-rule\n\nA.\n\n### artifact/b-rule\n\nB.\n\n## Adapters\n\nX.\n");
  assert.deepEqual(sections.map((s) => s.id), ["artifact/a-rule", "artifact/b-rule"]);
  assert.ok(!sections[1]!.markdown.includes("Adapters"));
});
