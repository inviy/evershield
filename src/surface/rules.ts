/**
 * Surface rules. Each inspects one page observed as every identity.
 *
 * - surface/expected-absent-present: the operator said identity X must not
 *   receive text T (or selector S) on this page, and it is somewhere in X's
 *   DOM, attributes, inline scripts or storage. High/high: the operator's
 *   own contract.
 * - surface/hidden-higher-tier-content: text the top tier can see is present
 *   for a lower tier but hidden from it (display:none, blur, clipped, in a
 *   data attribute, inline script or storage). The paywall is cosmetic.
 *   High/high: the same text, visible to one tier and hidden in another's
 *   page, is not a coincidence.
 * - surface/obscured-content: a lower tier's page blurs or makes transparent
 *   real-looking text. Blur is how UIs fake a paywall; legitimate hidden UI
 *   (menus, tabs) uses display or visibility instead. High/medium: the text
 *   may be a decoy, which the rule cannot always tell.
 *
 * Tabs, menus and dialogs hidden for every tier never fire the differential
 * rule, because it requires the top tier to see the text.
 */
import type { Confidence, Finding, Severity } from "../index.ts";
import type { PageObservation, SurfaceSnapshot } from "./types.ts";

export interface SurfaceRule {
  id: string;
  defaultSeverity: Severity;
  defaultConfidence: Confidence;
  check(observation: PageObservation): Finding[];
}

const RULES_DOC = "https://github.com/inviy/evershield/blob/main/docs/rules.md";
const help = (id: string) => `${RULES_DOC}#${id.replace("/", "")}`;

function excerpt(text: string, max = 80): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

function usable(snapshot: SurfaceSnapshot | undefined): snapshot is SurfaceSnapshot {
  return snapshot !== undefined && snapshot.error === undefined && snapshot.status < 400;
}

interface Hit {
  selector: string;
  where: string;
  text: string;
}

/** Find `needle` in everything the identity received, hidden or not. */
function locate(snapshot: SurfaceSnapshot, needle: string, options: { hiddenOnly: boolean }): Hit | undefined {
  for (const block of snapshot.blocks) {
    if (options.hiddenOnly && block.hiddenBy === null) continue;
    if (block.text.includes(needle)) {
      return { selector: block.selector, where: block.hiddenBy === null ? "visible text" : `text hidden by ${block.hiddenBy}`, text: block.text };
    }
  }
  for (const attribute of snapshot.attributes) {
    if (attribute.value.includes(needle)) return { selector: `${attribute.selector}[${attribute.name}]`, where: `attribute ${attribute.name}`, text: attribute.value };
  }
  for (const script of snapshot.scripts) {
    if (script.text.includes(needle)) return { selector: script.selector, where: "inline script", text: needle };
  }
  for (const entry of snapshot.storage) {
    if (entry.value.includes(needle) || entry.key.includes(needle)) {
      return { selector: `${entry.area}[${JSON.stringify(entry.key)}]`, where: entry.area, text: needle };
    }
  }
  return undefined;
}

export const expectedAbsentPresent: SurfaceRule = {
  id: "surface/expected-absent-present",
  defaultSeverity: "high",
  defaultConfidence: "high",
  check(observation) {
    const findings: Finding[] = [];
    for (const [identity, expectation] of Object.entries(observation.page.expect ?? {})) {
      const snapshot = observation.snapshots.get(identity);
      if (!usable(snapshot)) continue;
      for (const text of expectation.absentText ?? []) {
        const hit = locate(snapshot, text, { hiddenOnly: false });
        if (hit === undefined) continue;
        findings.push({
          ruleId: expectedAbsentPresent.id,
          layer: "surface",
          severity: "high",
          confidence: "high",
          message: `${observation.page.path} gives ${identity} "${excerpt(text, 40)}" (${hit.where}), which the config says it must not receive`,
          evidence: [{ kind: "dom", url: observation.url, selector: hit.selector, identity, excerpt: excerpt(hit.text) }],
          remediation: "Do not send this content to this tier at all: render it on the server only for entitled users. Hiding it in the page is not a boundary.",
          helpUri: help(expectedAbsentPresent.id),
        });
      }
      for (const match of snapshot.selectorMatches) {
        if (match.text === "(invalid selector)") continue;
        findings.push({
          ruleId: expectedAbsentPresent.id,
          layer: "surface",
          severity: "high",
          confidence: "high",
          message: `${observation.page.path} renders "${match.selector}" for ${identity}, which the config says must match nothing`,
          evidence: [{ kind: "dom", url: observation.url, selector: match.selector, identity, excerpt: excerpt(match.text) }],
          remediation: "Do not render this element for this tier; if it needs a placeholder, render placeholder content, not the real value.",
          helpUri: help(expectedAbsentPresent.id),
        });
      }
    }
    return findings;
  },
};

export const hiddenHigherTierContent: SurfaceRule = {
  id: "surface/hidden-higher-tier-content",
  defaultSeverity: "high",
  defaultConfidence: "high",
  check(observation) {
    const findings: Finding[] = [];
    const topName = observation.tiers[observation.tiers.length - 1];
    const top = topName === undefined ? undefined : observation.snapshots.get(topName);
    if (!usable(top) || observation.tiers.length < 2) return findings;

    const topVisible = [...new Set(top.blocks.filter((block) => block.hiddenBy === null && block.text.length >= observation.minTextLength).map((block) => block.text))];

    for (const identity of observation.tiers.slice(0, -1)) {
      const snapshot = observation.snapshots.get(identity);
      if (!usable(snapshot)) continue;
      const visibleHere = snapshot.blocks.filter((block) => block.hiddenBy === null).map((block) => block.text);
      let reported = 0;
      for (const text of topVisible) {
        // Visible to this tier too: shared content, not a leak.
        if (visibleHere.some((visible) => visible.includes(text))) continue;
        const hit = locate(snapshot, text, { hiddenOnly: true });
        if (hit === undefined) continue;
        reported += 1;
        if (reported > 20) break;
        findings.push({
          ruleId: hiddenHigherTierContent.id,
          layer: "surface",
          severity: "high",
          confidence: "high",
          message: `${observation.page.path}: "${excerpt(text, 40)}" is visible to ${topName} and present but hidden for ${identity} (${hit.where})`,
          evidence: [{ kind: "dom", url: observation.url, selector: hit.selector, identity, excerpt: excerpt(text) }],
          remediation: `Anyone on the ${identity} tier can read this in DevTools. Leave it out of the ${identity} page (server-render a placeholder) instead of hiding it.`,
          helpUri: help(hiddenHigherTierContent.id),
        });
      }
    }
    return findings;
  },
};

/** Text that is obviously a decoy: masks, lorem ipsum, a single repeated character. */
const PLACEHOLDER = /^(?:[\sxX*•●▒█#?·._,\-–—0]+|lorem ipsum.*|(.)\1+)$/i;

export const obscuredContent: SurfaceRule = {
  id: "surface/obscured-content",
  defaultSeverity: "high",
  defaultConfidence: "medium",
  check(observation) {
    const findings: Finding[] = [];
    // With one identity there is nothing more privileged to protect; still
    // check it, since blur on any audited page is the classic fake paywall.
    const lower = observation.tiers.length > 1 ? observation.tiers.slice(0, -1) : observation.tiers;
    for (const identity of lower) {
      const snapshot = observation.snapshots.get(identity);
      if (!usable(snapshot)) continue;
      const obscured = snapshot.blocks.filter(
        (block) => (block.hiddenBy === "blur" || block.hiddenBy === "transparent-text") && block.text.length >= 3 && !PLACEHOLDER.test(block.text),
      );
      if (obscured.length === 0) continue;
      findings.push({
        ruleId: obscuredContent.id,
        layer: "surface",
        severity: "high",
        confidence: "medium",
        message: `${observation.page.path} shows ${identity} ${obscured.length} blurred or transparent text element(s); the text is readable in the DOM`,
        evidence: obscured.slice(0, 10).map((block) => ({ kind: "dom" as const, url: observation.url, selector: block.selector, identity, excerpt: excerpt(block.text) })),
        remediation: `Render placeholder text (e.g. "●●●") behind the blur for ${identity}, or nothing; send the real values only to tiers that may see them.`,
        helpUri: help(obscuredContent.id),
      });
    }
    return findings;
  },
};

export const SURFACE_RULES: readonly SurfaceRule[] = [expectedAbsentPresent, hiddenHigherTierContent, obscuredContent];
