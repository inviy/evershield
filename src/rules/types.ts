import type { Confidence, Finding, Severity } from "../index.ts";
import type { Adapter } from "../scan/adapters.ts";
import type { ScannedFile } from "../scan/files.ts";

export interface RuleContext {
  adapter: Adapter;
  /** Every shipped file's relative path, for cross-file checks such as source map references. */
  shippedPaths: ReadonlySet<string>;
}

/**
 * A rule inspects one file and returns findings with evidence. The doc
 * comment on each rule module must state why its default severity and
 * confidence are what they are (see CONTRIBUTING.md).
 */
export interface Rule {
  id: string;
  defaultSeverity: Severity;
  defaultConfidence: Confidence;
  check(file: ScannedFile, context: RuleContext): Finding[];
}

export const RULES_DOC = "https://github.com/inviy/evershield/blob/main/docs/rules.md";

/** Rules cap findings per file so one generated bundle cannot flood a report. */
export const MAX_FINDINGS_PER_FILE = 25;

export function helpUri(ruleId: string): string {
  return `${RULES_DOC}#${ruleId.replace("/", "")}`;
}
