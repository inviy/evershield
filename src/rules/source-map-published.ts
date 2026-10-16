/**
 * artifact/source-map-published
 *
 * A source map that the browser can fetch hands over the original source:
 * comments, file names, unminified logic. Presence of a `.map` file in the
 * shipped set, or an inline `data:` source map, is unambiguous, so confidence
 * is high. Severity is high rather than critical: it exposes logic, not a
 * credential, though it often leads to one.
 *
 * A `sourceMappingURL` comment pointing at a file that is *not* shipped
 * leaks nothing and is not reported.
 */
import type { Finding } from "../index.ts";
import { lineColumn } from "../scan/text.ts";
import { helpUri, type Rule } from "./types.ts";

const INLINE_MAP = /\/\/[#@]\s*sourceMappingURL=data:application\/json[^\n]*/g;

export const sourceMapPublished: Rule = {
  id: "artifact/source-map-published",
  defaultSeverity: "high",
  defaultConfidence: "high",

  check(file) {
    const findings: Finding[] = [];

    if (file.relativePath.endsWith(".map")) {
      findings.push({
        ruleId: sourceMapPublished.id,
        layer: "artifact",
        severity: "high",
        confidence: "high",
        message: `Source map shipped: ${file.relativePath}`,
        evidence: [{ kind: "file", path: file.relativePath }],
        remediation: "Disable production browser source maps, or upload them to your error tracker and delete them from the deploy.",
        helpUri: helpUri(sourceMapPublished.id),
      });
      return findings;
    }

    for (const match of file.text.matchAll(INLINE_MAP)) {
      const { line, column } = lineColumn(file.text, match.index);
      findings.push({
        ruleId: sourceMapPublished.id,
        layer: "artifact",
        severity: "high",
        confidence: "high",
        message: `Inline source map embedded in ${file.relativePath}`,
        evidence: [{ kind: "file", path: file.relativePath, line, column, excerpt: "//# sourceMappingURL=data:application/json;…" }],
        remediation: "Build with source maps off, or emit them as separate files that are not deployed.",
        helpUri: helpUri(sourceMapPublished.id),
      });
    }

    return findings;
  },
};
