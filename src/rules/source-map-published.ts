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
 *
 * In an npm package tarball the question is whose source it is. Open-source
 * packages ship maps on purpose and their source is public already: those
 * are info. A package without an open-source license that ships a map with
 * `sourcesContent` publishes its source (the Claude Code CLI, March 2026):
 * high. Without `sourcesContent` such a map gives names and structure only:
 * medium confidence. Declaration maps (`.d.ts.map`) map types to source
 * file names and are not reported in a package.
 */
import type { Finding } from "../index.ts";
import { lineColumn } from "../scan/text.ts";
import { helpUri, type Rule, type RuleContext } from "./types.ts";

/** SPDX identifiers of open-source licenses, as package.json `license` uses them. */
const OPEN_SOURCE_LICENSE = /^(?:MIT(?:-0)?|ISC|0BSD|Apache-[\d.]+|BSD-[\w.-]+|MPL-[\d.]+|L?GPL-[\w.+-]+|AGPL-[\w.+-]+|EPL-[\d.]+|EUPL-[\d.]+|CDDL-[\d.]+|CC0-1\.0|CC-BY-[\w.-]+|Unlicense|BlueOak-[\d.]+|Zlib|Artistic-[\d.]+|Python-[\d.]+|PSF-[\d.]+|BSL-1\.0|OFL-[\d.]+|WTFPL|MS-PL|PostgreSQL|Unicode-[\w.-]+)$/i;

/** Whether every license in an SPDX expression ("MIT OR Apache-2.0") is open source. */
export function isOpenSourceLicense(license: string | null): boolean {
  if (license === null) return false;
  const ids = license.replace(/[()]/g, " ").split(/\s+(?:OR|AND)\s+/i).map((part) => part.split(/\s+WITH\s+/i)[0]!.trim()).filter(Boolean);
  return ids.length > 0 && ids.every((id) => OPEN_SOURCE_LICENSE.test(id));
}

const DECLARATION_MAP = /\.d\.[mc]?ts\.map$/i;
const EMBEDS_SOURCE = /"sourcesContent"\s*:\s*\[\s*"/;

/** Severity and confidence of a shipped `.map` file, given where it ships. */
function mapVerdict(file: { relativePath: string; text: string }, context: RuleContext): Pick<Finding, "severity" | "confidence"> | null {
  const embeds = EMBEDS_SOURCE.test(file.text);
  if (context.npmPackage === undefined) return { severity: "high", confidence: "high" };
  if (DECLARATION_MAP.test(file.relativePath)) return null;
  if (isOpenSourceLicense(context.npmPackage.license)) return { severity: "info", confidence: "high" };
  return embeds ? { severity: "high", confidence: "high" } : { severity: "high", confidence: "medium" };
}

const INLINE_MAP = /\/\/[#@]\s*sourceMappingURL=data:application\/json[^\n]*/g;

export const sourceMapPublished: Rule = {
  id: "artifact/source-map-published",
  defaultSeverity: "high",
  defaultConfidence: "high",

  check(file, context) {
    const findings: Finding[] = [];

    if (file.relativePath.endsWith(".map")) {
      const verdict = mapVerdict(file, context);
      if (verdict === null) return findings;
      findings.push({
        ruleId: sourceMapPublished.id,
        layer: "artifact",
        ...verdict,
        // sourcesContent is the original source verbatim, not just names and positions.
        message: EMBEDS_SOURCE.test(file.text)
          ? `Source map shipped with the original source embedded (sourcesContent): ${file.relativePath}`
          : `Source map shipped: ${file.relativePath}`,
        evidence: [{ kind: "file", path: file.relativePath }],
        remediation: context.npmPackage === undefined
          ? "Disable production browser source maps, or upload them to your error tracker and delete them from the deploy."
          : "Leave *.map out of the package (`files` in package.json or .npmignore), or build the maps without sourcesContent.",
        helpUri: helpUri(sourceMapPublished.id),
      });
      return findings;
    }

    const openSource = context.npmPackage !== undefined && isOpenSourceLicense(context.npmPackage.license);
    for (const match of file.text.matchAll(INLINE_MAP)) {
      const { line, column } = lineColumn(file.text, match.index);
      findings.push({
        ruleId: sourceMapPublished.id,
        layer: "artifact",
        severity: openSource ? "info" : "high",
        confidence: "high",
        message: `Inline source map embedded in ${file.relativePath}`,
        // Only the scheme prefix travels; the base64 payload is the whole source.
        evidence: [{ kind: "file", path: file.relativePath, line, column, excerpt: `${match[0].slice(0, 44)}…` }],
        remediation: "Build with source maps off, or emit them as separate files that are not deployed.",
        helpUri: helpUri(sourceMapPublished.id),
      });
    }

    return findings;
  },
};
