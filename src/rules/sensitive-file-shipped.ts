/**
 * artifact/sensitive-file-shipped
 *
 * Some files leak by being there: an `.env`, an `.npmrc`, a signing
 * keystore, an SSH key, `.git/config`, a coding-agent config. They turn up
 * in a deploy directory copied whole, in an npm tarball whose `files` list
 * was too wide, or in an app package. The path alone decides, so most kinds
 * are high confidence; `.env` and `.npmrc` are medium because they can hold
 * only public values. Severity follows what the file usually unlocks
 * (critical for a private key, medium for agent config). Content is never
 * quoted: the secret rule reports any credential inside separately.
 */
import type { Finding } from "../index.ts";
import { sensitivePath } from "../scan/sensitive-paths.ts";
import { helpUri, type Rule } from "./types.ts";

export const sensitiveFileShipped: Rule = {
  id: "artifact/sensitive-file-shipped",
  defaultSeverity: "high",
  defaultConfidence: "high",

  check(file) {
    // Archive string dumps carry a " (strings)" suffix; the entry name is what matters.
    const entry = file.relativePath.replace(/ \(strings\)$/, "");
    const info = sensitivePath(entry);
    if (info === null) return [];
    const finding: Finding = {
      ruleId: sensitiveFileShipped.id,
      layer: "artifact",
      severity: info.severity,
      confidence: info.confidence,
      message: `${entry} is ${info.kind} and ships with the artifact`,
      evidence: [{ kind: "file", path: file.relativePath }],
      remediation:
        "Remove it from the deploy or package (`files` in package.json, .npmignore, the copy step), and rotate anything it held: it may already have been fetched.",
      helpUri: helpUri(sensitiveFileShipped.id),
    };
    return [finding];
  },
};
