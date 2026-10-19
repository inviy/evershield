/**
 * Helpers for tests. Fake credentials are assembled at runtime so the
 * repository never contains a string shaped like a real secret; that keeps
 * secret scanners quiet about evershield's own source.
 */
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { plainAdapter } from "./scan/adapters.ts";
import type { ScannedFile } from "./scan/files.ts";
import type { RuleContext } from "./rules/types.ts";

export function file(relativePath: string, text: string): ScannedFile {
  return { absolutePath: `/virtual/${relativePath}`, relativePath, text };
}

export const plainContext: RuleContext = { adapter: plainAdapter, shippedPaths: new Set() };

export const fake = {
  awsAccessKeyId: () => ["AKIA", "IOSFODNN7EXAMPLE"].join(""),
  anthropicKey: () => ["sk", "ant", "api03", "Q".repeat(40)].join("-"),
  openAiKey: () => ["sk", "proj", "R".repeat(40)].join("-"),
  stripeLiveKey: () => ["sk", "live", "S".repeat(28)].join("_"),
  stripePublishableKey: () => ["pk", "live", "P".repeat(28)].join("_"),
  googleKey: () => `AIza${"G".repeat(35)}`,
  privateKeyBlock: () => ["-----BEGIN ", "PRIVATE KEY-----\\n", "MIIEv", "Q".repeat(64), "\\n-----END ", "PRIVATE KEY-----"].join(""),
  jwt: (payload: Record<string, unknown>) => {
    const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
    return `${encode({ alg: "HS256", typ: "JWT" })}.${encode(payload)}.${"s".repeat(43)}`;
  },
  highEntropy: () => "Zq8vN2pL5tR9wX3yB7cD1fG4hJ6kM0nPaE",
};

/** Create a temp directory populated with files, run `body`, then delete it. */
export async function withTempDir(
  files: Record<string, string>,
  body: (root: string) => Promise<void>,
): Promise<void> {
  const root = await mkdtemp(path.join(tmpdir(), "evershield-"));
  try {
    for (const [relativePath, text] of Object.entries(files)) {
      const absolutePath = path.join(root, relativePath);
      await mkdir(path.dirname(absolutePath), { recursive: true });
      await writeFile(absolutePath, text);
    }
    await body(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}
