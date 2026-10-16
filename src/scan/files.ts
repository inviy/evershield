import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";

import type { Adapter } from "./adapters.ts";

/** One text file inside the artifact, as rules see it. */
export interface ScannedFile {
  /** Absolute path on disk. */
  absolutePath: string;
  /** Path relative to the scan root, with forward slashes. Used in reports. */
  relativePath: string;
  text: string;
}

export interface CollectOptions {
  /** Files larger than this are skipped; bundles rarely exceed it and maps can be huge. */
  maxBytes?: number;
}

const DEFAULT_MAX_BYTES = 25 * 1024 * 1024;
const ALWAYS_SKIP_DIRS = new Set(["node_modules", ".git"]);

/** Cheap binary check: a NUL byte in the first 8 KiB means not text. */
function isProbablyBinary(buffer: Buffer): boolean {
  const end = Math.min(buffer.length, 8192);
  for (let i = 0; i < end; i += 1) {
    if (buffer[i] === 0) return true;
  }
  return false;
}

export function toPosix(relative: string): string {
  return relative.split(path.sep).join("/");
}

/** Walk the root, keep what the adapter says the browser receives, read as UTF-8. */
export async function collectFiles(
  root: string,
  adapter: Adapter,
  options: CollectOptions = {},
): Promise<ScannedFile[]> {
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const entries = await readdir(root, { recursive: true, withFileTypes: true });
  const files: ScannedFile[] = [];

  for (const entry of entries) {
    if (!entry.isFile()) continue;
    const absolutePath = path.join(entry.parentPath, entry.name);
    const relativePath = toPosix(path.relative(root, absolutePath));
    if (relativePath.split("/").some((segment) => ALWAYS_SKIP_DIRS.has(segment))) continue;
    if (!adapter.includes(relativePath)) continue;

    const info = await stat(absolutePath);
    if (info.size === 0 || info.size > maxBytes) continue;

    const buffer = await readFile(absolutePath);
    if (isProbablyBinary(buffer)) continue;

    files.push({ absolutePath, relativePath, text: buffer.toString("utf8") });
  }

  files.sort((a, b) => (a.relativePath < b.relativePath ? -1 : 1));
  return files;
}
