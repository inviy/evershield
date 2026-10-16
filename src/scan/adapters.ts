import { access } from "node:fs/promises";
import path from "node:path";

/**
 * An adapter knows which files in a build directory the browser actually
 * receives, and which environment variable prefixes the framework treats as
 * public by design. Every rule must still work with the plain adapter.
 */
export interface Adapter {
  name: "nextjs" | "plain";
  /** Whether a root-relative POSIX path is shipped to the browser. */
  includes(relativePath: string): boolean;
  /** Env var prefixes that are public by framework contract (never a finding by name). */
  publicEnvPrefixes: readonly string[];
}

const COMMON_PUBLIC_PREFIXES = [
  "NEXT_PUBLIC_",
  "VITE_",
  "PUBLIC_",
  "REACT_APP_",
  "NUXT_PUBLIC_",
  "EXPO_PUBLIC_",
  "GATSBY_",
  "VUE_APP_",
] as const;

const TEXT_EXTENSIONS = new Set([
  ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
  ".map", ".html", ".htm", ".css", ".json", ".txt", ".xml", ".svg",
  ".rsc", ".body", ".webmanifest",
]);

function hasTextExtension(relativePath: string): boolean {
  return TEXT_EXTENSIONS.has(path.posix.extname(relativePath).toLowerCase());
}

/** Any directory of built files: everything text-like is assumed shipped. */
export const plainAdapter: Adapter = {
  name: "plain",
  includes: hasTextExtension,
  publicEnvPrefixes: COMMON_PUBLIC_PREFIXES,
};

/**
 * Next.js `.next/` output. Only `static/` reaches the browser as-is;
 * `server/` holds server bundles that never leave the host, except the
 * prerendered documents (`.html`, `.rsc`, `.body`) that are served verbatim.
 * `cache/`, traces and manifests are build-time only.
 */
export const nextjsAdapter: Adapter = {
  name: "nextjs",
  includes(relativePath) {
    if (!hasTextExtension(relativePath)) return false;
    if (relativePath.startsWith("static/")) return true;
    if (relativePath.startsWith("server/")) {
      const ext = path.posix.extname(relativePath).toLowerCase();
      return ext === ".html" || ext === ".rsc" || ext === ".body";
    }
    return false;
  },
  publicEnvPrefixes: COMMON_PUBLIC_PREFIXES,
};

async function exists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

/** Pick the adapter from the directory's shape. */
export async function detectAdapter(root: string): Promise<Adapter> {
  const isNext =
    (await exists(path.join(root, "BUILD_ID"))) && (await exists(path.join(root, "static")));
  return isNext ? nextjsAdapter : plainAdapter;
}

export const ADAPTERS: Record<Adapter["name"], Adapter> = {
  nextjs: nextjsAdapter,
  plain: plainAdapter,
};
