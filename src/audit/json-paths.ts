/**
 * Flatten a JSON value into dot paths. Array indices collapse to `[]` so two
 * responses with different list lengths still compare field by field; the
 * first sample seen for a path is kept for evidence.
 *
 *   { a: { b: [ { c: 1 }, { c: 2 } ] } }  →  "a", "a.b", "a.b[]", "a.b[].c"
 */

export interface PathSample {
  path: string;
  value: unknown;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function flattenPaths(value: unknown): Map<string, unknown> {
  const out = new Map<string, unknown>();
  const visit = (node: unknown, path: string): void => {
    if (path !== "" && !out.has(path)) out.set(path, node);
    if (Array.isArray(node)) {
      for (const item of node) visit(item, `${path}[]`);
    } else if (isObject(node)) {
      for (const [key, child] of Object.entries(node)) visit(child, path === "" ? key : `${path}.${key}`);
    }
  };
  visit(value, "");
  return out;
}

/** Paths whose value is neither null nor undefined: what the identity actually received. */
export function presentPaths(value: unknown): Map<string, unknown> {
  const present = new Map<string, unknown>();
  for (const [path, sample] of flattenPaths(value)) {
    if (sample !== null && sample !== undefined) present.set(path, sample);
  }
  return present;
}

/** Last segment of a path, without array markers: "a.b[].c" → "c". */
export function leafName(path: string): string {
  const segments = path.split(".");
  const last = segments[segments.length - 1] ?? path;
  return last.replace(/\[\]$/g, "");
}

/** Whether `path` is `prefix` itself or nested under it. */
export function isUnder(path: string, prefix: string): boolean {
  return path === prefix || path.startsWith(`${prefix}.`) || path.startsWith(`${prefix}[]`);
}

/** Structural equality for parsed JSON. */
export function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((item, index) => deepEqual(item, b[index]));
  }
  if (isObject(a) && isObject(b)) {
    const keysA = Object.keys(a).sort();
    const keysB = Object.keys(b).sort();
    return keysA.length === keysB.length && keysA.every((key, index) => key === keysB[index] && deepEqual(a[key], b[key]));
  }
  return false;
}
