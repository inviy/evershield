/** Text helpers shared by rules: positions, redaction and entropy. */

export interface LineColumn {
  line: number;
  column: number;
}

/** 1-based line and column for a character offset. */
export function lineColumn(text: string, offset: number): LineColumn {
  let line = 1;
  let lastBreak = -1;
  for (let i = 0; i < offset && i < text.length; i += 1) {
    if (text.charCodeAt(i) === 10) {
      line += 1;
      lastBreak = i;
    }
  }
  return { line, column: offset - lastBreak };
}

/**
 * Redact a matched value so reports never reproduce the secret they found.
 * Keeps enough of each end to recognise the value in the source.
 */
export function redact(value: string, keep = 4): string {
  if (value.length <= keep * 2 + 1) return "*".repeat(value.length);
  return `${value.slice(0, keep)}…${value.slice(-keep)} (${value.length} chars)`;
}

/** Shannon entropy in bits per character. ~4.5 is random base64, ~3 is prose. */
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const PLACEHOLDER = /^(x+|0+|\*+|your[_-]|changeme|placeholder|example|dummy|test|sample|<)/i;

/** Values humans type as stand-ins; never worth a finding on their own. */
export function looksLikePlaceholder(value: string): boolean {
  return PLACEHOLDER.test(value) || /^(.)\1+$/.test(value);
}

/** Decode a JWT payload without verifying it. Returns null when it is not a JWT. */
export function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const payload = parts[1];
  if (payload === undefined) return null;
  try {
    const json = Buffer.from(payload, "base64url").toString("utf8");
    const parsed: unknown = JSON.parse(json);
    return typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}
