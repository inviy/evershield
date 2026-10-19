/**
 * Layer 3: rendered-surface audit.
 *
 * The operator lists pages and identities. evershield opens each page in a
 * headless browser as each identity, waits for it to settle, and records
 * every text-bearing element with whether a person can actually see it,
 * plus `data-*` attributes, inline scripts and web storage. The rules then
 * look for data that is present but only visually hidden.
 */

export interface SurfaceIdentityConfig {
  /** Sent only to requests for `baseUrl`'s origin. Credential headers must reference env vars. */
  headers?: Record<string, string>;
  /** Cookie name → value, set for `baseUrl`. Values must reference env vars. */
  cookies?: Record<string, string>;
  /** Path to a Playwright storage-state file (cookies + localStorage), e.g. from `playwright codegen --save-storage`. May reference env vars. */
  storageState?: string;
}

export interface PageExpectation {
  /** Strings that must not appear anywhere for this identity: DOM text (hidden or not), attributes, inline scripts, storage. */
  absentText?: string[];
  /** CSS selectors that must match nothing for this identity. */
  absentSelectors?: string[];
}

export interface PageConfig {
  /** Path relative to `baseUrl`, starting with `/`. */
  path: string;
  /** CSS selector to wait for before capturing, for pages that render after data loads. */
  waitFor?: string;
  expect?: Record<string, PageExpectation>;
}

export interface SurfaceConfig {
  /** Origin the browser is allowed to be credentialed for. Pages are relative to it. */
  baseUrl: string;
  /** Identity names ordered from least to most privileged. */
  tiers: string[];
  identities: Record<string, SurfaceIdentityConfig>;
  pages: PageConfig[];
  timeoutMs?: number;
  /** Shortest text, in characters, the differential rule compares. Default 12. */
  minTextLength?: number;
}

/** Why an element cannot be seen. `null` means visible. */
export type HiddenBy = "display" | "visibility" | "opacity" | "blur" | "transparent-text" | "clipped" | "zero-size";

export interface TextBlock {
  selector: string;
  /** Element's own text (direct text nodes), whitespace collapsed. */
  text: string;
  hiddenBy: HiddenBy | null;
}

export interface AttributeValue {
  selector: string;
  name: string;
  value: string;
}

export interface ScriptText {
  selector: string;
  text: string;
}

export interface StorageEntry {
  area: "localStorage" | "sessionStorage";
  key: string;
  value: string;
}

export interface SurfaceSnapshot {
  identity: string;
  /** URL requested. */
  url: string;
  /** URL after redirects. */
  finalUrl: string;
  status: number;
  blocks: TextBlock[];
  attributes: AttributeValue[];
  scripts: ScriptText[];
  storage: StorageEntry[];
  /** Selectors from the page's `absentSelectors` expectations that matched, with a text sample. */
  selectorMatches: Array<{ selector: string; text: string }>;
  /** Navigation or capture failure. */
  error?: string;
}

export interface PageObservation {
  page: PageConfig;
  /** Absolute URL of the page. */
  url: string;
  tiers: string[];
  snapshots: Map<string, SurfaceSnapshot>;
  minTextLength: number;
}
