/**
 * Layer 2: privilege-differential response audit.
 *
 * The operator declares identities (anonymous, free, pro, admin, …) whose
 * credentials live in environment variables, an ordered list of tiers from
 * least to most privileged, and endpoints to call as each identity. The
 * audit compares what each identity receives and reports fields that a
 * lower tier should not have.
 */

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface IdentityConfig {
  /** Header values may reference env vars as `${NAME}`; credential headers must. */
  headers?: Record<string, string>;
}

export interface EndpointExpectation {
  /** JSON paths (dot notation, `[]` for arrays) that must be absent or null for this identity. */
  absent?: string[];
}

export interface EndpointConfig {
  method: HttpMethod;
  /** Path relative to `baseUrl`, starting with `/`. */
  path: string;
  headers?: Record<string, string>;
  /** JSON body for POST/PUT/PATCH. String values may reference env vars. */
  body?: unknown;
  /** The endpoint is supposed to answer differently per tier. */
  tiered?: boolean;
  /** Per-identity expectations, keyed by identity name. */
  expect?: Record<string, EndpointExpectation>;
}

export interface AuditConfig {
  /** Origin the audit is allowed to talk to. Endpoints are relative to it. */
  baseUrl: string;
  /** Identity names ordered from least to most privileged. */
  tiers: string[];
  identities: Record<string, IdentityConfig>;
  endpoints: EndpointConfig[];
  timeoutMs?: number;
}

export interface ResponseObservation {
  identity: string;
  status: number;
  contentType: string | null;
  /** Parsed JSON body, or undefined when the body was not JSON. */
  json: unknown;
  isJson: boolean;
  /** Transport-level failure, when the request did not complete. */
  error?: string;
}

export interface EndpointObservation {
  endpoint: EndpointConfig;
  /** "POST /api/analyze" */
  label: string;
  /** Identity names, least privileged first. */
  tiers: string[];
  responses: Map<string, ResponseObservation>;
}
