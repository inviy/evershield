import { ConfigError } from "../config.ts";
import type { EndpointConfig, IdentityConfig, ResponseObservation } from "./types.ts";

const ENV_REF = /\$\{([A-Z_][A-Z0-9_]*)\}/g;

/** Replace `${NAME}` with the environment value; a missing variable is a config error that names the variable, never a value. */
export function interpolateEnv(value: string, env: NodeJS.ProcessEnv = process.env): string {
  return value.replace(ENV_REF, (_match, name: string) => {
    const resolved = env[name];
    if (resolved === undefined || resolved === "") {
      throw new ConfigError(`environment variable ${name} is referenced in the audit config but not set`);
    }
    return resolved;
  });
}

export function interpolateDeep(value: unknown, env: NodeJS.ProcessEnv = process.env): unknown {
  if (typeof value === "string") return interpolateEnv(value, env);
  if (Array.isArray(value)) return value.map((item) => interpolateDeep(item, env));
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, interpolateDeep(child, env)]));
  }
  return value;
}

/**
 * `fetch failed` on its own helps nobody. Surface the underlying cause
 * (DNS, refused connection, TLS) and, since Node's fetch ignores proxy
 * environment variables unless told otherwise, hint at the usual fix when a
 * proxy is configured but not in use.
 */
export function describeFetchError(error: unknown, timeoutMs: number, env: NodeJS.ProcessEnv = process.env): string {
  if (!(error instanceof Error)) return String(error);
  if (error.name === "AbortError") return `timed out after ${timeoutMs}ms`;
  // A refused connection over IPv4 and IPv6 arrives as an AggregateError with
  // no code of its own; the first inner error carries it.
  let cause = (error as Error & { cause?: unknown }).cause;
  if (cause instanceof AggregateError && cause.errors.length > 0) cause = cause.errors[0];
  const causeText =
    cause instanceof Error
      ? [...new Set([(cause as NodeJS.ErrnoException).code, cause.message])]
          .filter((part): part is string => typeof part === "string" && part.length > 0)
          .join(" ")
      : "";
  let message = causeText.length > 0 ? `${error.message}: ${causeText}` : error.message;
  const proxyConfigured = Boolean(env.HTTPS_PROXY ?? env.https_proxy ?? env.HTTP_PROXY ?? env.http_proxy);
  if (proxyConfigured && env.NODE_USE_ENV_PROXY === undefined) {
    message += " (a proxy is configured in the environment but Node's fetch does not use it by default; set NODE_USE_ENV_PROXY=1)";
  }
  return message;
}

export interface RequestOptions {
  baseUrl: string;
  endpoint: EndpointConfig;
  identityName: string;
  identity: IdentityConfig;
  timeoutMs: number;
  env?: NodeJS.ProcessEnv;
  fetchImpl?: typeof fetch;
}

/**
 * Perform one request as one identity. Header values are interpolated here
 * and never stored on the observation, so a report cannot leak them.
 */
export async function requestEndpoint(options: RequestOptions): Promise<ResponseObservation> {
  const { baseUrl, endpoint, identityName, identity, timeoutMs } = options;
  const env = options.env ?? process.env;
  const fetchImpl = options.fetchImpl ?? fetch;

  const headers = new Headers();
  for (const [name, value] of Object.entries(identity.headers ?? {})) headers.set(name, interpolateEnv(value, env));
  for (const [name, value] of Object.entries(endpoint.headers ?? {})) headers.set(name, interpolateEnv(value, env));

  let body: string | undefined;
  if (endpoint.body !== undefined && endpoint.method !== "GET") {
    body = JSON.stringify(interpolateDeep(endpoint.body, env));
    if (!headers.has("content-type")) headers.set("content-type", "application/json");
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const init: RequestInit = { method: endpoint.method, headers, signal: controller.signal };
    if (body !== undefined) init.body = body;
    const response = await fetchImpl(new URL(endpoint.path, baseUrl), init);
    const contentType = response.headers.get("content-type");
    const text = await response.text();
    let json: unknown;
    let isJson = false;
    if (text.length > 0) {
      try {
        json = JSON.parse(text);
        isJson = true;
      } catch {
        isJson = false;
      }
    }
    return { identity: identityName, status: response.status, contentType, json, isJson };
  } catch (error) {
    return { identity: identityName, status: 0, contentType: null, json: undefined, isJson: false, error: describeFetchError(error, timeoutMs) };
  } finally {
    clearTimeout(timer);
  }
}
