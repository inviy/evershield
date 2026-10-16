import { type Finding, type ScanSummary, VERSION } from "../index.ts";
import { sortFindings } from "../scan/artifact.ts";
import { requestEndpoint } from "./http.ts";
import { RESPONSE_RULES } from "./rules.ts";
import type { AuditConfig, EndpointObservation } from "./types.ts";

export interface AuditResult extends ScanSummary {
  layer: "response";
  /** The base URL audited. */
  target: string;
  identities: string[];
  endpointsAudited: number;
  /** Responses that were 2xx JSON and therefore evaluated by the rules. */
  responsesEvaluated: number;
  /** Findings removed by config ignore rules. */
  ignored: number;
  /** Endpoints or identities that could not be evaluated, and why. */
  warnings: string[];
}

export interface AuditOptions {
  env?: NodeJS.ProcessEnv;
  fetchImpl?: typeof fetch;
}

const DEFAULT_TIMEOUT_MS = 15_000;

/**
 * Layer 2: call each endpoint as each identity, least privileged first, and
 * run the response rules over what came back. Requests are sequential: an
 * audit is a handful of calls, and it should never look like load.
 */
export async function runAudit(config: AuditConfig, options: AuditOptions = {}): Promise<AuditResult> {
  const startedAt = new Date().toISOString();
  const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const findings: Finding[] = [];
  const warnings: string[] = [];
  let responsesEvaluated = 0;

  for (const endpoint of config.endpoints) {
    const label = `${endpoint.method} ${endpoint.path}`;
    const observation: EndpointObservation = { endpoint, label, tiers: config.tiers, responses: new Map() };

    for (const identityName of config.tiers) {
      const identity = config.identities[identityName];
      if (identity === undefined) {
        warnings.push(`${label}: identity "${identityName}" is not defined`);
        continue;
      }
      const requestOptions = { baseUrl: config.baseUrl, endpoint, identityName, identity, timeoutMs } as const;
      const response = await requestEndpoint({
        ...requestOptions,
        ...(options.env === undefined ? {} : { env: options.env }),
        ...(options.fetchImpl === undefined ? {} : { fetchImpl: options.fetchImpl }),
      });
      observation.responses.set(identityName, response);
      if (response.error !== undefined) {
        warnings.push(`${label} as ${identityName}: request failed (${response.error})`);
      } else if (response.status < 200 || response.status >= 300) {
        warnings.push(`${label} as ${identityName}: HTTP ${response.status}, not evaluated`);
      } else if (!response.isJson) {
        warnings.push(`${label} as ${identityName}: response is not JSON (${response.contentType ?? "no content-type"}), not evaluated`);
      } else {
        responsesEvaluated += 1;
      }
    }

    for (const rule of RESPONSE_RULES) findings.push(...rule.check(observation));
  }

  return {
    version: VERSION,
    layer: "response",
    target: config.baseUrl,
    identities: [...config.tiers],
    endpointsAudited: config.endpoints.length,
    responsesEvaluated,
    ignored: 0,
    warnings,
    startedAt,
    finishedAt: new Date().toISOString(),
    findings: sortFindings(findings),
  };
}
