import { type Finding, type ScanSummary, VERSION } from "../index.ts";
import { sortFindings } from "../scan/artifact.ts";
import { type SurfaceDriver, launchPlaywrightDriver } from "./driver.ts";
import { SURFACE_RULES } from "./rules.ts";
import type { PageObservation, SurfaceConfig } from "./types.ts";

export interface SurfaceResult extends ScanSummary {
  layer: "surface";
  target: string;
  identities: string[];
  pagesAudited: number;
  /** Page loads that rendered and were evaluated by the rules. */
  snapshotsEvaluated: number;
  ignored: number;
  warnings: string[];
}

export interface SurfaceOptions {
  env?: NodeJS.ProcessEnv;
  /** Injected in tests; defaults to a Playwright Chromium. */
  driver?: SurfaceDriver;
}

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MIN_TEXT = 12;

/**
 * Layer 3: open each page as each identity, least privileged first, one at a
 * time, and run the surface rules over what each identity's browser held.
 */
export async function runSurface(config: SurfaceConfig, options: SurfaceOptions = {}): Promise<SurfaceResult> {
  const startedAt = new Date().toISOString();
  const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const minTextLength = config.minTextLength ?? DEFAULT_MIN_TEXT;
  const findings: Finding[] = [];
  const warnings: string[] = [];
  let snapshotsEvaluated = 0;

  const driver = options.driver ?? (await launchPlaywrightDriver(options.env));
  try {
    for (const page of config.pages) {
      const url = new URL(page.path, config.baseUrl).toString();
      const observation: PageObservation = { page, url, tiers: config.tiers, snapshots: new Map(), minTextLength };

      for (const identityName of config.tiers) {
        const identity = config.identities[identityName];
        if (identity === undefined) {
          warnings.push(`${page.path}: identity "${identityName}" is not defined`);
          continue;
        }
        const snapshot = await driver.capture({
          baseUrl: config.baseUrl,
          url,
          identityName,
          identity,
          absentSelectors: page.expect?.[identityName]?.absentSelectors ?? [],
          timeoutMs,
          ...(page.waitFor === undefined ? {} : { waitFor: page.waitFor }),
          ...(options.env === undefined ? {} : { env: options.env }),
        });
        if (snapshot.error === undefined && new URL(snapshot.finalUrl).origin !== new URL(config.baseUrl).origin) {
          snapshot.error = `redirected off the audited origin to ${new URL(snapshot.finalUrl).origin}`;
        }
        observation.snapshots.set(identityName, snapshot);

        for (const match of snapshot.selectorMatches) {
          if (match.text === "(invalid selector)") warnings.push(`${page.path}: absentSelectors entry "${match.selector}" is not a valid CSS selector`);
        }
        if (snapshot.error !== undefined) {
          warnings.push(`${page.path} as ${identityName}: ${snapshot.error}, not evaluated`);
        } else if (snapshot.status >= 400) {
          warnings.push(`${page.path} as ${identityName}: HTTP ${snapshot.status}, not evaluated`);
        } else {
          snapshotsEvaluated += 1;
          if (snapshot.finalUrl !== url) warnings.push(`${page.path} as ${identityName}: landed on ${snapshot.finalUrl}`);
        }
      }

      for (const rule of SURFACE_RULES) findings.push(...rule.check(observation));
    }
  } finally {
    if (options.driver === undefined) await driver.close();
  }

  return {
    version: VERSION,
    layer: "surface",
    target: config.baseUrl,
    identities: [...config.tiers],
    pagesAudited: config.pages.length,
    snapshotsEvaluated,
    ignored: 0,
    warnings,
    startedAt,
    finishedAt: new Date().toISOString(),
    findings: sortFindings(findings),
  };
}
