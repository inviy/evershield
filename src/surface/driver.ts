/**
 * Headless browser driver. Playwright is an optional peer dependency: the
 * layer 1 and 2 commands never load it, and `evershield surface` explains
 * how to install it when it is missing.
 *
 * Only the small slice of Playwright's API evershield uses is typed here,
 * so the published types do not depend on Playwright being installed.
 */
import { readFile } from "node:fs/promises";
import path from "node:path";

import { interpolateEnv } from "../audit/http.ts";
import { ConfigError } from "../config.ts";
import { type CollectArgs, collectSurface, type CollectedSurface } from "./collect.ts";
import type { SurfaceIdentityConfig, SurfaceSnapshot } from "./types.ts";

interface PwRoute {
  request(): { url(): string; headers(): Record<string, string> };
  continue(options?: { headers?: Record<string, string> }): Promise<void>;
}
interface PwResponse {
  status(): number;
}
interface PwPage {
  goto(url: string, options: { waitUntil: "networkidle" | "load"; timeout: number }): Promise<PwResponse | null>;
  waitForSelector(selector: string, options: { timeout: number; state: "attached" }): Promise<unknown>;
  waitForTimeout(ms: number): Promise<void>;
  evaluate<R, A>(fn: (arg: A) => R, arg: A): Promise<R>;
  url(): string;
}
interface PwContext {
  route(pattern: string, handler: (route: PwRoute) => Promise<void>): Promise<void>;
  addCookies(cookies: Array<{ name: string; value: string; url: string }>): Promise<void>;
  newPage(): Promise<PwPage>;
  close(): Promise<void>;
}
interface PwBrowser {
  newContext(options: { storageState?: unknown; serviceWorkers: "block" }): Promise<PwContext>;
  close(): Promise<void>;
}
interface PwModule {
  chromium: { launch(options: { headless: boolean; executablePath?: string }): Promise<PwBrowser> };
}

export interface CaptureRequest {
  baseUrl: string;
  url: string;
  identityName: string;
  identity: SurfaceIdentityConfig;
  waitFor?: string;
  absentSelectors: string[];
  timeoutMs: number;
  env?: NodeJS.ProcessEnv;
}

export interface SurfaceDriver {
  capture(request: CaptureRequest): Promise<SurfaceSnapshot>;
  close(): Promise<void>;
}

export const PLAYWRIGHT_MISSING =
  "evershield surface drives a headless browser and needs Playwright: npm install --save-dev playwright && npx playwright install chromium";

async function loadPlaywright(): Promise<PwModule> {
  for (const name of ["playwright", "playwright-core"]) {
    try {
      return (await import(name)) as PwModule;
    } catch {
      // Try the next package name.
    }
  }
  throw new Error(PLAYWRIGHT_MISSING);
}

const COLLECT_LIMITS = { maxBlocks: 5000, maxText: 500 } as const;

function emptySnapshot(request: CaptureRequest, error: string): SurfaceSnapshot {
  return {
    identity: request.identityName,
    url: request.url,
    finalUrl: request.url,
    status: 0,
    blocks: [],
    attributes: [],
    scripts: [],
    storage: [],
    selectorMatches: [],
    error,
  };
}

async function readStorageState(file: string, env: NodeJS.ProcessEnv): Promise<unknown> {
  const resolved = path.resolve(interpolateEnv(file, env));
  try {
    return JSON.parse(await readFile(resolved, "utf8"));
  } catch (error) {
    throw new ConfigError(`cannot read storageState ${resolved}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

export async function launchPlaywrightDriver(env: NodeJS.ProcessEnv = process.env): Promise<SurfaceDriver> {
  const playwright = await loadPlaywright();
  const executablePath = env.EVERSHIELD_CHROMIUM_PATH;
  const browser = await playwright.chromium.launch({ headless: true, ...(executablePath ? { executablePath } : {}) });

  return {
    async capture(request) {
      const env = request.env ?? process.env;
      const origin = new URL(request.baseUrl).origin;
      const headers = Object.fromEntries(
        Object.entries(request.identity.headers ?? {}).map(([name, value]) => [name.toLowerCase(), interpolateEnv(value, env)]),
      );
      const cookies = Object.entries(request.identity.cookies ?? {}).map(([name, value]) => ({ name, value: interpolateEnv(value, env), url: origin }));
      const storageState = request.identity.storageState === undefined ? undefined : await readStorageState(request.identity.storageState, env);

      // Service workers are blocked so every request goes through the route
      // below, which adds credentials only for the audited origin.
      const context = await browser.newContext({ serviceWorkers: "block", ...(storageState === undefined ? {} : { storageState }) });
      try {
        if (Object.keys(headers).length > 0) {
          await context.route("**/*", async (route) => {
            const target = route.request();
            if (new URL(target.url()).origin === origin) await route.continue({ headers: { ...target.headers(), ...headers } });
            else await route.continue();
          });
        }
        if (cookies.length > 0) await context.addCookies(cookies);
        const page = await context.newPage();
        let response: PwResponse | null;
        try {
          response = await page.goto(request.url, { waitUntil: "networkidle", timeout: request.timeoutMs });
        } catch (error) {
          return emptySnapshot(request, error instanceof Error ? error.message.split("\n")[0]! : String(error));
        }
        if (request.waitFor !== undefined) {
          try {
            await page.waitForSelector(request.waitFor, { timeout: request.timeoutMs, state: "attached" });
          } catch {
            return { ...emptySnapshot(request, `waitFor selector "${request.waitFor}" never appeared`), finalUrl: page.url(), status: response?.status() ?? 0 };
          }
        }
        // Let late effects (entitlement checks, transitions) settle.
        await page.waitForTimeout(300);
        const args: CollectArgs = { absentSelectors: request.absentSelectors, ...COLLECT_LIMITS };
        const collected: CollectedSurface = await page.evaluate(collectSurface, args);
        return { identity: request.identityName, url: request.url, finalUrl: page.url(), status: response?.status() ?? 0, ...collected };
      } finally {
        await context.close();
      }
    },
    async close() {
      await browser.close();
    },
  };
}
