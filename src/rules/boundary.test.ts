/**
 * Boundary-mutation tests for the provider patterns of
 * artifact/secret-like-string (after "Boundary-Mutation Testing for
 * Pattern-Based Secret Detection", arXiv 2609.02983). Each provider's
 * values are generated at the edges of its format (shortest length,
 * a last character that is not a word character, digits only) and embedded
 * in the contexts a shipped file puts them in. The value must be found and
 * captured whole: a `\b` after a fixed-count quantifier silently misses a
 * key that ends in `-`.
 */
import assert from "node:assert/strict";
import test from "node:test";

import { file, plainContext } from "../test-support.ts";
import { secretLikeString } from "./secret-like-string.ts";

interface Format {
  name: string;
  prefixes: string[];
  /** Characters the body may use; the generator puts each edge character last. */
  charset: string;
  lengths: number[];
}

const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

const FORMATS: Format[] = [
  { name: "AWS access key ID", prefixes: ["AKIA"], charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", lengths: [16] },
  { name: "GitHub token", prefixes: ["ghp_", "gho_", "ghs_"], charset: ALNUM, lengths: [36, 40] },
  { name: "Stripe secret key", prefixes: ["sk_live_", "rk_live_"], charset: ALNUM, lengths: [24, 99] },
  { name: "Slack token", prefixes: ["xoxb-", "xoxp-"], charset: `${ALNUM}-`, lengths: [10, 50] },
  { name: "Anthropic API key", prefixes: ["sk-ant-"], charset: `${ALNUM}_-`, lengths: [32, 95] },
  { name: "OpenAI API key", prefixes: ["sk-", "sk-proj-", "sk-svcacct-"], charset: `${ALNUM}_-`, lengths: [32, 120] },
  { name: "Google API key", prefixes: ["AIza"], charset: `${ALNUM}_-`, lengths: [35] },
];

/** Deterministic body of `length` characters from `charset`, ending in `last`. */
function body(charset: string, length: number, last: string, seed: number): string {
  let out = "";
  for (let i = 0; i < length - 1; i += 1) out += charset[(seed * 31 + i * 17) % charset.length];
  return out + last;
}

/** One value per prefix, length and edge character (non-alphanumerics, a digit, a letter). */
function samples(format: Format): string[] {
  const pick = (re: RegExp) => [...format.charset].find((c) => re.test(c));
  const edges = [...new Set([...format.charset.replace(/[A-Za-z0-9]/g, ""), pick(/[0-9]/), pick(/[a-z]/) ?? pick(/[A-Z]/)])].filter((c): c is string => c !== undefined);
  const out: string[] = [];
  format.prefixes.forEach((prefix, p) => {
    for (const length of format.lengths) for (const [e, edge] of edges.entries()) out.push(prefix + body(format.charset, length, edge, p * 7 + e));
  });
  return out;
}

/** Where a shipped file puts a credential. */
const CONTEXTS: Array<[string, (value: string) => string]> = [
  ["minified JS", (v) => `var a={k:"${v}",b:1};`],
  ["single quotes", (v) => `f('${v}')`],
  ["template literal", (v) => "const h=`Bearer ${t}" + `${v}` + "`"],
  ["JSON", (v) => `{"apiKey":"${v}","x":1}`],
  ["escaped JSON in JS", (v) => `JSON.parse("{\\"apiKey\\":\\"${v}\\"}")`],
  ["XML resource", (v) => `<string name="api_key">${v}</string>`],
  ["plist", (v) => `<key>ApiKey</key><string>${v}</string>`],
  ["query string", (v) => `fetch("https://api.example.com/v1?key=${v}&q=1")`],
  ["header", (v) => `headers:{Authorization:"Bearer ${v}"}`],
  ["dotenv line", (v) => `API_KEY=${v}\nOTHER=1`],
  ["strings dump line", (v) => v],
  ["escaped newline after", (v) => `"${v}\\n"`],
];

for (const format of FORMATS) {
  test(`${format.name}: every edge value is found whole in every context`, () => {
    const misses: string[] = [];
    for (const value of samples(format)) {
      for (const [where, wrap] of CONTEXTS) {
        const findings = secretLikeString.check(file("static/app.js", wrap(value)), plainContext);
        const hit = findings.find((f) => f.message.startsWith(format.name));
        // The redacted excerpt keeps the last four characters: a truncated match shows other ones.
        const excerpt = hit?.evidence[0]?.kind === "file" ? (hit.evidence[0].excerpt ?? "") : "";
        if (hit === undefined) misses.push(`missed in ${where}: …${value.slice(-6)}`);
        else if (!excerpt.includes(value.slice(-4))) misses.push(`truncated in ${where}: …${value.slice(-6)} → ${excerpt}`);
      }
    }
    assert.deepEqual(misses, []);
  });
}
