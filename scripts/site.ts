/**
 * Builds the documentation site from the repository's Markdown into _site/.
 *
 *   node --experimental-strip-types scripts/site.ts
 *
 * The Markdown stays the single source: README, docs/*.md, the REA
 * experiment and the changelog become pages, and every rule in
 * docs/rules.md also gets a page of its own. Links between those files are
 * rewritten to the site's paths; anything else points at GitHub.
 */
import { copyFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";

import { Marked, type Tokens } from "marked";

const root = path.resolve(import.meta.dirname, "..");
const out = path.join(root, "_site");
const REPO = "https://github.com/inviy/evershield";

interface Page {
  /** Output directory relative to the site root ("" for the home page). */
  dir: string;
  title: string;
  source: string;
  markdown: string;
}

/** GitHub's heading anchors: lower case, punctuation dropped, spaces to dashes. */
export function slug(text: string): string {
  return text
    .toLowerCase()
    .replace(/<[^>]+>/g, "")
    .replace(/[^\p{L}\p{N}\s_-]/gu, "")
    .trim()
    .replace(/\s/g, "-");
}

const SOURCES: Record<string, string> = {
  "README.md": "",
  "docs/rules.md": "rules",
  "docs/configuration.md": "configuration",
  "docs/design.md": "design",
  "docs/corpus.md": "corpus",
  "experiments/rea/README.md": "rea",
  "CHANGELOG.md": "changelog",
};

const NAV: Array<[string, string]> = [
  ["", "Overview"],
  ["rules", "Rules"],
  ["configuration", "Configuration"],
  ["corpus", "False-positive corpus"],
  ["rea", "Tested against REA"],
  ["design", "Design"],
  ["changelog", "Changelog"],
];

/** Rewrite a link written for GitHub into one that works on the site, from a page at `fromDir`. */
export function rewriteLink(href: string, sourceFile: string, fromDir: string): string {
  if (/^(?:[a-z]+:|#|\/\/)/i.test(href)) return href;
  const [target = "", hash = ""] = href.split("#");
  const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(sourceFile), target));
  const up = fromDir === "" ? "" : "../".repeat(fromDir.split("/").length);
  const anchor = hash === "" ? "" : `#${hash}`;
  if (target === "") return anchor;
  if (resolved in SOURCES) return `${up}${SOURCES[resolved] === "" ? "" : `${SOURCES[resolved]}/`}${anchor}`;
  if (resolved.startsWith("docs/assets/")) return `${up}assets/${resolved.slice("docs/assets/".length)}`;
  if (resolved === "." || resolved === "") return REPO;
  return `${REPO}/blob/main/${resolved}${anchor}`;
}

function render(page: Page): string {
  const marked = new Marked({
    gfm: true,
    renderer: {
      heading({ tokens, depth }: Tokens.Heading) {
        const text = this.parser.parseInline(tokens);
        return `<h${depth} id="${slug(text)}">${text}</h${depth}>\n`;
      },
    },
    walkTokens(token) {
      if (token.type === "link" || token.type === "image") token.href = rewriteLink(token.href, page.source, page.dir);
      // Raw HTML in the Markdown (the README banner) carries links too.
      if (token.type === "html") {
        token.text = token.text.replace(/\b(src|href)="([^"]+)"/g, (_m: string, attr: string, href: string) => `${attr}="${rewriteLink(href, page.source, page.dir)}"`);
      }
    },
  });
  const body = marked.parse(page.markdown) as string;
  const up = page.dir === "" ? "" : "../".repeat(page.dir.split("/").length);
  const nav = NAV.map(([dir, label]) => {
    const current = page.dir === dir || (dir === "rules" && page.dir.startsWith("rules/"));
    return `<a href="${up}${dir === "" ? "" : `${dir}/`}"${current ? ' aria-current="page"' : ""}>${label}</a>`;
  }).join("");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${page.title} · evershield</title>
<meta name="description" content="evershield finds what your web app exposes to the browser: bundles, API responses and the rendered page.">
<link rel="stylesheet" href="${up}style.css">
</head>
<body>
<header><a class="brand" href="${up}">evershield</a><nav>${nav}</nav><a class="gh" href="${REPO}">GitHub</a></header>
<main>${body}</main>
<footer>MIT · <a href="${REPO}/blob/main/${page.source}">Edit this page</a> · generated from the repository's Markdown</footer>
</body>
</html>
`;
}

const CSS = `:root{--bg:#fbfbfa;--fg:#16181d;--muted:#5d6370;--line:#e3e4e8;--code:#f1f2f4;--accent:#1d5fd1}
@media (prefers-color-scheme:dark){:root{--bg:#111317;--fg:#e8e9ec;--muted:#9aa0ab;--line:#2a2e36;--code:#1b1e24;--accent:#7aa7ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.65 system-ui,-apple-system,"Segoe UI",sans-serif}
header{display:flex;flex-wrap:wrap;gap:12px 20px;align-items:center;padding:14px 20px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--bg)}
.brand{font-weight:700;color:var(--fg);text-decoration:none}nav{display:flex;flex-wrap:wrap;gap:4px 14px;flex:1}nav a,.gh{color:var(--muted);text-decoration:none;font-size:14px}
nav a[aria-current]{color:var(--fg);font-weight:600}main{max-width:820px;margin:0 auto;padding:24px 20px 64px}
a{color:var(--accent)}h1,h2,h3{line-height:1.25;margin-top:1.8em}h1{margin-top:.6em}img{max-width:100%}
pre{background:var(--code);padding:14px;border-radius:8px;overflow-x:auto;font-size:14px}code{background:var(--code);padding:.1em .35em;border-radius:4px;font-size:.92em}pre code{padding:0;background:none}
table{border-collapse:collapse;display:block;overflow-x:auto;font-size:14px;margin:1em 0}th,td{border:1px solid var(--line);padding:6px 10px;text-align:left;vertical-align:top}
@media (max-width:640px){header{position:static}nav{order:3;flex-basis:100%}.gh{margin-left:auto}}
blockquote{margin:1em 0;padding:.2em 1em;border-left:3px solid var(--line);color:var(--muted)}footer{max-width:820px;margin:0 auto;padding:20px;color:var(--muted);font-size:13px;border-top:1px solid var(--line)}
`;

/** One page per rule: the rule's section, under its own URL, linkable from findings. */
export function ruleSections(rules: string): Array<{ id: string; markdown: string }> {
  const sections: Array<{ id: string; markdown: string }> = [];
  const matches = [...rules.matchAll(/^### ((?:artifact|response|surface)\/[a-z-]+)\n/gm)];
  matches.forEach((match, i) => {
    const start = match.index;
    const after = rules.slice(start + match[0].length);
    const end = after.search(/^#{2,3} /m);
    sections.push({ id: match[1]!, markdown: rules.slice(start, end < 0 ? undefined : start + match[0].length + end) });
  });
  return sections;
}

async function main(): Promise<void> {
  await rm(out, { recursive: true, force: true });
  const pages: Page[] = [];
  for (const [source, dir] of Object.entries(SOURCES)) {
    const markdown = await readFile(path.join(root, source), "utf8");
    const title = /^# (.+)$/m.exec(markdown)?.[1] ?? "evershield";
    pages.push({ dir, title: dir === "" ? "Shield everything, everywhere" : title, source, markdown });
    if (source === "docs/rules.md") {
      for (const rule of ruleSections(markdown)) {
        const body = `${rule.markdown}\n\n[All rules](../)`;
        pages.push({ dir: `rules/${rule.id.replace("/", "-")}`, title: rule.id, source, markdown: body.replace(/^### /, "# ") });
      }
    }
  }
  for (const page of pages) {
    await mkdir(path.join(out, page.dir), { recursive: true });
    await writeFile(path.join(out, page.dir, "index.html"), render(page));
  }
  await mkdir(path.join(out, "assets"), { recursive: true });
  await copyFile(path.join(root, "docs/assets/banner.svg"), path.join(out, "assets/banner.svg"));
  await writeFile(path.join(out, "style.css"), CSS);
  await writeFile(path.join(out, ".nojekyll"), "");
  console.log(`site: ${pages.length} pages in ${path.relative(root, out)}/`);
}

if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === import.meta.filename) await main();
