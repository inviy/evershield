// Serves dist/ and a /api/report endpoint. MODE=leaky returns Pro fields to
// everyone (the client blurs them); MODE=fixed withholds them for free users.
import { createReadStream, existsSync, statSync } from "node:fs";
import { createServer } from "node:http";
import path from "node:path";

const mode = process.env.MODE ?? "leaky";
const port = Number(process.env.PORT ?? 4173);
const root = path.resolve(import.meta.dirname, `dist-${mode}`);
const types = { ".html": "text/html", ".js": "text/javascript", ".map": "application/json", ".css": "text/css" };

createServer((req, res) => {
  const url = new URL(req.url ?? "/", "http://x");
  if (url.pathname === "/api/report") {
    const plan = req.headers.authorization === "Bearer pro-demo" ? "pro" : "free";
    const body = { total: 78, plan };
    if (mode === "leaky" || plan === "pro") Object.assign(body, { burstiness: 0.82, perplexity: 41.2 });
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
    return;
  }
  let file = path.join(root, url.pathname === "/" ? "index.html" : url.pathname);
  if (!file.startsWith(root) || !existsSync(file) || statSync(file).isDirectory()) file = path.join(root, "index.html");
  res.writeHead(200, { "content-type": types[path.extname(file)] ?? "application/octet-stream" });
  createReadStream(file).pipe(res);
}).listen(port, "127.0.0.1", () => console.log(`${mode} on http://127.0.0.1:${port}`));
