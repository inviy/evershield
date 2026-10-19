import assert from "node:assert/strict";
import { chmod, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import { run } from "./cli.ts";
import { buildMap, runRecon } from "./recon.ts";
import { fake, file, withTempDir } from "./test-support.ts";

/**
 * A stand-in for the `rea` executable that prints JSON containing whatever
 * FAKE_REA_ECHO holds. On Windows it is a .cmd shim, as npm installs `rea`.
 */
async function fakeRea(dir: string): Promise<string> {
  const script = path.join(dir, "fake-rea.mjs");
  await writeFile(script, `#!/usr/bin/env node\nprocess.stdout.write(JSON.stringify({ evidence: [process.env.FAKE_REA_ECHO ?? ""] }));\n`);
  if (process.platform === "win32") {
    const shim = path.join(dir, "fake rea.cmd");
    await writeFile(shim, `@"${process.execPath}" "${script}" %*\r\n`);
    return shim;
  }
  await chmod(script, 0o755);
  return script;
}

const leaky = () => ({
  "assets/app.js": `const k="${fake.stripeLiveKey()}";fetch("http://10.0.3.7:8080/admin");fetch("/api/report");//# sourceMappingURL=app.js.map`,
  "assets/app.js.map": JSON.stringify({ version: 3, sources: ["src/main.js", "src/config.js"], sourcesContent: ["// main", null], mappings: "" }),
});

test("recon lists what is worth taking and checks each value against REA's own output", async () => {
  await withTempDir(leaky(), async (root) => {
    const bin = await fakeRea(root);
    process.env.FAKE_REA_ECHO = fake.stripeLiveKey();
    try {
      const result = await runRecon(path.join(root, "assets"), { reaBin: bin });
      assert.equal(result.rea.status, "ran");
      const secret = result.items.find((item) => item.category === "credential");
      const address = result.items.find((item) => item.category === "internal-address");
      const source = result.items.find((item) => item.category === "source");
      assert.equal(secret?.reaRecovered, true);
      assert.equal(address?.reaRecovered, false, "REA's output did not contain the address");
      assert.equal(source?.reaRecovered, null, "source maps are read by REA's live-page analysis, not checked here");
      assert.ok(!JSON.stringify(result).includes(fake.stripeLiveKey()), "the raw value never lands in the result");
    } finally {
      delete process.env.FAKE_REA_ECHO;
    }
  });
});

test("the map is what any tool reconstructs: hosts, API paths, source map coverage, public env names", () => {
  const map = buildMap([
    file("a.js", `fetch("https://api.example.com/v1/users");fetch("https://api.example.com/x");const u="/api/report";const g='/graphql';const e="VITE_API_URL";`),
    file("a.js.map", JSON.stringify({ sources: ["a.ts", "b.ts"], sourcesContent: ["x", "y"] })),
  ]);
  assert.deepEqual(map.hosts, [{ host: "api.example.com", count: 2 }]);
  assert.deepEqual(map.apiPaths, ["/api/report", "/graphql"]);
  assert.deepEqual(map.sourceMaps, { files: 1, originalSources: 2, withContent: 2 });
  assert.deepEqual(map.publicEnvNames, ["VITE_API_URL"]);
});

test("recon CLI: 1 when something is worth taking, 0 when nothing is, 2 when a requested REA check cannot run", async () => {
  await withTempDir(leaky(), async (root) => {
    const dirty = await run(["recon", path.join(root, "assets")]);
    assert.equal(dirty.code, 1);
    assert.match(dirty.stdout, /Verdict: 2 item\(s\) worth taking/);
    assert.ok(!dirty.stdout.includes(fake.stripeLiveKey()));

    const missing = await run(["recon", path.join(root, "assets"), "--rea-bin", path.join(root, "no-such-rea")]);
    assert.equal(missing.code, 2);
    assert.match(missing.stderr, /not found/);
  });
  await withTempDir({ "assets/app.js": `fetch("/api/report")` }, async (root) => {
    const clean = await run(["recon", root, "--format", "json"]);
    assert.equal(clean.code, 0);
    const report = JSON.parse(clean.stdout) as { blocking: number; map: { apiPaths: string[] } };
    assert.equal(report.blocking, 0);
    assert.deepEqual(report.map.apiPaths, ["/api/report"]);
  });
});

test("REA is skipped for APK and IPA files with a pointer to scan the extracted bundle instead", async () => {
  await withTempDir({}, async (root) => {
    // An empty zip: end-of-central-directory record only.
    const empty = Buffer.alloc(22);
    empty.writeUInt32LE(0x06054b50, 0);
    const apk = path.join(root, "app.apk");
    await writeFile(apk, Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.alloc(26), empty]));
    const result = await runRecon(apk, { reaBin: "rea" });
    assert.equal(result.rea.status, "skipped");
  });
});
