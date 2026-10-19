import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { crc32, deflateRawSync } from "node:zlib";

import { fake, withTempDir } from "../test-support.ts";
import { scanArtifact } from "./artifact.ts";
import { extractStrings, hermesStrings } from "./archive.ts";

/** Minimal zip writer: deflated entries, one central directory. */
function zip(entries: Record<string, Buffer | string>): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const [name, content] of Object.entries(entries)) {
    const data = Buffer.isBuffer(content) ? content : Buffer.from(content);
    const packed = deflateRawSync(data);
    const nameBytes = Buffer.from(name);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(8, 8);
    local.writeUInt32LE(crc32(data), 14);
    local.writeUInt32LE(packed.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(8, 10);
    central.writeUInt32LE(crc32(data), 16);
    central.writeUInt32LE(packed.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt32LE(offset, 42);
    locals.push(local, nameBytes, packed);
    centrals.push(central, nameBytes);
    offset += 30 + nameBytes.length + packed.length;
  }
  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(Object.keys(entries).length, 8);
  end.writeUInt16LE(Object.keys(entries).length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

/** Minimal ASAR writer, the layout @electron/asar produces. */
function asar(files: Record<string, string>): Buffer {
  const tree: Record<string, unknown> = {};
  const bodies: Buffer[] = [];
  let offset = 0;
  for (const [name, content] of Object.entries(files)) {
    const parts = name.split("/");
    let node = tree as { files?: Record<string, unknown> };
    for (const dir of parts.slice(0, -1)) {
      node.files ??= {};
      node = (node.files[dir] ??= {}) as { files?: Record<string, unknown> };
    }
    node.files ??= {};
    const data = Buffer.from(content);
    node.files[parts.at(-1)!] = { size: data.length, offset: String(offset) };
    bodies.push(data);
    offset += data.length;
  }
  const json = Buffer.from(JSON.stringify(tree));
  const padded = Math.ceil(json.length / 4) * 4;
  const header = Buffer.alloc(16 + padded);
  header.writeUInt32LE(4, 0);
  header.writeUInt32LE(8 + padded, 4);
  header.writeUInt32LE(4 + padded, 8);
  header.writeUInt32LE(json.length, 12);
  json.copy(header, 16);
  return Buffer.concat([header, ...bodies]);
}

const hermes = (strings: string[]) =>
  Buffer.concat([Buffer.from([0xc6, 0x1f, 0xbc, 0x03, 0xc1, 0x03, 0x19, 0x1f]), Buffer.alloc(64), ...strings.map((s) => Buffer.concat([Buffer.from(s), Buffer.alloc(1)]))]);
const utf16 = (s: string) => Buffer.from(s, "utf16le");

test("an APK: keys in a plain RN bundle, in Hermes bytecode, and in the binary manifest are found", async () => {
  const apk = zip({
    "AndroidManifest.xml": Buffer.concat([Buffer.alloc(32), utf16("http://10.0.2.2:8080/api"), Buffer.alloc(4)]),
    "assets/index.android.bundle": `var c={billing:"${fake.stripeLiveKey()}"};`,
    "assets/other.hbc": hermes(["hello world", fake.awsAccessKeyId()]),
    "res/drawable/icon.png": Buffer.alloc(100, 1),
    "classes.dex": Buffer.concat([Buffer.from("dex\n035\0"), Buffer.from(fake.anthropicKey()), Buffer.alloc(1)]),
    "META-INF/CERT.RSA": Buffer.alloc(10, 2),
  });
  await withTempDir({}, async (root) => {
    const file = path.join(root, "app-release.apk");
    await writeFile(file, apk);
    const result = await scanArtifact(file);
    assert.equal(result.adapter, "android");
    const where = result.findings.map((f) => `${f.ruleId} ${f.evidence[0]?.kind === "file" ? f.evidence[0].path : ""}`);
    assert.ok(where.includes("artifact/secret-like-string assets/index.android.bundle"), where.join("\n"));
    assert.ok(where.includes("artifact/secret-like-string assets/other.hbc (strings)"), where.join("\n"));
    assert.ok(where.includes("artifact/secret-like-string classes.dex (strings)"), where.join("\n"));
    assert.ok(where.includes("artifact/internal-endpoint AndroidManifest.xml (strings)"), where.join("\n"));
    assert.equal(result.filesScanned, 4, "images and signatures are not scanned");
    assert.ok(!JSON.stringify(result).includes(fake.stripeLiveKey()), "matched values stay redacted");
  });
});

test("an IPA: main.jsbundle and the Mach-O executable's strings are scanned", async () => {
  const macho = Buffer.concat([Buffer.from([0xcf, 0xfa, 0xed, 0xfe]), Buffer.alloc(16), Buffer.from(fake.openAiKey()), Buffer.alloc(1)]);
  const ipa = zip({
    "Payload/Demo.app/main.jsbundle": `fetch("https://api.payments.internal/v1")`,
    "Payload/Demo.app/Demo": macho,
    "Payload/Demo.app/Info.plist": `<plist><dict><key>CFBundleName</key><string>Demo</string></dict></plist>`,
  });
  await withTempDir({}, async (root) => {
    const file = path.join(root, "Demo.ipa");
    await writeFile(file, ipa);
    const result = await scanArtifact(file);
    assert.equal(result.adapter, "ios");
    assert.ok(result.findings.some((f) => f.ruleId === "artifact/internal-endpoint"));
    assert.ok(result.findings.some((f) => f.ruleId === "artifact/secret-like-string" && f.message.includes("OpenAI")));
  });
});

test("an Electron app.asar is unpacked in memory and its code scanned", async () => {
  await withTempDir({}, async (root) => {
    const file = path.join(root, "app.asar");
    await writeFile(file, asar({ "package.json": `{"main":"main.js"}`, "main.js": `const k="${fake.stripeLiveKey()}";`, "renderer/app.js": "console.log(1)" }));
    const result = await scanArtifact(file);
    assert.equal(result.adapter, "electron");
    assert.equal(result.filesScanned, 3);
    assert.equal(result.findings.filter((f) => f.severity === "critical").length, 1);
  });
});

test("a native build directory with a Hermes bundle is scanned like the package", async () => {
  await withTempDir({}, async (root) => {
    await writeFile(path.join(root, "index.android.bundle"), hermes([fake.stripeLiveKey()]));
    const result = await scanArtifact(root);
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0]!.evidence[0]?.kind === "file" && result.findings[0]!.evidence[0].path, "index.android.bundle (strings)");
  });
});

test("extractStrings reads ASCII and UTF-16LE runs and drops short noise", () => {
  const strings = extractStrings(Buffer.concat([Buffer.from("ab\0hello_world\0"), utf16("android:apiKey"), Buffer.alloc(2)]));
  assert.equal(strings[0], "hello_world");
  assert.ok(strings.some((value) => value.endsWith("android:apiKey")), strings.join("|"));
  assert.ok(!strings.includes("ab"));
});

test("a file that is not an app package is a clear error", async () => {
  await withTempDir({ "notes.txt": "hi" }, async (root) => {
    await assert.rejects(scanArtifact(path.join(root, "notes.txt")), /not a supported app package/);
  });
});

/** A Hermes v99-layout file: strings packed into one storage blob with no separators, as hermesc emits them. */
function hermesFile(strings: string[]): Buffer {
  const header = Buffer.alloc(128);
  Buffer.from([0xc6, 0x1f, 0xbc, 0x03, 0xc1, 0x03, 0x19, 0x1f]).copy(header, 0);
  header.writeUInt32LE(99, 8);
  const storage = Buffer.from(strings.join(""));
  header.writeUInt32LE(1, 40); // functionCount
  header.writeUInt32LE(strings.length, 52); // stringCount
  header.writeUInt32LE(storage.length, 60); // stringStorageSize
  const table = Buffer.alloc(strings.length * 4);
  let offset = 0;
  strings.forEach((value, i) => {
    table.writeUInt32LE(((offset << 1) | (value.length << 24)) >>> 0, i * 4);
    offset += value.length;
  });
  return Buffer.concat([header, Buffer.alloc(12), table, storage]);
}

test("Hermes string tables are read entry by entry, so a key packed between identifiers keeps its boundaries", async () => {
  const file = hermesFile(["renderItem", fake.stripeLiveKey(), "BILLING", "http://10.0.3.7:8080/admin"]);
  assert.deepEqual(hermesStrings(file), ["renderItem", fake.stripeLiveKey(), "BILLING", "http://10.0.3.7:8080/admin"]);
  // A plain strings pass sees one glued run, where the key has no word boundary.
  assert.ok(extractStrings(file).some((run) => run.includes(`renderItem${fake.stripeLiveKey()}BILLING`)));
  await withTempDir({}, async (root) => {
    await writeFile(path.join(root, "index.android.bundle"), file);
    const result = await scanArtifact(root);
    assert.ok(result.findings.some((f) => f.severity === "critical" && f.message.includes("Stripe")));
    assert.ok(result.findings.some((f) => f.message.includes("10.0.3.7")));
  });
});

test("a corrupt Hermes table falls back to a plain strings pass instead of failing", () => {
  const file = hermesFile(["abcdefgh"]);
  file.writeUInt32LE(999_999, 60 + 0); // storage size larger than the file
  assert.equal(hermesStrings(file), null);
});
