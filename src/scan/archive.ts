/**
 * Packaged apps as artifacts: Android (.apk, .aab), iOS (.ipa) and Electron
 * (.asar). Everything inside ships to the user's device, so everything a
 * rule can read is scanned. No dependencies: zip is parsed here and inflated
 * with node:zlib; ASAR is a JSON header followed by file bytes.
 *
 * Text entries are decoded as UTF-8. Binary entries that carry the strings an
 * attacker would read (Hermes bytecode, DEX, compiled Android XML and
 * resources, binary plists, Mach-O executables) are reduced to their
 * printable strings, one per line, so the same rules apply; a finding's
 * line is then the string's index, and its path ends in " (strings)".
 */
import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { inflateRawSync } from "node:zlib";

import type { ScannedFile } from "./files.ts";

export type ArchiveKind = "android" | "ios" | "electron";

const MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024;
const MAX_ENTRY_BYTES = 100 * 1024 * 1024;

const TEXT_ENTRY = /\.(?:m?js|cjs|jsx|ts|tsx|json|html?|css|xml|plist|txt|svg|map|bundle|jsbundle|webmanifest|properties|strings)$/i;
/** Binary formats whose string tables hold what developers embed: keys, URLs, config. */
const STRINGS_ENTRY = /(?:\.(?:dex|hbc|arsc|bundle|jsbundle|plist)$|(?:^|\/)AndroidManifest\.xml$)/i;
const SKIP_ENTRY = /\.(?:png|jpe?g|gif|webp|ico|ttf|otf|woff2?|mp3|mp4|ogg|wav|so|dylib|car|nib|storyboardc|RSA|DSA|EC|SF|MF)$|(?:^|\/)(?:META-INF\/|_CodeSignature\/)/i;

/** Hermes bytecode magic, little-endian 0x1F1903C103BC1FC6. */
const HERMES_MAGIC = Buffer.from([0xc6, 0x1f, 0xbc, 0x03, 0xc1, 0x03, 0x19, 0x1f]);

export function archiveKind(file: string, head: Buffer): ArchiveKind | null {
  const ext = path.extname(file).toLowerCase();
  if (ext === ".asar") return "electron";
  if (head.length < 4 || head.readUInt32LE(0) !== 0x04034b50) return null;
  if (ext === ".ipa") return "ios";
  if (ext === ".apk" || ext === ".aab" || ext === ".xapk") return "android";
  return null;
}

interface Entry {
  name: string;
  read(): Buffer;
}

function zipEntries(buffer: Buffer): Entry[] {
  // End of central directory: last 22..65557 bytes.
  let eocd = -1;
  for (let i = buffer.length - 22; i >= Math.max(0, buffer.length - 65557); i -= 1) {
    if (buffer.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error("not a zip archive (no end of central directory)");
  const count = buffer.readUInt16LE(eocd + 10);
  let offset = buffer.readUInt32LE(eocd + 16);
  const entries: Entry[] = [];
  for (let i = 0; i < count; i += 1) {
    if (buffer.readUInt32LE(offset) !== 0x02014b50) throw new Error("corrupt zip central directory");
    const method = buffer.readUInt16LE(offset + 10);
    const compressed = buffer.readUInt32LE(offset + 20);
    const size = buffer.readUInt32LE(offset + 24);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const local = buffer.readUInt32LE(offset + 42);
    const name = buffer.toString("utf8", offset + 46, offset + 46 + nameLength);
    offset += 46 + nameLength + extraLength + commentLength;
    if (name.endsWith("/") || size > MAX_ENTRY_BYTES || compressed === 0xffffffff) continue;
    entries.push({
      name,
      read() {
        const start = local + 30 + buffer.readUInt16LE(local + 26) + buffer.readUInt16LE(local + 28);
        const data = buffer.subarray(start, start + compressed);
        if (method === 0) return data;
        if (method === 8) return inflateRawSync(data, { maxOutputLength: MAX_ENTRY_BYTES });
        throw new Error(`unsupported zip compression method ${method} for ${name}`);
      },
    });
  }
  return entries;
}

function asarEntries(buffer: Buffer): Entry[] {
  // Pickle: [u32 4][u32 headerPickleSize] then [u32 payload][u32 jsonLength][json…].
  const headerSize = buffer.readUInt32LE(4);
  const jsonLength = buffer.readUInt32LE(12);
  const header = JSON.parse(buffer.toString("utf8", 16, 16 + jsonLength)) as AsarNode;
  const base = 8 + headerSize;
  const entries: Entry[] = [];
  const walk = (node: AsarNode, prefix: string): void => {
    for (const [name, child] of Object.entries(node.files ?? {})) {
      const full = prefix === "" ? name : `${prefix}/${name}`;
      if (child.files !== undefined) walk(child, full);
      else if (child.offset !== undefined && child.size !== undefined && child.unpacked !== true && child.size <= MAX_ENTRY_BYTES) {
        const start = base + Number(child.offset);
        const size = child.size;
        entries.push({ name: full, read: () => buffer.subarray(start, start + size) });
      }
    }
  };
  walk(header, "");
  return entries;
}

interface AsarNode {
  files?: Record<string, AsarNode>;
  offset?: string;
  size?: number;
  unpacked?: boolean;
}

/** Printable runs of at least `min` characters, ASCII/UTF-8 and UTF-16LE (Android string pools). */
export function extractStrings(buffer: Buffer, min = 6): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const add = (value: string) => {
    if (value.length >= min && !seen.has(value)) {
      seen.add(value);
      out.push(value);
    }
  };
  let start = -1;
  for (let i = 0; i <= buffer.length; i += 1) {
    const byte = i < buffer.length ? buffer[i]! : 0;
    const printable = (byte >= 0x20 && byte < 0x7f) || byte === 0x09;
    if (printable && start < 0) start = i;
    if (!printable && start >= 0) {
      add(buffer.toString("latin1", start, i));
      start = -1;
    }
  }
  // UTF-16LE: printable ASCII byte followed by 0x00, at either byte alignment.
  for (const alignment of [0, 1]) {
    let run = "";
    for (let i = alignment; i + 1 < buffer.length; i += 2) {
      const lo = buffer[i]!;
      if (buffer[i + 1] === 0 && lo >= 0x20 && lo < 0x7f) run += String.fromCharCode(lo);
      else {
        add(run);
        run = "";
      }
    }
    add(run);
  }
  return out;
}

/**
 * Hermes keeps every string literal and identifier in one storage blob with
 * no separators, so a plain strings pass glues neighbours together and a key
 * loses its word boundaries. Read the string table instead. The header is
 * 128 bytes; the counts sit at fixed offsets; the sections that follow are
 * 4-byte aligned. Function headers are 12 bytes in current versions (99,
 * Expo SDK 58) and 16 in older ones, so both layouts are tried and the one
 * whose every entry fits inside the storage wins. Returns null when neither
 * does, and the caller falls back to a plain strings pass.
 */
export function hermesStrings(buffer: Buffer): string[] | null {
  if (buffer.length < 128) return null;
  const u32 = (offset: number) => buffer.readUInt32LE(offset);
  const align = (value: number) => Math.ceil(value / 4) * 4;
  const functionCount = u32(40);
  const stringKindCount = u32(44);
  const identifierCount = u32(48);
  const stringCount = u32(52);
  const overflowCount = u32(56);
  const storageSize = u32(60);
  for (const functionHeaderSize of [12, 16]) {
    let offset = 128;
    offset = align(offset + functionCount * functionHeaderSize);
    offset = align(offset + stringKindCount * 4);
    offset = align(offset + identifierCount * 4);
    const small = offset;
    offset = align(offset + stringCount * 4);
    const overflow = offset;
    offset = align(offset + overflowCount * 8);
    const storage = offset;
    if (storage + storageSize > buffer.length) continue;
    const strings: string[] = [];
    let valid = true;
    for (let i = 0; i < stringCount && valid; i += 1) {
      const entry = u32(small + i * 4);
      const utf16 = (entry & 1) === 1;
      let start = (entry >>> 1) & 0x7fffff;
      let length = entry >>> 24;
      if (length === 255) {
        if (start >= overflowCount) {
          valid = false;
          break;
        }
        const at = overflow + start * 8;
        start = u32(at);
        length = u32(at + 4);
      }
      const bytes = utf16 ? length * 2 : length;
      if (start + bytes > storageSize) valid = false;
      else if (length > 0) strings.push(buffer.toString(utf16 ? "utf16le" : "latin1", storage + start, storage + start + bytes));
    }
    if (valid) return strings;
  }
  return null;
}

function looksBinary(buffer: Buffer): boolean {
  const end = Math.min(buffer.length, 8192);
  for (let i = 0; i < end; i += 1) if (buffer[i] === 0) return true;
  return false;
}

/** Turn one archive entry, or a loose file from an extracted app, into what rules read. */
export function toScanned(name: string, data: Buffer, location: string): ScannedFile | null {
  if (data.length === 0 || SKIP_ENTRY.test(name)) return null;
  const isHermes = data.length >= 8 && data.subarray(0, 8).equals(HERMES_MAGIC);
  if (!isHermes && TEXT_ENTRY.test(name) && !looksBinary(data)) {
    return { absolutePath: location, relativePath: name, text: data.toString("utf8") };
  }
  if (isHermes || STRINGS_ENTRY.test(name) || isMainExecutable(name, data)) {
    const strings = (isHermes ? hermesStrings(data) : null) ?? extractStrings(data);
    // One string per line; a multi-line literal stays readable but cannot merge with its neighbour.
    return { absolutePath: location, relativePath: `${name} (strings)`, text: strings.map((s) => s.replace(/\n/g, " ")).join("\n") };
  }
  return null;
}

/** The iOS app executable: Payload/Name.app/Name, a Mach-O file. */
function isMainExecutable(name: string, data: Buffer): boolean {
  const match = /^Payload\/([^/]+)\.app\/([^/]+)$/.exec(name);
  if (match === null || match[1] !== match[2] || data.length < 4) return false;
  const magic = data.readUInt32LE(0);
  return magic === 0xfeedfacf || magic === 0xfeedface || magic === 0xcafebabe || magic === 0xbebafeca;
}

export async function collectArchive(file: string): Promise<{ kind: ArchiveKind; files: ScannedFile[] }> {
  const info = await stat(file);
  if (info.size > MAX_ARCHIVE_BYTES) throw new Error(`${file} is larger than ${MAX_ARCHIVE_BYTES / 1024 / 1024} MiB`);
  const buffer = await readFile(file);
  const kind = archiveKind(file, buffer);
  if (kind === null) throw new Error(`not a supported app package (.apk, .aab, .ipa, .asar): ${file}`);
  const entries = kind === "electron" ? asarEntries(buffer) : zipEntries(buffer);
  const files: ScannedFile[] = [];
  for (const entry of entries) {
    if (entry.name.split("/").includes("node_modules") && kind !== "electron") continue;
    const scanned = toScanned(entry.name, entry.read(), `${file}!/${entry.name}`);
    if (scanned !== null) files.push(scanned);
  }
  files.sort((a, b) => (a.relativePath < b.relativePath ? -1 : 1));
  return { kind, files };
}
