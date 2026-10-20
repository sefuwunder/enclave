// scan.ts — walk a source tree and detect secrets deterministically.
// Zero deps. Detectors: env entries, private-key blocks, known token
// shapes, secret-named assignments, and high-entropy quoted strings.
// Findings carry the exact span (line + start/end columns) so seal can
// replace precisely and restore can be byte-exact.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, basename, extname } from "node:path";
import { inflateSync } from "node:zlib";

export interface Finding {
  file: string;        // path relative to the scanned root
  line: number;        // 1-based (display)
  start: number;       // column offset of the secret within the line
  end: number;         // exclusive
  offsetStart: number; // absolute offset into the file content
  offsetEnd: number;   // exclusive (may span lines for private-key blocks)
  kind: string;        // env | private-key | aws-key-id | github-token | ...
  keyName: string;     // suggested vault name
  value: string;       // the detected secret (never printed by the CLI)
  meta?: string;       // for blobs: what personal data is present (no values)
  blob?: boolean;      // whole-file finding: seal stores bytes, not a span
}

export const SKIP_DIRS = new Set([
  ".git", "node_modules", ".enclave", "dist", "build", "vendor",
  ".next", ".turbo", "target", "__pycache__", ".venv",
]);
const SKIP_FILES = new Set([
  "bun.lockb", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
  "enclave.manifest.json",
]);
const BINARY_EXTS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz",
  ".tar", ".woff", ".woff2", ".ttf", ".otf", ".mp3", ".mp4", ".mov",
  ".bin", ".exe", ".dll", ".so", ".dylib", ".class", ".o", ".a", ".wasm",
]);
const MAX_FILE_BYTES = 1_000_000;

// Values that are obviously not real secrets.
const PLACEHOLDER_RE =
  /example|changeme|change-me|placeholder|your[-_ ]|xxxx|TODO|FIXME|\$\{|process\.env|os\.environ|getenv|import\.meta\.env|undefined|null|true|false|localhost|127\.0\.0\.1|enclave:/i;

export function shannonEntropy(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function isPlaceholder(value: string): boolean {
  if (value.length < 4) return true;
  if (PLACEHOLDER_RE.test(value)) return true;
  if (/^(.)\1+$/.test(value)) return true; // aaaa..., 0000...
  return false;
}

function slug(s: string): string {
  return s.replace(/[^A-Za-z0-9]+/g, "_").replace(/^_+|_+$/g, "").toUpperCase();
}

interface Rule { kind: string; re: RegExp; group: number }
const TOKEN_RULES: Rule[] = [
  { kind: "aws-key-id", re: /\b(AKIA[0-9A-Z]{16})\b/, group: 1 },
  { kind: "github-token", re: /\b(gh[pousr]_[A-Za-z0-9]{36,})\b/, group: 1 },
  { kind: "github-token", re: /\b(github_pat_[A-Za-z0-9_]{50,})\b/, group: 1 },
  { kind: "slack-token", re: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/, group: 1 },
  { kind: "stripe-key", re: /\b((?:sk|rk)_live_[A-Za-z0-9]{16,})\b/, group: 1 },
  { kind: "jwt", re: /\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b/, group: 1 },
  { kind: "private-key", re: /(-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----)/, group: 1 },
];

// key[:=] value where the key name smells like a secret (key may be quoted).
// Two shapes, calibrated by file kind (see fileKind below):
//  - QUOTED: the value is a string literal — counts in every file kind.
//  - BARE: an unquoted value — counts only outside code files. In code an
//    unquoted RHS is a reference (process.env.X, TOKEN_PREFIX), an
//    expression (arr[9]), or a regex literal, almost never a literal secret;
//    treating it as one was the main source of false positives in .ts/.py
//    sources. Even outside code, bare values that are plain references or
//    code fragments are filtered by looksLikeReference.
const SECRETY_KEYNAME = String.raw`[A-Za-z0-9_.-]*(?:api[_-]?key|secret|token|passwd|password|credential|private[_-]?key|access[_-]?key)[A-Za-z0-9_.-]*`;
const ASSIGN_QUOTED_RE = new RegExp(
  String.raw`["']?(${SECRETY_KEYNAME})["']?\s*[:=]\s*(["'\x60])((?:(?!\2)[^\\]|\\.)*)\2`, "i");
const ASSIGN_BARE_RE = new RegExp(
  String.raw`["']?(${SECRETY_KEYNAME})["']?\s*[:=]\s*["']?([^\s"'\x60,;]{8,})["']?`, "i");

// A bare (unquoted) value that is really a reference or a code fragment.
// Note what is NOT here: a plain alphanumeric word. In the file kinds the
// bare rule applies to (config, shell, docs) a bare word IS the literal
// value — shell needs $ to dereference, YAML has no bare references — so
// excluding identifier-shaped values would eat real hex/base tokens.
export function looksLikeReference(value: string): boolean {
  if (/[()\[\]{}]/.test(value)) return true;  // call, index, object fragment
  if (value.startsWith("$")) return true;     // shell-style $VAR / ${...} reference
  return false;
}

// A quoted string that is a character set, not a secret: long, almost all
// unique characters, with a long ascending run (alphabets, base64 tables,
// keyboard maps). Real random secrets are not sequential.
export function isCharsetConstant(value: string): boolean {
  if (value.length < 24) return false;
  if (new Set(value).size / value.length < 0.9) return false;
  let run = 1, maxRun = 1;
  for (let i = 1; i < value.length; i++) {
    run = value.charCodeAt(i) === value.charCodeAt(i - 1) + 1 ? run + 1 : 1;
    if (run > maxRun) maxRun = run;
  }
  return maxRun >= 10;
}
// any quoted string that could be a bare credential
const QUOTED_RE = /["']([A-Za-z0-9+/=_-]{20,})["']/g;
// personal data in text: SSNs anywhere (distinctive shape), emails in data files
const SSN_RE = /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/;
const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;
const DATA_FILE_EXTS = new Set([".csv", ".tsv", ".sql", ".json", ".xml", ".ndjson"]);

// File kinds calibrate the detectors: code files get the strict rules
// (quoted-literal assignments only, no bare high-entropy guesses at
// references), data files get PII email detection, everything else is
// general text/config where bare assignments are idiomatic (.yaml,
// .toml, shell scripts, Dockerfiles).
const CODE_EXTS = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts",
  ".py", ".rb", ".go", ".rs", ".java", ".kt", ".kts", ".swift", ".cs",
  ".php", ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".lua", ".pl", ".pm",
  ".r", ".scala", ".hs", ".ml", ".ex", ".exs", ".erl", ".clj", ".vim", ".el",
]);
export type FileKind = "code" | "data" | "text";
export function fileKind(rel: string): FileKind {
  const ext = extname(rel).toLowerCase();
  if (CODE_EXTS.has(ext)) return "code";
  if (DATA_FILE_EXTS.has(ext)) return "data";
  return "text";
}

function isEnvFile(name: string): boolean {
  return name === ".env" || name.startsWith(".env.") || name.endsWith(".env");
}

export function scanEnvContent(rel: string, content: string): Finding[] {
  // In a .env file, an entry counts as a secret when its key name is
  // secret-y, or the value is long / high-entropy. Short plain config
  // values (PORT=3000, PLAIN=hello) are left alone.
  const SECRETY_KEY = /key|secret|token|pass|credential|auth|private/i;
  const out: Finding[] = [];
  const lines = content.split("\n");
  let lineOffset = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const m = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (m) {
      let raw = m[2].trim();
      if ((raw.startsWith('"') && raw.endsWith('"')) || (raw.startsWith("'") && raw.endsWith("'"))) {
        raw = raw.slice(1, -1);
      }
      const looksSecret = SECRETY_KEY.test(m[1]) || raw.length >= 12 ||
        (raw.length >= 8 && shannonEntropy(raw) >= 4.2);
      if (!isPlaceholder(raw) && looksSecret) {
        const valStart = line.indexOf(raw);
        out.push({
          file: rel, line: i + 1, start: valStart, end: valStart + raw.length,
          offsetStart: lineOffset + valStart, offsetEnd: lineOffset + valStart + raw.length,
          kind: "env", keyName: m[1], value: raw,
        });
      }
    }
    lineOffset += line.length + 1;
  }
  return out;
}

export function scanTextContent(rel: string, content: string): Finding[] {
  const kind = fileKind(rel);
  const out: Finding[] = [];
  const seen = new Set<string>(); // line:start dedupe across rules
  const lines = content.split("\n");
  let lineOffset = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const push = (f: Finding) => {
      const k = `${f.line}:${f.start}:${f.end}`;
      if (seen.has(k)) return;
      seen.add(k);
      out.push(f);
    };
    for (const rule of TOKEN_RULES) {
      const m = line.match(rule.re);
      if (m && m.index !== undefined) {
        const marker = m[rule.group];
        const start = line.indexOf(marker, m.index);
        if (rule.kind === "private-key") {
          // expand to the whole BEGIN…END block (may span lines)
          const blockStart = content.indexOf(marker, lineOffset);
          const endMarker = marker.replace("BEGIN", "END");
          const blockEndIdx = content.indexOf(endMarker, blockStart);
          if (blockEndIdx !== -1) {
            const blockEnd = blockEndIdx + endMarker.length;
            push({
              file: rel, line: i + 1, start, end: start + marker.length,
              offsetStart: blockStart, offsetEnd: blockEnd,
              kind: rule.kind,
              keyName: slug(basename(rel).replace(/\.[^.]*$/, "") + "_" + rule.kind),
              value: content.slice(blockStart, blockEnd),
            });
            continue;
          }
        }
        push({
          file: rel, line: i + 1, start, end: start + marker.length,
          offsetStart: lineOffset + start, offsetEnd: lineOffset + start + marker.length,
          kind: rule.kind,
          keyName: slug(basename(rel).replace(/\.[^.]*$/, "") + "_" + rule.kind),
          value: marker,
        });
      }
    }
    // assignment detectors: a quoted string literal counts in any file;
    // a bare value counts only outside code (and never when it is really
    // a reference or code fragment). See the regex definitions above.
    const qa = line.match(ASSIGN_QUOTED_RE);
    if (qa && qa.index !== undefined) {
      const value = qa[3];
      if (value.length >= 8 && !isPlaceholder(value)) {
        const start = qa.index + qa[0].lastIndexOf(value);
        push({
          file: rel, line: i + 1, start, end: start + value.length,
          offsetStart: lineOffset + start, offsetEnd: lineOffset + start + value.length,
          kind: "assignment", keyName: slug(qa[1]), value,
        });
      }
    } else if (kind !== "code") {
      const am = line.match(ASSIGN_BARE_RE);
      if (am && am.index !== undefined) {
        const value = am[2];
        if (!isPlaceholder(value) && !looksLikeReference(value)) {
          const start = line.lastIndexOf(value);
          push({
            file: rel, line: i + 1, start, end: start + value.length,
            offsetStart: lineOffset + start, offsetEnd: lineOffset + start + value.length,
            kind: "assignment", keyName: slug(am[1]), value,
          });
        }
      }
    }
    // bare high-entropy quoted strings (lower confidence, still sealed)
    QUOTED_RE.lastIndex = 0;
    let qm: RegExpExecArray | null;
    while ((qm = QUOTED_RE.exec(line)) !== null) {
      const value = qm[1];
      if (isPlaceholder(value)) continue;
      if (isCharsetConstant(value)) continue; // alphabets / base64 tables, not secrets
      const hasUpper = /[A-Z]/.test(value), hasLower = /[a-z]/.test(value), hasDigit = /[0-9]/.test(value);
      if (!(hasUpper && hasLower && hasDigit)) continue;
      if (shannonEntropy(value) < 4.3) continue;
      const start = line.indexOf(value, qm.index);
      push({
        file: rel, line: i + 1, start, end: start + value.length,
        offsetStart: lineOffset + start, offsetEnd: lineOffset + start + value.length,
        kind: "high-entropy",
        keyName: slug(basename(rel).replace(/\.[^.]*$/, "") + "_SECRET_" + (i + 1)),
        value,
      });
    }
    // PII: SSNs anywhere; emails only in data files (code has contacts, dumps have people)
    const sm = line.match(SSN_RE);
    if (sm && sm.index !== undefined) {
      push({
        file: rel, line: i + 1, start: sm.index, end: sm.index + sm[0].length,
        offsetStart: lineOffset + sm.index, offsetEnd: lineOffset + sm.index + sm[0].length,
        kind: "pii-ssn",
        keyName: slug(basename(rel).replace(/\.[^.]*$/, "") + "_SSN_" + (i + 1)),
        value: sm[0],
      });
    }
    if (kind === "data") {
      const em = line.match(EMAIL_RE);
      if (em && em.index !== undefined) {
        push({
          file: rel, line: i + 1, start: em.index, end: em.index + em[0].length,
          offsetStart: lineOffset + em.index, offsetEnd: lineOffset + em.index + em[0].length,
          kind: "pii-email",
          keyName: slug(basename(rel).replace(/\.[^.]*$/, "") + "_EMAIL_" + (i + 1)),
          value: em[0],
        });
      }
    }
    lineOffset += line.length + 1;
  }
  return out;
}

/* ============================== binary blobs ============================== */
// Whole-file findings for binary blobs carrying personal data. Metadata is
// reported as a list of WHAT is present (GPS, author, …), never the values.

const KEY_MATERIAL_EXTS = new Set([".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".der", ".crt", ".cer"]);
const MAX_BLOB_BYTES = 25_000_000;

// --- minimal TIFF/EXIF walk: which personal tags are present? ---
function exifTags(tiff: Buffer): Set<string> {
  const tags = new Set<string>();
  try {
    if (tiff.length < 8) return tags;
    const le = tiff[0] === 0x49 && tiff[1] === 0x49; // "II"
    const mm = tiff[0] === 0x4d && tiff[1] === 0x4d; // "MM"
    if (!le && !mm) return tags;
    const u16 = (o: number) => (le ? tiff.readUInt16LE(o) : tiff.readUInt16BE(o));
    const u32 = (o: number) => (le ? tiff.readUInt32LE(o) : tiff.readUInt32BE(o));
    if (u16(2) !== 42) return tags;
    const NAMES: Record<number, string> = {
      0x010f: "Make", 0x0110: "Model", 0x013b: "Artist", 0x0132: "DateTime",
      0x8298: "Copyright", 0x02bc: "XMP",
    };
    const walkIfd = (off: number, isGps: boolean) => {
      if (off <= 0 || off + 2 > tiff.length) return;
      const n = u16(off);
      for (let i = 0; i < n; i++) {
        const e = off + 2 + i * 12;
        if (e + 12 > tiff.length) break;
        const tag = u16(e);
        if (isGps) {
          if (tag === 0x0002 || tag === 0x0004) tags.add("GPS");
        } else if (tag === 0x8825) {
          tags.add("GPS");
          walkIfd(u32(e + 8), true);
        } else if (NAMES[tag]) tags.add(NAMES[tag]);
      }
    };
    walkIfd(u32(4), false);
  } catch { /* malformed EXIF — presence was already established */ }
  return tags;
}

function jpegExif(buf: Buffer): Set<string> | null {
  // FFD8 then segments; find APP1 "Exif\0\0"
  let off = 2;
  while (off + 4 < buf.length && off < 131072) {
    if (buf[off] !== 0xff) break;
    const marker = buf[off + 1];
    if (marker === 0xda || marker === 0xd9) break; // SOS / EOI
    const len = buf.readUInt16BE(off + 2);
    if (len < 2) break;
    if (marker === 0xe1 && buf.slice(off + 4, off + 10).toString("latin1") === "Exif\0\0") {
      return exifTags(buf.subarray(off + 10, off + 2 + len));
    }
    off += 2 + len;
  }
  return null;
}

function pngPersonal(buf: Buffer): Set<string> | null {
  const found = new Set<string>();
  let off = 8;
  while (off + 12 < buf.length && off < 2_000_000) {
    const len = buf.readUInt32BE(off);
    const type = buf.slice(off + 4, off + 8).toString("latin1");
    const data = buf.subarray(off + 8, Math.min(off + 8 + len, buf.length));
    if (type === "eXIf") {
      for (const t of exifTags(data)) found.add(t);
      found.add("EXIF");
    } else if (type === "tEXt" || type === "iTXt" || type === "zTXt") {
      const text = data.toString("latin1");
      const kw = text.split("\0")[0];
      if (/author|artist|copyright|description|comment/i.test(kw)) found.add("text:" + kw);
      if (/GPS/i.test(text)) found.add("GPS");
    }
    if (type === "IEND") break;
    off += 12 + len;
  }
  return found.size ? found : null;
}

function pdfPersonal(buf: Buffer): Set<string> | null {
  const text = buf.toString("latin1");
  const found = new Set<string>();
  for (const key of ["Author", "Creator", "Producer", "Title", "Keywords", "Company"]) {
    if (new RegExp("/" + key + "\\s*[\\(<]").test(text)) found.add(key);
  }
  if (/dc:creator|xmp:CreatorTool|photoshop:Credit/i.test(text)) found.add("XMP");
  return found.size ? found : null;
}

function zipPersonal(buf: Buffer): { meta: string } | null {
  // locate End Of Central Directory
  const tailStart = Math.max(0, buf.length - 65558);
  let eocd = -1;
  for (let i = buf.length - 22; i >= tailStart; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd === -1) return null;
  const count = buf.readUInt16LE(eocd + 10);
  let off = buf.readUInt32LE(eocd + 16);
  const names: string[] = [];
  let coreXml: { method: number; compSize: number; localOff: number } | null = null;
  for (let i = 0; i < count && off + 46 <= buf.length; i++) {
    if (buf.readUInt32LE(off) !== 0x02014b50) break;
    const method = buf.readUInt16LE(off + 10);
    const compSize = buf.readUInt32LE(off + 20);
    const nameLen = buf.readUInt16LE(off + 28);
    const extraLen = buf.readUInt16LE(off + 30);
    const commentLen = buf.readUInt16LE(off + 32);
    const localOff = buf.readUInt32LE(off + 42);
    const name = buf.slice(off + 46, off + 46 + nameLen).toString("utf8");
    names.push(name);
    if (name === "docProps/core.xml") coreXml = { method, compSize, localOff };
    off += 46 + nameLen + extraLen + commentLen;
  }
  if (coreXml) {
    const parts = ["Office document"];
    try {
      const lo = coreXml.localOff;
      const nLen = buf.readUInt16LE(lo + 26), eLen = buf.readUInt16LE(lo + 28);
      const dataStart = lo + 30 + nLen + eLen;
      const raw = buf.subarray(dataStart, dataStart + coreXml.compSize);
      const xml = coreXml.method === 8
        ? inflateSync(raw).toString("utf8")
        : raw.toString("utf8");
      if (/<dc:creator>/.test(xml)) parts.push("creator");
      if (/<cp:lastModifiedBy>/.test(xml)) parts.push("lastModifiedBy");
      if (/<dc:title>/.test(xml)) parts.push("title");
      if (/<cp:company>/i.test(xml)) parts.push("company");
    } catch { /* metadata unreadable — the docProps presence already counts */ }
    return { meta: parts.join(" · ") };
  }
  return { meta: `archive · ${count} entr${count === 1 ? "y" : "ies"} (contents opaque)` };
}

// Returns a blob Finding (or null) for a file buffer.
export function scanBlob(rel: string, buf: Buffer): Finding | null {
  const ext = extname(rel).toLowerCase();
  const base = basename(rel).replace(/\.[^.]*$/, "");
  const mk = (kind: string, meta: string): Finding => ({
    file: rel, line: 1, start: 0, end: 0, offsetStart: 0, offsetEnd: buf.length,
    kind, keyName: slug(base + "_" + kind.replace("blob:", "")), value: "", meta, blob: true,
  });
  if (buf.length >= 16 && buf.slice(0, 16).toString("latin1") === "SQLite format 3\0") {
    return mk("blob:database", "SQLite database — rows may hold personal data");
  }
  if (KEY_MATERIAL_EXTS.has(ext)) {
    return mk("blob:key-material", "key/certificate material (" + ext + ")");
  }
  if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) {
    const tags = jpegExif(buf);
    if (tags && (tags.has("GPS") || tags.has("Make") || tags.has("Model") || tags.has("Artist"))) {
      return mk("blob:photo-exif", "EXIF: " + [...tags].sort().join(", "));
    }
    return null;
  }
  if (buf.length >= 8 && buf.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) {
    const found = pngPersonal(buf);
    if (found) return mk("blob:image-meta", "PNG metadata: " + [...found].sort().join(", "));
    return null;
  }
  if (buf.length >= 5 && buf.slice(0, 5).toString("latin1") === "%PDF-") {
    const found = pdfPersonal(buf);
    if (found) return mk("blob:pdf-meta", "PDF metadata: " + [...found].sort().join(", "));
    return null;
  }
  if (buf.length >= 4 && buf.readUInt32LE(0) === 0x04034b50) {
    const z = zipPersonal(buf);
    if (z) return mk(ext === ".docx" || ext === ".xlsx" || ext === ".pptx" ? "blob:office" : "blob:archive", z.meta);
    return null;
  }
  if (buf.length >= 8 && buf.slice(0, 8).equals(Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]))) {
    return mk("blob:office", "legacy Office (OLE) document");
  }
  return null;
}

function loadIgnore(root: string): RegExp[] {
  try {
    const text = readFileSync(join(root, ".enclaveignore"), "utf8");
    return text.split("\n").map((s) => s.trim()).filter((s) => s && !s.startsWith("#"))
      .map((pat) => new RegExp("^" + pat.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$"));
  } catch { return []; }
}

export function scanTree(root: string): Finding[] {
  const findings: Finding[] = [];
  const ignore = loadIgnore(root);
  const walk = (dir: string) => {
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const full = join(dir, e.name);
      const rel = relative(root, full);
      if (ignore.some((re) => re.test(rel))) continue;
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) walk(full);
        continue;
      }
      if (!e.isFile() || SKIP_FILES.has(e.name)) continue;
      let st;
      try { st = statSync(full); } catch { continue; }
      if (st.size === 0 || st.size > MAX_BLOB_BYTES) continue;
      let buf: Buffer;
      try { buf = readFileSync(full); } catch { continue; }
      // sealed blob tombstones are pointers, not findings
      if (buf.slice(0, 13).toString("latin1") === "enclave-blob:") continue;
      const blobFinding = scanBlob(rel, buf);
      if (blobFinding) { findings.push(blobFinding); continue; }
      if (BINARY_EXTS.has(extname(e.name).toLowerCase())) continue;
      if (st.size > MAX_FILE_BYTES) continue;
      const content = buf.toString("utf8");
      if (content.slice(0, 4096).includes("\0")) continue; // binary
      if (isEnvFile(e.name)) findings.push(...scanEnvContent(rel, content));
      else findings.push(...scanTextContent(rel, content));
    }
  };
  walk(root);
  // unique vault names: suffix duplicates deterministically
  const used = new Map<string, number>();
  for (const f of findings) {
    const n = (used.get(f.keyName) || 0) + 1;
    used.set(f.keyName, n);
    if (n > 1) f.keyName = `${f.keyName}_${n}`;
  }
  return findings.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.start - b.start);
}

export function mask(value: string): string {
  if (value.length <= 4) return "••••";
  return "••••" + value.slice(-4);
}
