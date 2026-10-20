// enclave tests — vault crypto, scanner detectors, and a full
// seal -> verify -> restore roundtrip on a temp fixture tree (byte-exact).
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync, writeFileSync, readFileSync, mkdirSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { encryptVaultPassphrase, decryptPassphrase, emptyVault, type VaultData } from "../src/vault.ts";
import { scanTextContent, scanEnvContent, scanTree, scanBlob, shannonEntropy, isPlaceholder } from "../src/scan.ts";

describe("vault crypto", () => {
  const data: VaultData = {
    project: "demo", createdAt: new Date().toISOString(),
    entries: [{ name: "API_KEY", value: "super-secret-value", file: ".env", kind: "env", sealedAt: new Date().toISOString() }],
  };
  test("roundtrip", () => {
    const enc = encryptVaultPassphrase(data, "hunter2");
    const dec = decryptPassphrase(enc, "hunter2");
    expect(dec.entries[0].value).toBe("super-secret-value");
  });
  test("ciphertext contains no plaintext", () => {
    const enc = encryptVaultPassphrase(data, "hunter2");
    expect(JSON.stringify(enc)).not.toContain("super-secret");
  });
  test("wrong passphrase throws", () => {
    const enc = encryptVaultPassphrase(data, "hunter2");
    expect(() => decryptPassphrase(enc, "wrong")).toThrow();
  });
  test("tampered ciphertext throws", () => {
    const enc = encryptVaultPassphrase(data, "hunter2");
    const raw = Buffer.from(enc.data, "base64");
    raw[0] = raw[0] ^ 0xff;
    enc.data = raw.toString("base64");
    expect(() => decryptPassphrase(enc, "hunter2")).toThrow();
  });
  test("empty vault", () => {
    const v = emptyVault("x");
    expect(v.entries).toEqual([]);
  });
});

describe("scanner detectors", () => {
  test("aws key id (documented example key)", () => {
    const f = scanTextContent("a.ts", "const id = 'AKIAIOSFODNN7EXAMPLE';");
    expect(f.some((x) => x.kind === "aws-key-id")).toBe(true);
  });
  test("github token shape", () => {
    const f = scanTextContent("a.ts", "const t = 'ghp_" + "A".repeat(36) + "';");
    expect(f.some((x) => x.kind === "github-token")).toBe(true);
  });
  test("generic assignment with secret-y name", () => {
    const f = scanTextContent("cfg.py", 'db_password = "Tr0ub4dor&3-secret"');
    expect(f.some((x) => x.kind === "assignment" && x.keyName.includes("PASSWORD"))).toBe(true);
  });
  test("quoted dict key assignment (JSON/Python style)", () => {
    const f = scanTextContent("cfg.py", '    "db_password": "Tr0ub4dor&3-secret",');
    const a = f.find((x) => x.kind === "assignment");
    expect(a).toBeDefined();
    expect(a!.value).toBe("Tr0ub4dor&3-secret");
  });
  test("ignores placeholders and env lookups", () => {
    const src = [
      'const a = process.env.API_KEY;',
      'api_key = "your-api-key-here"',
      'token = "changeme-changeme"',
      'secret = "example-secret-value"',
    ].join("\n");
    const f = scanTextContent("a.ts", src);
    expect(f.length).toBe(0);
  });
  test("private key block expands to full block", () => {
    const BEGIN = "-----BEGIN " + "PRIVATE KEY-----"; // assembled: keeps scanners calm
    const END = "-----END " + "PRIVATE KEY-----";
    const src = "const k = `\n" + BEGIN + "\nMIIBVAIBADANBg==\nabc123\n" + END + "\n`;";
    const f = scanTextContent("k.ts", src);
    const pk = f.find((x) => x.kind === "private-key");
    expect(pk).toBeDefined();
    expect(pk!.value).toContain("MIIBVAIBADANBg==");
    expect(pk!.value.endsWith(END)).toBe(true);
    expect(src.slice(pk!.offsetStart, pk!.offsetEnd)).toBe(pk!.value);
  });
  test("env entries parsed with exact spans", () => {
    const content = "# comment\nAPI_KEY=abc123def456\nEMPTY=\nQUOTED=\"shhh-secret-789\"\n";
    const f = scanEnvContent(".env", content);
    expect(f.map((x) => x.keyName)).toEqual(["API_KEY", "QUOTED"]);
    for (const x of f) expect(content.slice(x.offsetStart, x.offsetEnd)).toBe(x.value);
  });
  test("entropy sanity", () => {
    expect(shannonEntropy("aaaaaaaaaaaaaaaa")).toBe(0);
    expect(shannonEntropy("Xk9$mQ2vLp8wR4nZ7bH3")).toBeGreaterThan(4);
  });
  test("isPlaceholder", () => {
    expect(isPlaceholder("enclave:FOO")).toBe(true);
    expect(isPlaceholder("real-value-123")).toBe(false);
    expect(isPlaceholder("abc")).toBe(true);
  });
});

describe("blob detectors", () => {
  // minimal little-endian TIFF: IFD0{ Make, GPSInfo->GPS IFD{ GPSLatitude } }
  function exifJpeg(): Buffer {
    const tiff = Buffer.alloc(8 + 2 + 2 * 12 + 4 + 6 + 2 + 12 + 4);
    tiff.write("II", 0, "latin1"); tiff.writeUInt16LE(42, 2); tiff.writeUInt32LE(8, 4);
    tiff.writeUInt16LE(2, 8); // IFD0: 2 entries
    // Make (0x010F), ASCII, count 6, value offset -> 38
    tiff.writeUInt16LE(0x010f, 10); tiff.writeUInt16LE(2, 12); tiff.writeUInt32LE(6, 14); tiff.writeUInt32LE(38, 18);
    // GPSInfo (0x8825), LONG, count 1, value = GPS IFD offset 44
    tiff.writeUInt16LE(0x8825, 22); tiff.writeUInt16LE(4, 24); tiff.writeUInt32LE(1, 26); tiff.writeUInt32LE(44, 30);
    tiff.writeUInt32LE(0, 34); // next IFD
    tiff.write("Canon\0", 38, "latin1");
    tiff.writeUInt16LE(1, 44); // GPS IFD: 1 entry
    tiff.writeUInt16LE(0x0002, 46); tiff.writeUInt16LE(5, 48); tiff.writeUInt32LE(3, 50); tiff.writeUInt32LE(0, 54);
    tiff.writeUInt32LE(0, 58);
    const app1 = Buffer.concat([Buffer.from("Exif\0\0", "latin1"), tiff]);
    const head = Buffer.alloc(4);
    head[0] = 0xff; head[1] = 0xd8; head[2] = 0xff; head[3] = 0xe1;
    const len = Buffer.alloc(2); len.writeUInt16BE(app1.length + 2, 0);
    return Buffer.concat([head, len, app1, Buffer.from([0xff, 0xd9])]);
  }
  test("jpeg EXIF with GPS + Make is flagged", () => {
    const f = scanBlob("photo.jpg", exifJpeg());
    expect(f).not.toBeNull();
    expect(f!.kind).toBe("blob:photo-exif");
    expect(f!.meta).toContain("GPS");
    expect(f!.meta).toContain("Make");
  });
  test("jpeg without EXIF is not flagged", () => {
    const plain = Buffer.from([0xff, 0xd8, 0xff, 0xd9]);
    expect(scanBlob("plain.jpg", plain)).toBeNull();
  });
  test("pdf metadata flagged by key presence", () => {
    const pdf = Buffer.from("%PDF-1.4\n1 0 obj<</Author (Jane Doe)/Creator (Word)>>endobj\n%%EOF", "latin1");
    const f = scanBlob("report.pdf", pdf);
    expect(f!.kind).toBe("blob:pdf-meta");
    expect(f!.meta).toContain("Author");
    expect(f!.meta).not.toContain("Jane");
  });
  test("sqlite header flagged as database", () => {
    const db = Buffer.concat([Buffer.from("SQLite format 3\0", "latin1"), Buffer.alloc(100)]);
    expect(scanBlob("app.db", db)!.kind).toBe("blob:database");
  });
  test("key material by extension", () => {
    const pem = Buffer.from("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n");
    expect(scanBlob("client.pem", pem)!.kind).toBe("blob:key-material");
  });
  test("stored-zip docx with creator metadata", () => {
    // hand-rolled STORED zip: docProps/core.xml + word/document.xml
    const files: [string, string][] = [
      ["docProps/core.xml", "<cp:coreProperties><dc:creator>Jane Doe</dc:creator><cp:lastModifiedBy>Jane</cp:lastModifiedBy></cp:coreProperties>"],
      ["word/document.xml", "<w:document/>"],
    ];
    const chunks: Buffer[] = [], central: Buffer[] = [];
    let off = 0;
    for (const [name, body] of files) {
      const data = Buffer.from(body), nb = Buffer.from(name);
      const lh = Buffer.alloc(30);
      lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt32LE(data.length, 18); lh.writeUInt32LE(data.length, 22);
      lh.writeUInt16LE(nb.length, 26);
      chunks.push(lh, nb, data);
      const ch = Buffer.alloc(46);
      ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt32LE(data.length, 20); ch.writeUInt32LE(data.length, 24);
      ch.writeUInt16LE(nb.length, 28); ch.writeUInt32LE(off, 42);
      central.push(ch, nb);
      off += 30 + nb.length + data.length;
    }
    const cd = Buffer.concat(central);
    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(files.length, 10);
    eocd.writeUInt32LE(cd.length, 12); eocd.writeUInt32LE(off, 16);
    const zip = Buffer.concat([...chunks, cd, eocd]);
    const f = scanBlob("letter.docx", zip);
    expect(f!.kind).toBe("blob:office");
    expect(f!.meta).toContain("creator");
    expect(f!.meta).toContain("lastModifiedBy");
    expect(f!.meta).not.toContain("Jane");
  });
  test("plain zip is an opaque archive", () => {
    const zip = Buffer.alloc(22);
    zip.writeUInt32LE(0x06054b50, 0);
    // needs a PK\x03\x04 start to be seen as zip by magic — prepend empty local header
    const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0);
    const f = scanBlob("backup.zip", Buffer.concat([lh, zip]));
    expect(f!.kind).toBe("blob:archive");
  });
});

describe("PII detectors", () => {
  test("SSN shape flagged anywhere", () => {
    const f = scanTextContent("notes.txt", "his ssn is 078-05-1120 ok");
    expect(f.some((x) => x.kind === "pii-ssn")).toBe(true);
  });
  test("emails flagged in data files, not code", () => {
    const csv = scanTextContent("users.csv", "name,email\nJane,jane.doe@example.com");
    expect(csv.some((x) => x.kind === "pii-email")).toBe(true);
    const code = scanTextContent("contact.ts", "export const support = 'help@example.com';");
    expect(code.some((x) => x.kind === "pii-email")).toBe(false);
  });
});

describe("tree roundtrip: scan -> seal -> verify -> restore", () => {
  let root: string;
  const STRIPE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"; // Stripe's documented example, split for push protection
  const envOrig = "# app env\nAPI_KEY=abc123def456ghi\nDB_PASSWORD='p@ssw0rd-very-secret'\nPLAIN=hello\n";
  const tsOrig = "export const config = {\n  stripe: '" + STRIPE + "',\n  note: 'nothing secret here',\n};\n";
  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), "enclave-test-"));
    mkdirSync(join(root, "src"), { recursive: true });
    writeFileSync(join(root, ".env"), envOrig);
    writeFileSync(join(root, "src", "config.ts"), tsOrig);
    writeFileSync(join(root, "src", "clean.ts"), "export const x = 1;\n");
  });
  afterAll(() => { rmSync(root, { recursive: true, force: true }); });

  test("scan finds the planted secrets", () => {
    const f = scanTree(root);
    const kinds = f.map((x) => x.kind).sort();
    expect(kinds).toContain("env");
    expect(kinds).toContain("stripe-key");
    expect(f.filter((x) => x.file === ".env").length).toBe(2);
  });

  test("CLI seal/verify/restore roundtrip is byte-exact", async () => {
    const env = { ...process.env, ENCLAVE_PASSPHRASE: "test-pass-123", HOME: root };
    const run = async (args: string[]) => {
      const p = Bun.spawn(["bun", "run", join(import.meta.dir, "..", "src", "cli.ts"), ...args],
        { env, stdout: "pipe", stderr: "pipe" });
      const code = await p.exited;
      return { code, out: await new Response(p.stdout).text(), err: await new Response(p.stderr).text() };
    };
    // HOME is redirected so the vault lands in the temp dir.
    const seal = await run(["seal", root, "--apply"]);
    expect(seal.code).toBe(0);
    const sealedEnv = readFileSync(join(root, ".env"), "utf8");
    expect(sealedEnv).toContain("API_KEY=enclave:API_KEY");
    expect(sealedEnv).not.toContain("abc123def456");
    expect(existsSync(join(root, "enclave.manifest.json"))).toBe(true);
    const manifest = JSON.parse(readFileSync(join(root, "enclave.manifest.json"), "utf8"));
    expect(JSON.stringify(manifest)).not.toContain("abc123def456");
    expect(JSON.stringify(manifest)).not.toContain("p@ssw0rd");

    const verify = await run(["verify", root]);
    expect(verify.code).toBe(0);

    const restore = await run(["restore", root]);
    expect(restore.code).toBe(0);
    expect(readFileSync(join(root, ".env"), "utf8")).toBe(envOrig);
    expect(readFileSync(join(root, "src", "config.ts"), "utf8")).toBe(tsOrig);
    expect(existsSync(join(root, "enclave.manifest.json"))).toBe(false);
  });
});

describe("blob roundtrip via CLI", () => {
  test("photo seals to a tombstone and restores byte-exact", async () => {
    const root = mkdtempSync(join(tmpdir(), "enclave-blob-"));
    // tiny EXIF jpeg: FFD8 + APP1(Exif + TIFF with Make) + FFD9
    const tiff = Buffer.alloc(64);
    tiff.write("II", 0, "latin1"); tiff.writeUInt16LE(42, 2); tiff.writeUInt32LE(8, 4);
    tiff.writeUInt16LE(1, 8);
    tiff.writeUInt16LE(0x010f, 10); tiff.writeUInt16LE(2, 12); tiff.writeUInt32LE(6, 14); tiff.writeUInt32LE(26, 18);
    tiff.writeUInt32LE(0, 22);
    tiff.write("Canon\0", 26, "latin1");
    const app1 = Buffer.concat([Buffer.from("Exif\0\0", "latin1"), tiff]);
    const head = Buffer.from([0xff, 0xd8, 0xff, 0xe1]);
    const len = Buffer.alloc(2); len.writeUInt16BE(app1.length + 2, 0);
    const photo = Buffer.concat([head, len, app1, Buffer.from([0xff, 0xd9])]);
    writeFileSync(join(root, "photo.jpg"), photo);
    writeFileSync(join(root, "app.db"), Buffer.concat([Buffer.from("SQLite format 3\0", "latin1"), Buffer.alloc(64, 7)]));

    const env = { ...process.env, ENCLAVE_PASSPHRASE: "blob-pass-9", HOME: root };
    const run = async (args: string[]) => {
      const p = Bun.spawn(["bun", "run", join(import.meta.dir, "..", "src", "cli.ts"), ...args],
        { env, stdout: "pipe", stderr: "pipe", cwd: root });
      const code = await p.exited;
      return { code, out: await new Response(p.stdout).text() };
    };
    const seal = await run(["seal", root, "--apply"]);
    expect(seal.code).toBe(0);
    const tomb = readFileSync(join(root, "photo.jpg"), "utf8");
    expect(tomb.startsWith("enclave-blob:")).toBe(true);
    expect(tomb).toContain("sha256:");
    expect((await run(["verify", root])).code).toBe(0);

    const list = await run(["list", root]);
    expect(list.out).toContain("blob:photo-exif");
    expect(list.out).toContain("blob:database");

    // re-seal after replacing the photo: the vault must track the NEW bytes
    const photo2 = Buffer.concat([photo, Buffer.from([0x00, 0x11, 0x22])]);
    writeFileSync(join(root, "photo.jpg"), photo2);
    expect((await run(["seal", root, "--apply"])).code).toBe(0);

    const restore = await run(["restore", root]);
    expect(restore.code).toBe(0);
    expect(readFileSync(join(root, "photo.jpg")).equals(photo2)).toBe(true);
    rmSync(root, { recursive: true, force: true });
  });
});
