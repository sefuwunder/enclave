#!/usr/bin/env bun
// enclave — secrets enclave manager for source trees.
//
//   enclave scan   [dir]                  list detected secrets (masked)
//   enclave seal   [dir] [--apply]        dry-run plan; --apply seals into the vault
//   enclave verify [dir]                  fail (exit 1) if plaintext secrets remain
//   enclave list                          vault contents (masked)
//   enclave show   <name> [--reveal]      one entry
//   enclave inject [dir] [--out <file>]   write env file from the vault (default .env.local)
//   enclave run    [dir] -- <cmd...>      run a command with vault secrets as env vars
//   enclave restore [dir]                 put sealed values back, byte-exact
//
// The vault lives OUTSIDE the tree at ~/.enclave/<project>.vault.enc
// (override with --vault <path>). Passphrase: ENCLAVE_PASSPHRASE env var,
// or a hidden prompt on a TTY. A manifest (names + locations, NO values)
// is kept at <dir>/enclave.manifest.json so restore/verify know the map.
import { readFileSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, resolve, basename } from "node:path";
import { homedir } from "node:os";
import { scanTree, mask, type Finding } from "./scan.ts";
import { loadVault, saveVault, vaultExists, emptyVault, type VaultData } from "./vault.ts";

const TOKEN_PREFIX = "enclave:";

interface ManifestEntry { name: string; file: string; line: number; kind: string }
interface Manifest { v: 1; project: string; entries: ManifestEntry[] }

function fail(msg: string): never {
  console.error("enclave: " + msg);
  process.exit(2);
}

async function getPassphrase(confirmNew = false): Promise<string> {
  const env = process.env.ENCLAVE_PASSPHRASE;
  if (env) return env;
  if (!process.stdin.isTTY) fail("set ENCLAVE_PASSPHRASE (no TTY to prompt on)");
  const promptHidden = async (label: string): Promise<string> => {
    process.stderr.write(label);
    const stdin = process.stdin;
    stdin.setRawMode(true);
    stdin.resume();
    let buf = "";
    return new Promise((res) => {
      const onData = (d: Buffer) => {
        const s = d.toString("utf8");
        for (const ch of s) {
          if (ch === "\n" || ch === "\r" || ch === "\u0004") {
            stdin.setRawMode(false);
            stdin.pause();
            stdin.off("data", onData);
            process.stderr.write("\n");
            res(buf);
            return;
          } else if (ch === "\u0003") { process.exit(130); }
          else if (ch === "\u007f") { buf = buf.slice(0, -1); }
          else { buf += ch; }
        }
      };
      stdin.on("data", onData);
    });
  };
  const pass = await promptHidden("Vault passphrase: ");
  if (!pass) fail("empty passphrase");
  if (confirmNew) {
    const again = await promptHidden("Confirm passphrase: ");
    if (again !== pass) fail("passphrases do not match");
  }
  return pass;
}

const BOOLEAN_FLAGS = new Set(["--apply", "--reveal"]);
function parseArgs(argv: string[]) {
  const flags = new Map<string, string | boolean>();
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") { positional.push(...argv.slice(i + 1)); break; }
    if (a.startsWith("--")) {
      const next = argv[i + 1];
      if (!BOOLEAN_FLAGS.has(a) && next && !next.startsWith("--")) { flags.set(a, next); i++; }
      else flags.set(a, true);
    } else positional.push(a);
  }
  return { flags, positional };
}

function projectOf(dir: string): string {
  return basename(resolve(dir)).replace(/[^A-Za-z0-9_.-]+/g, "-");
}
function vaultPathFor(dir: string, flags: Map<string, string | boolean>): string {
  const v = flags.get("--vault");
  if (typeof v === "string") return resolve(v);
  return join(homedir(), ".enclave", projectOf(dir) + ".vault.enc");
}
function manifestPath(dir: string): string { return join(dir, "enclave.manifest.json"); }
function loadManifest(dir: string): Manifest | null {
  const p = manifestPath(dir);
  if (!existsSync(p)) return null;
  return JSON.parse(readFileSync(p, "utf8")) as Manifest;
}
function saveManifest(dir: string, m: Manifest): void {
  writeFileSync(manifestPath(dir), JSON.stringify(m, null, 2) + "\n");
}

function printFindings(findings: Finding[]): void {
  for (const f of findings) {
    if (f.blob) {
      console.log(`${f.file}  ${f.kind.padEnd(16)} ${f.keyName.padEnd(28)} [blob · ${f.offsetEnd} bytes · ${f.meta || ""}]`);
    } else {
      console.log(`${f.file}:${f.line}  ${f.kind.padEnd(16)} ${f.keyName.padEnd(28)} ${mask(f.value)}`);
    }
  }
}

async function cmdScan(dir: string): Promise<void> {
  const findings = scanTree(dir);
  if (!findings.length) { console.log("No secrets found."); return; }
  printFindings(findings);
  console.log(`\n${findings.length} secret(s) in ${new Set(findings.map((f) => f.file)).size} file(s).`);
}

async function cmdSeal(dir: string, flags: Map<string, string | boolean>): Promise<void> {
  const apply = flags.get("--apply") === true;
  const findings = scanTree(dir);
  if (!findings.length) { console.log("Nothing to seal — tree is clean."); return; }
  if (!apply) {
    console.log("Dry run — would seal:");
    printFindings(findings);
    console.log(`\n${findings.length} secret(s). Re-run with --apply to seal them into the vault.`);
    return;
  }
  const vpath = vaultPathFor(dir, flags);
  const isNew = !vaultExists(vpath);
  const pass = await getPassphrase(isNew);
  const vault: VaultData = isNew ? emptyVault(projectOf(dir)) : loadVault(vpath, pass);
  const byName = new Map(vault.entries.map((e) => [e.name, e]));
  const manifest = loadManifest(dir) || { v: 1 as const, project: projectOf(dir), entries: [] };
  const now = new Date().toISOString();

  // Resolve name collisions against the existing vault (and this plan).
  const planned: { f: Finding; name: string }[] = [];
  const taken = new Map(byName);
  for (const f of findings) {
    let name = f.keyName;
    const existing = taken.get(name);
    if (existing && existing.value !== f.value) {
      let n = 2;
      while (taken.has(`${name}_${n}`) && taken.get(`${name}_${n}`)!.value !== f.value) n++;
      name = `${name}_${n}`;
    }
    taken.set(name, { name, value: f.value, file: f.file, kind: f.kind, sealedAt: now });
    planned.push({ f, name });
  }

  // Apply text replacements file by file, last span first; skip overlaps.
  const byFile = new Map<string, { f: Finding; name: string }[]>();
  for (const p of planned) {
    if (p.f.blob) continue;
    const arr = byFile.get(p.f.file) || [];
    arr.push(p);
    byFile.set(p.f.file, arr);
  }
  let sealedCount = 0;
  for (const [rel, items] of byFile) {
    const full = join(dir, rel);
    let content = readFileSync(full, "utf8");
    const sorted = items.slice().sort((a, b) => b.f.offsetStart - a.f.offsetStart);
    const appliedSpans: [number, number][] = [];
    for (const { f, name } of sorted) {
      if (appliedSpans.some(([s, e]) => f.offsetStart < e && s < f.offsetEnd)) continue;
      if (content.slice(f.offsetStart, f.offsetEnd) !== f.value) continue;
      content = content.slice(0, f.offsetStart) + TOKEN_PREFIX + name + content.slice(f.offsetEnd);
      appliedSpans.push([f.offsetStart, f.offsetEnd]);
      if (!byName.has(name)) {
        const entry = { name, value: f.value, file: f.file, kind: f.kind, sealedAt: now };
        vault.entries.push(entry);
        byName.set(name, entry);
      }
      if (!manifest.entries.some((m) => m.name === name)) {
        manifest.entries.push({ name, file: f.file, line: f.line, kind: f.kind });
      }
      sealedCount++;
    }
    writeFileSync(full, content);
  }
  // Seal binary blobs: bytes go into the vault, a tombstone stays in-tree.
  for (const { f, name } of planned) {
    if (!f.blob) continue;
    const full = join(dir, f.file);
    const bytes = readFileSync(full);
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    const existingBlob = byName.get(name);
    if (existingBlob && existingBlob.sha256 !== sha256) {
      // same name, new bytes: the file changed since it was last sealed —
      // update the vault entry, never keep stale bytes under a fresh tombstone
      existingBlob.blob = bytes.toString("base64");
      existingBlob.size = bytes.length;
      existingBlob.sha256 = sha256;
      existingBlob.meta = f.meta;
      existingBlob.sealedAt = now;
    } else if (!existingBlob) {
      const entry = {
        name, value: "", file: f.file, kind: f.kind, sealedAt: now,
        blob: bytes.toString("base64"), size: bytes.length, sha256, meta: f.meta,
      };
      vault.entries.push(entry);
      byName.set(name, entry);
    }
    if (!manifest.entries.some((m) => m.name === name)) {
      manifest.entries.push({ name, file: f.file, line: f.line, kind: f.kind });
    }
    writeFileSync(full,
      `enclave-blob:${name}\nsha256:${sha256}\nsize:${bytes.length}\n` +
      `Sealed in the enclave vault (${f.meta || f.kind}). Restore with: enclave restore\n`);
    sealedCount++;
  }
  saveVault(vpath, vault, pass);
  saveManifest(dir, manifest);
  console.log(`Sealed ${sealedCount} secret(s) into ${vpath}`);
  console.log(`Manifest: ${manifestPath(dir)} (${manifest.entries.length} entries, no values).`);
}

async function cmdVerify(dir: string): Promise<void> {
  const findings = scanTree(dir);
  if (findings.length) {
    console.log("Plaintext secrets remain:");
    printFindings(findings);
    process.exit(1);
  }
  const manifest = loadManifest(dir);
  if (manifest) {
    let drift = 0;
    for (const m of manifest.entries) {
      const full = join(dir, m.file);
      const text = existsSync(full) ? readFileSync(full, "utf8") : "";
      if (!text.includes(TOKEN_PREFIX + m.name) && !text.includes("enclave-blob:" + m.name)) {
        console.log(`drift: ${m.name} placeholder missing from ${m.file}`);
        drift++;
      }
    }
    if (drift) process.exit(1);
  }
  console.log("Verified: no plaintext secrets in tree.");
}

async function withVault(dir: string, flags: Map<string, string | boolean>): Promise<VaultData> {
  const vpath = vaultPathFor(dir, flags);
  if (!vaultExists(vpath)) fail(`no vault at ${vpath} — run 'enclave seal --apply' first`);
  return loadVault(vpath, await getPassphrase());
}

async function cmdList(dir: string, flags: Map<string, string | boolean>): Promise<void> {
  const vault = await withVault(dir, flags);
  if (!vault.entries.length) { console.log("Vault is empty."); return; }
  for (const e of vault.entries) {
    const shown = e.blob !== undefined ? `[blob · ${e.size} bytes · ${e.meta || ""}]` : mask(e.value);
    console.log(`${e.name.padEnd(28)} ${e.kind.padEnd(16)} ${e.file.padEnd(28)} ${shown}`);
  }
  console.log(`\n${vault.entries.length} entr(ies) in the ${vault.project} enclave.`);
}

async function cmdShow(dir: string, flags: Map<string, string | boolean>, name: string): Promise<void> {
  const vault = await withVault(dir, flags);
  const e = vault.entries.find((x) => x.name === name);
  if (!e) fail(`no entry named ${name}`);
  if (e.blob !== undefined) {
    console.log(`${e.name}: binary blob · ${e.size} bytes · sha256 ${e.sha256?.slice(0, 12)}… · ${e.meta || ""} (from ${e.file}, sealed ${e.sealedAt})`);
    console.log("Use 'enclave extract <name> --out <file>' to write it out, or 'enclave restore'.");
    return;
  }
  if (flags.get("--reveal") === true) console.log(e.value);
  else console.log(`${e.name}: ${mask(e.value)}  (${e.kind}, from ${e.file}, sealed ${e.sealedAt})`);
}

async function cmdExtract(dir: string, flags: Map<string, string | boolean>, name: string): Promise<void> {
  const vault = await withVault(dir, flags);
  const e = vault.entries.find((x) => x.name === name);
  if (!e) fail(`no entry named ${name}`);
  if (e.blob === undefined) fail(`${name} is a text secret — use 'enclave show ${name} --reveal'`);
  const out = typeof flags.get("--out") === "string" ? resolve(flags.get("--out") as string) : resolve(e.file);
  const bytes = Buffer.from(e.blob, "base64");
  const sha = createHash("sha256").update(bytes).digest("hex");
  if (e.sha256 && sha !== e.sha256) fail("sha256 mismatch — vault entry is corrupt");
  writeFileSync(out, bytes, { mode: 0o600 });
  console.log(`Wrote ${bytes.length} bytes to ${out} (sha256 verified).`);
}

function envQuote(v: string): string {
  return "'" + v.replace(/'/g, "'\\''") + "'";
}

async function cmdInject(dir: string, flags: Map<string, string | boolean>): Promise<void> {
  const vault = await withVault(dir, flags);
  const out = typeof flags.get("--out") === "string" ? resolve(flags.get("--out") as string) : join(dir, ".env.local");
  const lines = vault.entries
    .filter((e) => e.blob === undefined && /^[A-Za-z_][A-Za-z0-9_]*$/.test(e.name))
    .map((e) => `${e.name}=${envQuote(e.value)}`);
  writeFileSync(out, lines.join("\n") + "\n", { mode: 0o600 });
  console.log(`Wrote ${lines.length} variable(s) to ${out} (mode 600).`);
}

async function cmdRun(dir: string, flags: Map<string, string | boolean>, cmd: string[]): Promise<void> {
  if (!cmd.length) fail("usage: enclave run [dir] -- <command...>");
  const vault = await withVault(dir, flags);
  const env: Record<string, string> = { ...process.env } as Record<string, string>;
  for (const e of vault.entries) {
    if (e.blob === undefined && /^[A-Za-z_][A-Za-z0-9_]*$/.test(e.name)) env[e.name] = e.value;
  }
  const proc = Bun.spawn(cmd, { env, stdin: "inherit", stdout: "inherit", stderr: "inherit" });
  process.exit(await proc.exited);
}

async function cmdRestore(dir: string, flags: Map<string, string | boolean>): Promise<void> {
  const manifest = loadManifest(dir);
  if (!manifest) fail("no enclave.manifest.json — nothing to restore");
  const vault = await withVault(dir, flags);
  const byName = new Map(vault.entries.map((e) => [e.name, e]));
  let restored = 0, missing = 0;
  const byFile = new Map<string, ManifestEntry[]>();
  for (const m of manifest.entries) {
    const arr = byFile.get(m.file) || [];
    arr.push(m);
    byFile.set(m.file, arr);
  }
  for (const [rel, items] of byFile) {
    const full = join(dir, rel);
    if (!existsSync(full)) { missing += items.length; continue; }
    // blob entries: the tombstone is replaced by the original bytes
    const blobItems = items.filter((m) => m.kind.startsWith("blob:"));
    const textItems = items.filter((m) => !m.kind.startsWith("blob:"));
    for (const m of blobItems) {
      const e = byName.get(m.name);
      if (e && e.blob !== undefined) {
        const bytes = Buffer.from(e.blob, "base64");
        const sha = createHash("sha256").update(bytes).digest("hex");
        if (e.sha256 && sha !== e.sha256) { missing++; continue; }
        // the tombstone records the sha that was sealed over this path —
        // if it disagrees with the vault, stop rather than overwrite wrongly
        const tomb = readFileSync(full, "utf8");
        const tombSha = tomb.match(/^sha256:([0-9a-f]{64})$/m)?.[1];
        if (tombSha && e.sha256 && tombSha !== e.sha256) {
          console.log(`warning: ${m.file} tombstone sha does not match vault entry ${m.name} — skipped`);
          missing++;
          continue;
        }
        writeFileSync(full, bytes);
        restored++;
      } else missing++;
    }
    if (textItems.length) {
      let content = readFileSync(full, "utf8");
      for (const m of textItems) {
        const e = byName.get(m.name);
        const token = TOKEN_PREFIX + m.name;
        if (e && content.includes(token)) {
          content = content.split(token).join(e.value);
          restored++;
        } else missing++;
      }
      writeFileSync(full, content);
    }
  }
  rmSync(manifestPath(dir));
  console.log(`Restored ${restored} secret(s)${missing ? `, ${missing} placeholder(s) not found` : ""}. Manifest removed; vault kept at ${vaultPathFor(dir, flags)}.`);
}

const USAGE = `enclave — secrets enclave manager for source trees
  enclave scan    [dir]                 list detected secrets (masked)
  enclave seal    [dir] [--apply]       dry-run, or seal into the vault with --apply
  enclave verify  [dir]                 exit 1 if plaintext secrets remain
  enclave list    [--vault <path>]      vault contents (masked)
  enclave show    <name> [--reveal]     one entry
  enclave extract <name> [--out <file>] write a sealed blob back out (sha256-checked)
  enclave inject  [dir] [--out <file>]  write env file (default <dir>/.env.local)
  enclave run     [dir] -- <cmd...>     run with vault secrets as env vars
  enclave restore [dir]                 put sealed values back, byte-exact
Passphrase: ENCLAVE_PASSPHRASE env var, or hidden TTY prompt.
Vault: ~/.enclave/<project>.vault.enc (outside the tree), AES-256-GCM + scrypt.`;

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  if (!cmd || cmd === "--help" || cmd === "-h") { console.log(USAGE); return; }
  const { flags, positional } = parseArgs(argv.slice(1));
  // dir = first positional that is not consumed by the command itself
  const dir = resolve(positional[0] && cmd !== "show" ? positional[0] : ".");
  switch (cmd) {
    case "scan": return cmdScan(dir);
    case "seal": return cmdSeal(dir, flags);
    case "verify": return cmdVerify(dir);
    case "list": return cmdList(dir, flags);
    case "show": {
      const name = positional[0];
      if (!name) fail("usage: enclave show <name> [--reveal]");
      return cmdShow(".", flags, name);
    }
    case "extract": {
      const name = positional[0];
      if (!name) fail("usage: enclave extract <name> [--out <file>]");
      return cmdExtract(".", flags, name);
    }
    case "inject": return cmdInject(dir, flags);
    case "run": {
      const sep = argv.indexOf("--");
      const runCmd = sep === -1 ? [] : argv.slice(sep + 1);
      const runDir = positional[0] && sep > 1 && argv[1] !== "--" ? resolve(positional[0]) : resolve(".");
      return cmdRun(runDir, flags, runCmd);
    }
    case "restore": return cmdRestore(dir, flags);
    default: fail(`unknown command '${cmd}' — try --help`);
  }
}

main().catch((e) => fail(e instanceof Error ? e.message : String(e)));
