#!/usr/bin/env bun
// enclave — secrets enclave manager for source trees.
//
//   enclave scan   [dir]                  list detected secrets (masked)
//   enclave seal   [dir] [--apply]        dry-run plan; --apply seals into the vault
//   enclave verify [dir]                  fail (exit 1) if plaintext secrets remain
//   enclave list                          vault contents (masked)
//   enclave show   <name> [--reveal]      one entry
//   enclave extract <name> [--out <f>]    write a sealed blob back out
//   enclave inject [dir] [--out <file>]   write env file from the vault (default .env.local)
//   enclave run    [dir] -- <cmd...>      run a command with vault secrets as env vars
//   enclave restore [dir]                 put sealed values back, byte-exact
//   enclave ui     [--port 3039]          macOS-style web UI (127.0.0.1)
//
// The vault lives OUTSIDE the tree at ~/.enclave/<project>.vault.enc
// (override with --vault <path>). Passphrase: ENCLAVE_PASSPHRASE env var,
// or a hidden prompt on a TTY. A manifest (names + locations, NO values)
// is kept at <dir>/enclave.manifest.json so restore/verify know the map.
import { writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { scanTree, mask, type Finding } from "./scan.ts";
import { loadVault, saveVault, vaultExists, emptyVault, type VaultData } from "./vault.ts";
import {
  TOKEN_PREFIX, projectOf, defaultVaultPath, manifestPath, loadManifest,
  sealTree, verifyTree, restoreTree, envEntries, injectEnvFile, extractBlobBytes,
} from "./core.ts";

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

function vaultPathFor(dir: string, flags: Map<string, string | boolean>): string {
  const v = flags.get("--vault");
  if (typeof v === "string") return resolve(v);
  return defaultVaultPath(dir);
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
  const result = sealTree(dir, vault);
  saveVault(vpath, vault, pass);
  console.log(`Sealed ${result.sealed} secret(s) into ${vpath}`);
  console.log(`Manifest: ${manifestPath(dir)} (${loadManifest(dir)?.entries.length ?? 0} entries, no values).`);
}

async function cmdVerify(dir: string): Promise<void> {
  const { ok, findings, drift } = verifyTree(dir);
  if (findings.length) {
    console.log("Plaintext secrets remain:");
    printFindings(findings);
  }
  for (const d of drift) console.log("drift: " + d);
  if (!ok) process.exit(1);
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
  let out: string, bytes: Buffer;
  try {
    const r = extractBlobBytes(vault, name);
    bytes = r.bytes;
    out = typeof flags.get("--out") === "string" ? resolve(flags.get("--out") as string) : resolve(r.entry.file);
  } catch (e) { fail(e instanceof Error ? e.message : String(e)); }
  writeFileSync(out!, bytes!, { mode: 0o600 });
  console.log(`Wrote ${bytes!.length} bytes to ${out!} (sha256 verified).`);
}

async function cmdInject(dir: string, flags: Map<string, string | boolean>): Promise<void> {
  const vault = await withVault(dir, flags);
  const out = typeof flags.get("--out") === "string" ? resolve(flags.get("--out") as string) : join(dir, ".env.local");
  const n = injectEnvFile(vault, out);
  console.log(`Wrote ${n} variable(s) to ${out} (mode 600).`);
}

async function cmdRun(dir: string, flags: Map<string, string | boolean>, cmd: string[]): Promise<void> {
  if (!cmd.length) fail("usage: enclave run [dir] -- <command...>");
  const vault = await withVault(dir, flags);
  const env: Record<string, string> = { ...process.env } as Record<string, string>;
  for (const e of envEntries(vault)) env[e.name] = e.value;
  const proc = Bun.spawn(cmd, { env, stdin: "inherit", stdout: "inherit", stderr: "inherit" });
  process.exit(await proc.exited);
}

async function cmdRestore(dir: string, flags: Map<string, string | boolean>): Promise<void> {
  if (!loadManifest(dir)) fail("no enclave.manifest.json — nothing to restore");
  const vault = await withVault(dir, flags);
  const r = restoreTree(dir, vault);
  for (const w of r.warnings) console.log("warning: " + w);
  console.log(`Restored ${r.restored} secret(s)${r.missing ? `, ${r.missing} placeholder(s) not found` : ""}. Manifest removed; vault kept at ${vaultPathFor(dir, flags)}.`);
}

async function cmdUi(flags: Map<string, string | boolean>): Promise<void> {
  const portFlag = flags.get("--port");
  const port = typeof portFlag === "string" ? parseInt(portFlag, 10) : 3039;
  const { startUiServer } = await import("./server.ts");
  const server = startUiServer(port);
  console.log(`Enclave UI: http://${server.hostname}:${server.port}/  (127.0.0.1 only — Ctrl-C to stop)`);
  await new Promise(() => {}); // serve until killed
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
  enclave ui      [--port 3039]         macOS-style web UI on 127.0.0.1
Passphrase: ENCLAVE_PASSPHRASE env var, or hidden TTY prompt.
Vault: ~/.enclave/<project>.vault.enc (outside the tree), AES-256-GCM + scrypt.`;

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  if (!cmd || cmd === "--help" || cmd === "-h") { console.log(USAGE); return; }
  const { flags, positional } = parseArgs(argv.slice(1));
  const dir = resolve(positional[0] && cmd !== "show" && cmd !== "extract" ? positional[0] : ".");
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
    case "ui": return cmdUi(flags);
    default: fail(`unknown command '${cmd}' — try --help`);
  }
}

main().catch((e) => fail(e instanceof Error ? e.message : String(e)));
