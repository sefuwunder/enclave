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
//   enclave stow   [dir] [pkg...]         restore secrets, then GNU-stow packages
//   enclave unstow [dir] [pkg...]         GNU-stow -D packages, then seal back
//   enclave home   <sub>                  home manager (rsync backups + history)
//   enclave ui     [--port 3039]          macOS-style web UI (127.0.0.1)
//
// The vault lives OUTSIDE the tree at ~/.enclave/<project>.vault.enc
// (override with --vault <path>). Passphrase: ENCLAVE_PASSPHRASE env var,
// or a hidden prompt on a TTY. A manifest (names + locations, NO values)
// is kept at <dir>/enclave.manifest.json so restore/verify know the map.
import { writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { scanTree, mask, type Finding } from "./scan.ts";
import { loadVault, saveVault, vaultExists, emptyVault, inspectVaultFile, type VaultData, type VaultAuth, type VaultFileInfo } from "./vault.ts";
import { pgpAvailable, listAllKeys, findKey, generateKey, loadConfig, saveConfig, resolveRecipient, dedicatedGpgHome } from "./pgp.ts";
import {
  TOKEN_PREFIX, projectOf, defaultVaultPath, manifestPath, loadManifest,
  sealTree, verifyTree, restoreTree, envEntries, injectEnvFile, extractBlobBytes,
  stowPackages, unstowPackages, markStowManaged,
} from "./core.ts";
import { stowAvailable } from "./stow.ts";
import {
  loadHomeConfig, saveHomeConfig, emptyHomeConfig, addFiles, removeFile,
  addDest, removeDest, backupTo, backupAll, restoreFrom, homeStatus,
  fmtBytes, opendriveCreds, loadCredentials, saveCredentials,
  homeConfigPath, normalizeSelection, type DestConfig, type HomeConfig,
} from "./home.ts";

function fail(msg: string): never {
  console.error("enclave: " + msg);
  process.exit(2);
}

async function promptHidden(label: string): Promise<string> {
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
}

async function getPassphrase(confirmNew = false): Promise<string> {
  const env = process.env.ENCLAVE_PASSPHRASE;
  if (env) return env;
  if (!process.stdin.isTTY) fail("set ENCLAVE_PASSPHRASE (no TTY to prompt on)");
  const pass = await promptHidden("Vault passphrase: ");
  if (!pass) fail("empty passphrase");
  if (confirmNew) {
    const again = await promptHidden("Confirm passphrase: ");
    if (again !== pass) fail("passphrases do not match");
  }
  return pass;
}

// Open any vault (either scheme) and return the auth needed to re-save it.
async function openVault(vpath: string): Promise<{ vault: VaultData; auth: VaultAuth; info: VaultFileInfo }> {
  const info = inspectVaultFile(vpath);
  if (info.scheme === "pgp") {
    const mk = (passphrase?: string): VaultAuth => ({ passphrase, recipient: info.recipient, keyring: info.keyring });
    const envPass = process.env.ENCLAVE_PASSPHRASE;
    const tries: (string | undefined)[] = envPass !== undefined && envPass !== "" ? [envPass, undefined] : [undefined];
    for (const p of tries) {
      try { return { vault: loadVault(vpath, mk(p)), auth: mk(p), info }; } catch { /* try next */ }
    }
    if (process.stdin.isTTY) {
      const p = await promptHidden("PGP key passphrase (blank for unprotected/agent): ");
      const auth = mk(p === "" ? undefined : p);
      try { return { vault: loadVault(vpath, auth), auth, info }; }
      catch (e) { fail("could not decrypt the PGP vault: " + (e instanceof Error ? e.message : String(e))); }
    }
    fail("could not decrypt the PGP vault — set ENCLAVE_PASSPHRASE to the key's passphrase");
  }
  const auth: VaultAuth = { passphrase: await getPassphrase(false) };
  return { vault: loadVault(vpath, auth), auth, info };
}

const BOOLEAN_FLAGS = new Set(["--apply", "--reveal", "--pgp", "--no-protection", "--stow", "--restow", "--adopt", "--delete", "--require-mount", "--no-require-mount"]);
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
  const noteStow = () => {
    if (flags.get("--stow") !== true) return;
    const target = typeof flags.get("--target") === "string" ? flags.get("--target") as string : "~";
    if (markStowManaged(dir, target)) {
      console.log(`Recorded as a GNU Stow directory (target ${target}) — link it with: enclave stow`);
    }
  };
  const findings = scanTree(dir);
  if (!findings.length) { console.log("Nothing to seal — tree is clean."); noteStow(); return; }
  if (!apply) {
    console.log("Dry run — would seal:");
    printFindings(findings);
    console.log(`\n${findings.length} secret(s). Re-run with --apply to seal them into the vault.`);
    return;
  }
  const vpath = vaultPathFor(dir, flags);
  const isNew = !vaultExists(vpath);
  const wantPgp = flags.get("--pgp") === true;
  let vault: VaultData;
  let auth: VaultAuth;
  if (!isNew) {
    const info = inspectVaultFile(vpath);
    if (wantPgp && info.scheme !== "pgp") fail("this vault is passphrase-encrypted — run 'enclave pgp convert' to switch schemes");
    const opened = await openVault(vpath);
    vault = opened.vault;
    auth = opened.auth;
  } else if (wantPgp) {
    if (!pgpAvailable()) fail("gpg is not available on this system");
    const key = resolveRecipient(typeof flags.get("--recipient") === "string" ? flags.get("--recipient") as string : undefined);
    auth = { recipient: key.fingerprint, keyring: key.keyring };
    vault = emptyVault(projectOf(dir));
  } else {
    auth = { passphrase: await getPassphrase(true) };
    vault = emptyVault(projectOf(dir));
  }
  const result = sealTree(dir, vault);
  saveVault(vpath, vault, auth);
  console.log(`Sealed ${result.sealed} secret(s) into ${vpath}${auth.recipient ? ` (PGP → ${auth.recipient})` : ""}`);
  console.log(`Manifest: ${manifestPath(dir)} (${loadManifest(dir)?.entries.length ?? 0} entries, no values).`);
  noteStow();
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
  return (await openVault(vpath)).vault;
}

async function cmdList(dir: string, flags: Map<string, string | boolean>): Promise<void> {
  const vpath = vaultPathFor(dir, flags);
  const vault = await withVault(dir, flags);
  if (vaultExists(vpath)) {
    const info = inspectVaultFile(vpath);
    if (info.scheme === "pgp") console.log(`Scheme: PGP → ${info.recipient} (${info.keyring} keyring)\n`);
  }
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

/* ------------------------- stow subcommands ------------------------- */

function requireStow(): void {
  if (!stowAvailable()) {
    fail("GNU stow is not installed (or not on PATH) — install it first, e.g. 'sudo apt install stow' / 'brew install stow'");
  }
}

async function cmdStow(positional: string[], flags: Map<string, string | boolean>): Promise<void> {
  requireStow();
  const dir = resolve(positional[0] || ".");
  const packages = positional.slice(1);
  const manifest = loadManifest(dir);
  const vault = manifest && manifest.entries.length ? await withVault(dir, flags) : null;
  const r = stowPackages(dir, vault, {
    target: typeof flags.get("--target") === "string" ? flags.get("--target") as string : undefined,
    packages: packages.length ? packages : undefined,
    restow: flags.get("--restow") === true,
    adopt: flags.get("--adopt") === true,
  });
  if (r.restored) console.log(`Restored ${r.restored} secret(s) into the tree.`);
  if (r.stowOutput) console.log(r.stowOutput);
  console.log(`Stowed ${r.packages.length} package(s) into ${r.target}: ${r.packages.join(", ")}`);
}

async function cmdUnstow(positional: string[], flags: Map<string, string | boolean>): Promise<void> {
  requireStow();
  const dir = resolve(positional[0] || ".");
  const packages = positional.slice(1);
  const vpath = vaultPathFor(dir, flags);
  const opts = {
    target: typeof flags.get("--target") === "string" ? flags.get("--target") as string : undefined,
    packages: packages.length ? packages : undefined,
  };
  // Nothing plaintext and no vault yet: a plain unlink needs no vault work.
  if (!vaultExists(vpath) && scanTree(dir).length === 0) {
    const r = unstowPackages(dir, null, opts);
    if (r.stowOutput) console.log(r.stowOutput);
    console.log(`Unstowed ${r.packages.length} package(s) from ${r.target}: ${r.packages.join(", ")} (tree already clean, no vault created)`);
    return;
  }
  let vault: VaultData;
  let auth: VaultAuth;
  if (vaultExists(vpath)) {
    const opened = await openVault(vpath);
    vault = opened.vault;
    auth = opened.auth;
  } else if (flags.get("--pgp") === true) {
    if (!pgpAvailable()) fail("gpg is not available on this system");
    const key = resolveRecipient(typeof flags.get("--recipient") === "string" ? flags.get("--recipient") as string : undefined);
    auth = { recipient: key.fingerprint, keyring: key.keyring };
    vault = emptyVault(projectOf(dir));
  } else {
    auth = { passphrase: await getPassphrase(true) };
    vault = emptyVault(projectOf(dir));
  }
  const r = unstowPackages(dir, vault, opts);
  saveVault(vpath, vault, auth);
  if (r.stowOutput) console.log(r.stowOutput);
  console.log(`Unstowed ${r.packages.length} package(s) from ${r.target}: ${r.packages.join(", ")}`);
  console.log(`Sealed ${r.sealed} secret(s) back into ${vpath} — the tree is safe to commit.`);
}

/* ------------------------- home subcommands ------------------------- */

async function promptLine(label: string): Promise<string> {
  process.stderr.write(label);
  return new Promise((res) => {
    let buf = "";
    const onData = (d: Buffer) => {
      buf += d.toString("utf8");
      if (buf.includes("\n")) {
        process.stdin.off("data", onData);
        process.stdin.pause();
        res(buf.split("\n")[0].trim());
      }
    };
    process.stdin.on("data", onData);
    process.stdin.resume();
  });
}

function requireHomeConfig(mutate = false): HomeConfig {
  const cfg = loadHomeConfig();
  if (cfg) return cfg;
  if (!mutate) fail("no home config yet — run 'enclave home init'");
  const fresh = emptyHomeConfig();
  saveHomeConfig(fresh);
  console.log(`Created ${homeConfigPath()}`);
  return fresh;
}

function fmtWhen(iso: string): string {
  const d = new Date(iso);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function cmdHomeStatus(): void {
  const cfg = loadHomeConfig();
  const st = homeStatus(cfg);
  console.log(`Home: ${st.home}${cfg ? "" : "  (no home config — 'enclave home init')"}`);
  console.log(`rsync: ${st.rsyncAvailable ? "available" : "NOT FOUND"} · stow: ${st.stowAvailable ? "available" : "not installed"} · OpenDrive creds: ${st.opendriveConfigured ? "set" : "not set"}`);
  if (st.stow) {
    const n = st.stow.packages.length, s = st.stow.packages.filter((p) => p.stowed).length;
    console.log(`Stow: ${st.stow.dir} → ${st.stow.target} · ${s}/${n} package(s) stowed${n ? ": " + st.stow.packages.map((p) => `${p.name}${p.stowed ? " ✓" : ""}`).join(", ") : ""}`);
  }
  if (cfg) {
    console.log(`\nSelection (${st.files.length}):`);
    for (const f of st.files) {
      console.log(`  ${f.path.padEnd(36)} ${f.exists ? (f.dir ? "(dir)" : fmtBytes(f.size ?? 0)) : "(missing)"}`);
    }
    console.log(`\nDestinations (${st.destinations.length}):`);
    for (const d of st.destinations) {
      const b = d.lastBackup;
      const pill = !b ? "○ never backed up"
        : !b.ok ? `✗ last backup FAILED ${fmtWhen(b.at)} — ${b.note || ""}`
        : `● last backup ${fmtWhen(b.at)} · ${b.files} file(s) · ${fmtBytes(b.bytes)}`;
      const mount = d.mounted === null ? "" : d.mounted ? "" : " · not mounted";
      console.log(`  ${d.name.padEnd(14)} ${d.type.padEnd(9)} ${d.where}`);
      console.log(`  ${"".padEnd(14)} ${pill}${mount}`);
      if (d.lastRestore) console.log(`  ${"".padEnd(14)} last restore ${fmtWhen(d.lastRestore.at)} · ${d.lastRestore.files} file(s)${d.lastRestore.ok ? "" : " · FAILED"}`);
    }
  }
}

async function cmdHomeCreds(kind: string): Promise<void> {
  if (kind !== "opendrive") fail("usage: enclave home creds opendrive");
  if (!process.stdin.isTTY) fail("no TTY to prompt on — or set OPENDRIVE_USERNAME / OPENDRIVE_PASSWORD");
  const username = await promptLine("OpenDrive username: ");
  if (!username) fail("empty username");
  const password = await promptHidden("OpenDrive password: ");
  if (!password) fail("empty password");
  const creds = loadCredentials();
  creds.opendrive = { username, password };
  saveCredentials(creds);
  console.log("OpenDrive credentials saved to ~/.enclave/credentials.json (mode 600). They are never printed or put in the home config.");
}

async function cmdHome(positional: string[], flags: Map<string, string | boolean>): Promise<void> {
  const sub = positional[0] || "status";
  switch (sub) {
    case "status": return cmdHomeStatus();
    case "init": {
      const cfg = loadHomeConfig() || emptyHomeConfig();
      const sd = flags.get("--stow-dir");
      if (typeof sd === "string") cfg.stowDir = sd;
      saveHomeConfig(cfg);
      console.log(`Home config: ${homeConfigPath()}`);
      console.log(`Stow dir: ${cfg.stowDir || "(not set — pass --stow-dir ~/dotfiles)"} · ${cfg.files.length} selected file(s) · ${cfg.destinations.length} destination(s)`);
      return;
    }
    case "add": {
      const paths = positional.slice(1);
      if (!paths.length) fail("usage: enclave home add <home-relative path...>");
      const cfg = requireHomeConfig(true);
      const { added, rejected } = addFiles(cfg, paths);
      saveHomeConfig(cfg);
      for (const a of added) console.log(`added: ${a}`);
      for (const r of rejected) console.log(`rejected (outside home or invalid): ${r}`);
      if (!added.length && !rejected.length) console.log("already selected — nothing changed");
      return;
    }
    case "remove": {
      const p = positional[1];
      if (!p) fail("usage: enclave home remove <path>");
      const cfg = requireHomeConfig();
      if (!removeFile(cfg, p)) fail(`not in the selection: ${p}`);
      saveHomeConfig(cfg);
      console.log(`removed: ${normalizeSelection(p)}`);
      return;
    }
    case "dest": {
      const action = positional[1];
      if (action === "add") {
        const name = positional[2];
        const type = flags.get("--type");
        if (!name || typeof type !== "string") fail("usage: enclave home dest add <name> --type path|webdav|opendrive [--path <dir>] [--url <url>] [--folder <f>]");
        if (type !== "path" && type !== "webdav" && type !== "opendrive") fail("--type must be path, webdav or opendrive");
        const dest: DestConfig = { name, type };
        if (typeof flags.get("--path") === "string") dest.path = flags.get("--path") as string;
        if (typeof flags.get("--url") === "string") dest.url = flags.get("--url") as string;
        if (typeof flags.get("--folder") === "string") dest.folder = flags.get("--folder") as string;
        if (flags.get("--require-mount") === true) dest.requireMount = true;
        if (flags.get("--no-require-mount") === true) dest.requireMount = false;
        const cfg = requireHomeConfig(true);
        addDest(cfg, dest);
        saveHomeConfig(cfg);
        console.log(`Destination '${name}' (${type}) added.`);
        if (type === "opendrive" && !opendriveCreds()) {
          console.log("No OpenDrive credentials yet — run 'enclave home creds opendrive' (or set OPENDRIVE_USERNAME / OPENDRIVE_PASSWORD).");
        }
        return;
      }
      if (action === "remove") {
        const name = positional[2];
        if (!name) fail("usage: enclave home dest remove <name>");
        const cfg = requireHomeConfig();
        if (!removeDest(cfg, name)) fail(`no destination named '${name}'`);
        saveHomeConfig(cfg);
        console.log(`Destination '${name}' removed (its history went with it).`);
        return;
      }
      return fail("usage: enclave home dest add|remove");
    }
    case "backup": {
      const cfg = requireHomeConfig();
      const name = positional[1];
      const opts = { deleteExtra: flags.get("--delete") === true };
      if (name) {
        const rec = await backupTo(cfg, name, opts);
        console.log(`Backed up to ${name}: ${rec.files} file(s), ${fmtBytes(rec.bytes)}${rec.note ? " · " + rec.note : ""}`);
        return;
      }
      if (!cfg.destinations.length) fail("no destinations — add one with 'enclave home dest add'");
      const results = await backupAll(cfg, opts);
      let failed = 0;
      for (const r of results) {
        if (r.rec) console.log(`  ${r.name}: ${r.rec.files} file(s), ${fmtBytes(r.rec.bytes)}${r.rec.note ? " · " + r.rec.note : ""}`);
        else { console.log(`  ${r.name}: FAILED — ${r.error}`); failed++; }
      }
      if (failed) process.exit(1);
      return;
    }
    case "restore": {
      const name = positional[1];
      if (!name) fail("usage: enclave home restore <destination>");
      const cfg = requireHomeConfig();
      const rec = await restoreFrom(cfg, name);
      console.log(`Restored from ${name}: ${rec.files} file(s), ${fmtBytes(rec.bytes)}${rec.note ? " · " + rec.note : ""}`);
      return;
    }
    case "creds": return cmdHomeCreds(positional[1] || "");
    default: return fail(`unknown home command '${sub}' — try: status | init | add | remove | dest | backup | restore | creds`);
  }
}

/* ------------------------- pgp subcommands ------------------------- */

async function cmdPgpInit(flags: Map<string, string | boolean>): Promise<void> {
  if (!pgpAvailable()) fail("gpg is not available on this system");
  const name = typeof flags.get("--name") === "string" ? flags.get("--name") as string : "Enclave Vault";
  const email = typeof flags.get("--email") === "string" ? flags.get("--email") as string : "enclave@localhost";
  let passphrase: string | undefined;
  if (flags.get("--no-protection") !== true) {
    passphrase = await getPassphrase(true);
  }
  const key = generateKey({ name, email, passphrase });
  saveConfig({ pgpRecipient: key.fingerprint, pgpKeyring: "dedicated" });
  console.log(`Created dedicated enclave key in ${dedicatedGpgHome()}`);
  console.log(`  ${key.fingerprint}`);
  console.log(`  ${key.uid}${passphrase ? " (passphrase-protected)" : " (no passphrase — the keyring is the secret)"}`);
  console.log("Set as the default recipient. New PGP vaults: enclave seal --pgp --apply");
}

async function cmdPgpList(): Promise<void> {
  if (!pgpAvailable()) fail("gpg is not available on this system");
  const cfg = loadConfig();
  const keys = listAllKeys();
  if (!keys.length) {
    console.log("No PGP keys found in the dedicated or system keyrings.");
    console.log("Create one: enclave pgp init — or point at yours: enclave pgp use <fingerprint>");
    return;
  }
  for (const k of keys) {
    const marks = [
      k.keyring,
      k.hasSecret ? "secret ✓" : "public only",
      cfg.pgpRecipient === k.fingerprint ? "← default recipient" : "",
    ].filter(Boolean).join(" · ");
    console.log(`${k.fingerprint}\n  ${k.uid}  [${marks}]`);
  }
}

async function cmdPgpUse(query: string): Promise<void> {
  const key = findKey(query);
  if (!key) fail(`no unique PGP key matches '${query}' — see 'enclave pgp list'`);
  saveConfig({ pgpRecipient: key.fingerprint, pgpKeyring: key.keyring });
  console.log(`Default PGP recipient: ${key.fingerprint} (${key.uid}, ${key.keyring} keyring)`);
  if (!key.hasSecret) console.log("Note: no secret key in that keyring — you can seal to it here, but opening the vault needs the private key.");
}

async function cmdPgpConvert(dir: string, flags: Map<string, string | boolean>): Promise<void> {
  const vpath = vaultPathFor(dir, flags);
  if (!vaultExists(vpath)) fail(`no vault at ${vpath}`);
  const info = inspectVaultFile(vpath);
  const to = typeof flags.get("--to") === "string" ? flags.get("--to") as string : (info.scheme === "pgp" ? "passphrase" : "pgp");
  if (to !== "pgp" && to !== "passphrase") fail("--to must be 'pgp' or 'passphrase'");
  if (to === info.scheme) fail(`vault is already ${info.scheme}-encrypted`);
  const { vault } = await openVault(vpath);
  if (to === "pgp") {
    if (!pgpAvailable()) fail("gpg is not available on this system");
    const key = resolveRecipient(typeof flags.get("--recipient") === "string" ? flags.get("--recipient") as string : undefined);
    saveVault(vpath, vault, { recipient: key.fingerprint, keyring: key.keyring });
    console.log(`Converted ${vpath} to PGP (recipient ${key.fingerprint}, ${key.keyring} keyring). ${vault.entries.length} entr(ies) re-encrypted.`);
  } else {
    const pass = await getPassphrase(true);
    saveVault(vpath, vault, { passphrase: pass });
    console.log(`Converted ${vpath} to passphrase encryption. ${vault.entries.length} entr(ies) re-encrypted.`);
  }
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
  enclave stow    [dir] [pkg...] [--target <dir>] [--restow] [--adopt]
                                        restore secrets, then GNU-stow the packages
  enclave unstow  [dir] [pkg...] [--target <dir>]
                                        GNU-stow -D the packages, then seal secrets back
  enclave seal --stow [--target <dir>]  record the tree as a stow directory (target in manifest)
  enclave home    status|init|add|remove|dest|backup|restore|creds
                                        home manager: rsync backups of selected home
                                        files to USB / WebDAV mounts / OpenDrive,
                                        with last-backup history per destination
  enclave ui      [--port 3039]         macOS-style web UI on 127.0.0.1
  enclave seal --pgp [--recipient <fpr>]  seal into a PGP-encrypted vault instead
  enclave pgp init [--name N] [--email E] [--no-protection]
                                        create a dedicated key (~/.enclave/gnupg)
  enclave pgp list                      keys in the dedicated + system keyrings
  enclave pgp use <fpr|uid>             default recipient for new PGP vaults
  enclave pgp convert [dir] [--to pgp|passphrase] [--recipient <fpr>]
                                        re-encrypt a vault to the other scheme
Passphrase: ENCLAVE_PASSPHRASE env var, or hidden TTY prompt.
Vault: ~/.enclave/<project>.vault.enc (outside the tree), AES-256-GCM + scrypt, or OpenPGP via gpg.`;

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
    case "home": return cmdHome(positional, flags);
    case "stow": return cmdStow(positional, flags);
    case "unstow": return cmdUnstow(positional, flags);
    case "ui": return cmdUi(flags);
    case "pgp": {
      const sub = positional[0];
      if (sub === "init") return cmdPgpInit(flags);
      if (sub === "list") return cmdPgpList();
      if (sub === "use") {
        const q = positional[1];
        if (!q) fail("usage: enclave pgp use <fingerprint|uid>");
        return cmdPgpUse(q);
      }
      if (sub === "convert") return cmdPgpConvert(resolve(positional[1] || "."), flags);
      return fail("usage: enclave pgp init|list|use|convert");
    }
    default: fail(`unknown command '${cmd}' — try --help`);
  }
}

main().catch((e) => fail(e instanceof Error ? e.message : String(e)));
