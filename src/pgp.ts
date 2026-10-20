// pgp.ts — OpenPGP support via the system gpg binary.
// Two keyrings: the user's own ("system", their default GNUPGHOME) and a
// dedicated one for enclave-generated keys at ~/.enclave/gnupg (mode 700),
// so a tool key never pollutes — or depends on — the user's main keyring.
// Ciphertext/plaintext move through 0600 temp files; key passphrases via
// a passphrase file, never argv. Everything throws Error with gpg's own
// message trimmed when something fails.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync, readFileSync, rmSync, chmodSync } from "node:fs";
import { join, dirname } from "node:path";
import { homedir, tmpdir } from "node:os";
import { randomBytes } from "node:crypto";

export type Keyring = "dedicated" | "system";

export interface PgpKey {
  fingerprint: string;
  uid: string;
  created: string;       // ISO date
  expires: string | null;
  hasSecret: boolean;
  keyring: Keyring;
}

function homeDir(): string { return process.env.HOME || homedir(); }
export function enclaveHome(): string { return join(homeDir(), ".enclave"); }
export function dedicatedGpgHome(): string { return join(enclaveHome(), "gnupg"); }

export function ensureDedicatedHome(): string {
  const dir = dedicatedGpgHome();
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  try { chmodSync(dir, 0o700); } catch { /* already fine */ }
  // The dedicated keyring is enclave's own: never let gpg-agent cache the
  // key passphrase, so a protected vault key asks every time — the same
  // contract as the passphrase scheme. (The system keyring is untouched.)
  const agentConf = join(dir, "gpg-agent.conf");
  if (!existsSync(agentConf)) {
    writeFileSync(agentConf, "default-cache-ttl 0\nmax-cache-ttl 0\n", { mode: 0o600 });
  }
  return dir;
}

export function pgpAvailable(): boolean {
  try { return spawnSync("gpg", ["--version"], { encoding: "utf8" }).status === 0; }
  catch { return false; }
}

interface GpgOpts { input?: Buffer; passphrase?: string; }
function gpg(args: string[], keyring: Keyring, opts: GpgOpts = {}): { out: Buffer; err: string } {
  const env = { ...process.env } as Record<string, string>;
  if (keyring === "dedicated") env.GNUPGHOME = ensureDedicatedHome();
  const full = ["--batch", "--yes", ...args];
  const r = spawnSync("gpg", full, {
    input: opts.input, env, maxBuffer: 64 * 1024 * 1024,
  });
  const errText = (r.stderr ? r.stderr.toString("utf8") : "").trim();
  if (r.error) throw new Error("gpg failed to run: " + r.error.message);
  if (r.status !== 0) {
    const line = errText.split("\n").filter((l) => /failure|error|No secret key|decryption failed/i.test(l)).pop()
      || errText.split("\n").pop() || ("exit " + r.status);
    throw new Error("gpg: " + line.replace(/^gpg:\s*/, ""));
  }
  return { out: r.stdout as Buffer, err: errText };
}

// Passphrase goes through a short-lived 0600 file (never argv/stdin).
function withPassphraseFile<T>(passphrase: string | undefined, fn: (args: string[]) => T): T {
  if (passphrase === undefined) return fn([]);
  const dir = join(tmpdir(), "enclave-pgp-" + randomBytes(6).toString("hex"));
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const pf = join(dir, "pass");
  writeFileSync(pf, passphrase, { mode: 0o600 });
  try { return fn(["--pinentry-mode", "loopback", "--passphrase-file", pf]); }
  finally { rmSync(dir, { recursive: true, force: true }); }
}

export function listKeys(keyring: Keyring): PgpKey[] {
  if (keyring === "dedicated" && !existsSync(dedicatedGpgHome())) return [];
  let pubOut = "";
  try { pubOut = gpg(["--list-keys", "--with-colons", "--with-fingerprint"], keyring).out.toString("utf8"); }
  catch { return []; }
  const secretFprs = new Set<string>();
  try {
    const sec = gpg(["--list-secret-keys", "--with-colons", "--with-fingerprint"], keyring).out.toString("utf8");
    for (const line of sec.split("\n")) {
      const f = line.split(":");
      if (f[0] === "fpr") secretFprs.add(f[9]);
    }
  } catch { /* no secret keys */ }
  const keys: PgpKey[] = [];
  let current: PgpKey | null = null;
  for (const line of pubOut.split("\n")) {
    const f = line.split(":");
    if (f[0] === "pub") {
      current = {
        fingerprint: "", uid: "",
        created: f[5] ? new Date(parseInt(f[5], 10) * 1000).toISOString() : "",
        expires: f[6] ? new Date(parseInt(f[6], 10) * 1000).toISOString() : null,
        hasSecret: false, keyring,
      };
      keys.push(current);
    } else if (f[0] === "fpr" && current && !current.fingerprint) {
      current.fingerprint = f[9];
      current.hasSecret = secretFprs.has(f[9]);
    } else if (f[0] === "uid" && current && !current.uid) {
      current.uid = f[9];
    }
  }
  return keys.filter((k) => k.fingerprint);
}

export function listAllKeys(): PgpKey[] {
  return [...listKeys("dedicated"), ...listKeys("system")];
}

export function findKey(query: string): PgpKey | null {
  const all = listAllKeys();
  const q = query.replace(/\s+/g, "").toLowerCase();
  const exact = all.find((k) => k.fingerprint.toLowerCase() === q);
  if (exact) return exact;
  const byUid = all.filter((k) => k.uid.toLowerCase().includes(query.toLowerCase()));
  if (byUid.length === 1) return byUid[0];
  const byPrefix = all.filter((k) => k.fingerprint.toLowerCase().startsWith(q));
  if (byPrefix.length === 1) return byPrefix[0];
  const bySuffix = all.filter((k) => k.fingerprint.toLowerCase().endsWith(q)); // key-ID style
  return bySuffix.length === 1 ? bySuffix[0] : null;
}

// Create a dedicated keypair (Ed25519 sign + Cv25519 encryption subkey).
export function generateKey(opts: { name: string; email: string; passphrase?: string }): PgpKey {
  ensureDedicatedHome();
  const uid = `${opts.name} <${opts.email}>`;
  const { err } = withPassphraseFile(opts.passphrase, (passArgs) => {
    const base = passArgs.length ? passArgs : ["--pinentry-mode", "loopback"];
    return gpg([...base, "--quick-gen-key", uid, "ed25519", "sign", "never"], "dedicated", {});
  });
  const m = err.match(/KEY_CREATED ([0-9A-F]+)/) || err.match(/key ([0-9A-F]{16,}) marked as ultimately trusted/);
  let fpr = m ? m[1] : "";
  if (!fpr) {
    const mine = listKeys("dedicated").filter((k) => k.uid === uid);
    if (!mine.length) throw new Error("key generation did not produce a key");
    fpr = mine[mine.length - 1].fingerprint;
  }
  withPassphraseFile(opts.passphrase, (passArgs) => {
    const base = passArgs.length ? passArgs : ["--pinentry-mode", "loopback"];
    return gpg([...base, "--quick-add-key", fpr, "cv25519", "encr", "never"], "dedicated", {});
  });
  const key = listKeys("dedicated").find((k) => k.fingerprint === fpr);
  if (!key) throw new Error("generated key not found in dedicated keyring");
  return key;
}

export function pgpEncrypt(recipient: string, keyring: Keyring, plaintext: Buffer): Buffer {
  const dir = join(tmpdir(), "enclave-pgp-" + randomBytes(6).toString("hex"));
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const inF = join(dir, "plain"), outF = join(dir, "cipher");
  try {
    writeFileSync(inF, plaintext, { mode: 0o600 });
    gpg(["--trust-model", "always", "--encrypt", "--recipient", recipient, "--output", outF, inF], keyring);
    return readFileSync(outF);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

export function pgpDecrypt(keyring: Keyring, passphrase: string | undefined, ciphertext: Buffer): Buffer {
  const dir = join(tmpdir(), "enclave-pgp-" + randomBytes(6).toString("hex"));
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const inF = join(dir, "cipher"), outF = join(dir, "plain");
  try {
    writeFileSync(inF, ciphertext, { mode: 0o600 });
    withPassphraseFile(passphrase, (passArgs) =>
      gpg([...passArgs, "--decrypt", "--output", outF, inF], keyring));
    return readFileSync(outF);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

/* -------- enclave config (~/.enclave/config.json): default recipient -------- */
export interface EnclaveConfig { pgpRecipient?: string; pgpKeyring?: Keyring }
function configPath(): string { return join(enclaveHome(), "config.json"); }
export function loadConfig(): EnclaveConfig {
  try { return JSON.parse(readFileSync(configPath(), "utf8")) as EnclaveConfig; }
  catch { return {}; }
}
export function saveConfig(cfg: EnclaveConfig): void {
  mkdirSync(dirname(configPath()), { recursive: true });
  writeFileSync(configPath(), JSON.stringify(cfg, null, 2) + "\n", { mode: 0o600 });
}

// Resolve which key a `--pgp` seal should use: explicit > config > dedicated.
export function resolveRecipient(explicit?: string): PgpKey {
  if (explicit) {
    const k = findKey(explicit);
    if (!k) throw new Error(`no PGP key matches '${explicit}' in either keyring`);
    return k;
  }
  const cfg = loadConfig();
  if (cfg.pgpRecipient) {
    const k = findKey(cfg.pgpRecipient);
    if (k) return k;
  }
  const dedicated = listKeys("dedicated");
  if (dedicated.length === 1) return dedicated[0];
  if (dedicated.length > 1) throw new Error("multiple dedicated keys — pick one with 'enclave pgp use <fingerprint>'");
  throw new Error("no PGP key configured — run 'enclave pgp init' (dedicated key) or 'enclave pgp use <fingerprint>' (your existing key)");
}
