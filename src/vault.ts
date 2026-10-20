// vault.ts — the enclave itself: an encrypted JSON store with two schemes.
//   passphrase: scrypt (N=2^15) + AES-256-GCM (v1 files load unchanged)
//   pgp:        the JSON is a system-gpg OpenPGP message to one recipient;
//               the envelope records scheme + recipient + keyring in the
//               clear so tools know what to ask for before decrypting.
// Wrong passphrases, wrong keys and tampering all fail loudly.
import { scryptSync, randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { pgpEncrypt, pgpDecrypt, type Keyring } from "./pgp.ts";

export interface VaultEntry {
  name: string;
  value: string;     // text secrets; "" for blobs
  file: string;      // source file (relative to tree root)
  kind: string;
  sealedAt: string;  // ISO date
  blob?: string;     // base64 file bytes (blob entries only)
  size?: number;     // original byte size (blobs)
  sha256?: string;   // content hash (blobs)
  meta?: string;     // what personal data was detected (blobs)
}

export interface VaultData {
  project: string;
  createdAt: string;
  entries: VaultEntry[];
}

export type VaultScheme = "passphrase" | "pgp";

export interface VaultAuth {
  passphrase?: string;          // vault passphrase, or the PGP key's passphrase
  recipient?: string;           // pgp: fingerprint to encrypt to (save only)
  keyring?: Keyring;            // pgp: where the key lives
}

export interface VaultFileInfo {
  scheme: VaultScheme;
  recipient?: string;
  keyring?: Keyring;
}

interface VaultFileV1 {
  v: 1;
  kdf: { salt: string; N: number; r: number; p: number };
  iv: string;
  tag: string;
  data: string;
}
interface VaultFileV2 {
  v: 2;
  scheme: VaultScheme;
  kdf?: { salt: string; N: number; r: number; p: number };
  iv?: string;
  tag?: string;
  pgp?: { recipient: string; keyring: Keyring };
  data: string;
}

const SCRYPT = { N: 32768, r: 8, p: 1 };
const MAXMEM = 256 * 1024 * 1024; // N=2^15,r=8 needs ~34MB > default cap

function deriveKey(passphrase: string, salt: Buffer, params = SCRYPT): Buffer {
  return scryptSync(passphrase, salt, 32, { ...params, maxmem: MAXMEM });
}

export function encryptVaultPassphrase(data: VaultData, passphrase: string): VaultFileV2 {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = deriveKey(passphrase, salt);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const plain = Buffer.from(JSON.stringify(data), "utf8");
  const enc = Buffer.concat([cipher.update(plain), cipher.final()]);
  return {
    v: 2, scheme: "passphrase",
    kdf: { salt: salt.toString("base64"), ...SCRYPT },
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    data: enc.toString("base64"),
  };
}

export function decryptPassphrase(file: VaultFileV1 | VaultFileV2, passphrase: string): VaultData {
  if (!file.kdf || !file.iv || !file.tag) throw new Error("vault file is missing its passphrase envelope");
  const salt = Buffer.from(file.kdf.salt, "base64");
  const key = deriveKey(passphrase, salt, { N: file.kdf.N, r: file.kdf.r, p: file.kdf.p });
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(file.iv, "base64"));
  decipher.setAuthTag(Buffer.from(file.tag, "base64"));
  const plain = Buffer.concat([
    decipher.update(Buffer.from(file.data, "base64")),
    decipher.final(), // throws on wrong passphrase / tampering
  ]);
  return JSON.parse(plain.toString("utf8")) as VaultData;
}

export function inspectVaultFile(path: string): VaultFileInfo {
  const file = JSON.parse(readFileSync(path, "utf8")) as VaultFileV1 | VaultFileV2;
  if (file.v === 1) return { scheme: "passphrase" };
  if (file.scheme === "pgp" && file.pgp) {
    return { scheme: "pgp", recipient: file.pgp.recipient, keyring: file.pgp.keyring };
  }
  return { scheme: "passphrase" };
}

export function saveVault(path: string, data: VaultData, auth: VaultAuth): void {
  mkdirSync(dirname(path), { recursive: true });
  let file: VaultFileV2;
  if (auth.recipient) {
    const cipher = pgpEncrypt(auth.recipient, auth.keyring || "dedicated", Buffer.from(JSON.stringify(data), "utf8"));
    file = {
      v: 2, scheme: "pgp",
      pgp: { recipient: auth.recipient, keyring: auth.keyring || "dedicated" },
      data: cipher.toString("base64"),
    };
  } else {
    if (!auth.passphrase) throw new Error("saveVault needs a passphrase or a PGP recipient");
    file = encryptVaultPassphrase(data, auth.passphrase);
  }
  writeFileSync(path, JSON.stringify(file, null, 2) + "\n", { mode: 0o600 });
}

export function loadVault(path: string, auth: VaultAuth): VaultData {
  const file = JSON.parse(readFileSync(path, "utf8")) as VaultFileV1 | VaultFileV2;
  if (file.v === 2 && file.scheme === "pgp") {
    if (!file.pgp) throw new Error("vault file is missing its PGP envelope");
    const plain = pgpDecrypt(file.pgp.keyring, auth.passphrase, Buffer.from(file.data, "base64"));
    return JSON.parse(plain.toString("utf8")) as VaultData;
  }
  if (!auth.passphrase) throw new Error("this vault needs a passphrase");
  return decryptPassphrase(file, auth.passphrase);
}

export function vaultExists(path: string): boolean {
  return existsSync(path);
}

export function emptyVault(project: string): VaultData {
  return { project, createdAt: new Date().toISOString(), entries: [] };
}
