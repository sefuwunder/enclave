// vault.ts — the enclave itself: an AES-256-GCM encrypted JSON store.
// Key derived from the passphrase with scrypt (N=2^15). The vault file
// holds no plaintext: { v, kdf params, salt, iv, tag, data } (base64).
// GCM's auth tag makes tampering and wrong passphrases fail loudly.
import { scryptSync, randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

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

interface VaultFile {
  v: 1;
  kdf: { salt: string; N: number; r: number; p: number };
  iv: string;
  tag: string;
  data: string;
}

const SCRYPT = { N: 32768, r: 8, p: 1 };
const MAXMEM = 256 * 1024 * 1024; // N=2^15,r=8 needs ~34MB > default cap

function deriveKey(passphrase: string, salt: Buffer, params = SCRYPT): Buffer {
  return scryptSync(passphrase, salt, 32, { ...params, maxmem: MAXMEM });
}

export function encryptVault(data: VaultData, passphrase: string): VaultFile {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = deriveKey(passphrase, salt);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const plain = Buffer.from(JSON.stringify(data), "utf8");
  const enc = Buffer.concat([cipher.update(plain), cipher.final()]);
  return {
    v: 1,
    kdf: { salt: salt.toString("base64"), ...SCRYPT },
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    data: enc.toString("base64"),
  };
}

export function decryptVault(file: VaultFile, passphrase: string): VaultData {
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

export function saveVault(path: string, data: VaultData, passphrase: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(encryptVault(data, passphrase), null, 2) + "\n", { mode: 0o600 });
}

export function loadVault(path: string, passphrase: string): VaultData {
  const file = JSON.parse(readFileSync(path, "utf8")) as VaultFile;
  return decryptVault(file, passphrase);
}

export function vaultExists(path: string): boolean {
  return existsSync(path);
}

export function emptyVault(project: string): VaultData {
  return { project, createdAt: new Date().toISOString(), entries: [] };
}
