// core.ts — the tree operations shared by the CLI and the UI server:
// seal / verify / restore / inject / extract, plus manifest IO.
// Functions take an already-decrypted VaultData and return structured
// results; callers own passphrases, persistence and printing.
import { readFileSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, resolve, basename } from "node:path";
import { homedir } from "node:os";
import { scanTree, type Finding } from "./scan.ts";
import type { VaultData, VaultEntry } from "./vault.ts";

export const TOKEN_PREFIX = "enclave:";

export interface ManifestEntry { name: string; file: string; line: number; kind: string }
export interface Manifest { v: 1; project: string; entries: ManifestEntry[] }

export function projectOf(dir: string): string {
  return basename(resolve(dir)).replace(/[^A-Za-z0-9_.-]+/g, "-");
}
export function defaultVaultPath(dir: string): string {
  // $HOME first: predictable under tests/tools that redirect it per-process
  const home = process.env.HOME || homedir();
  return join(home, ".enclave", projectOf(dir) + ".vault.enc");
}
export function manifestPath(dir: string): string { return join(dir, "enclave.manifest.json"); }
export function loadManifest(dir: string): Manifest | null {
  const p = manifestPath(dir);
  if (!existsSync(p)) return null;
  return JSON.parse(readFileSync(p, "utf8")) as Manifest;
}
export function saveManifest(dir: string, m: Manifest): void {
  writeFileSync(manifestPath(dir), JSON.stringify(m, null, 2) + "\n");
}
export function deleteManifest(dir: string): void {
  rmSync(manifestPath(dir), { force: true });
}

export interface PlannedItem { f: Finding; name: string }

// Resolve each finding's vault name against the existing vault so a
// different secret never silently takes an existing name.
export function resolvePlan(findings: Finding[], vault: VaultData): PlannedItem[] {
  const now = new Date().toISOString();
  const taken = new Map(vault.entries.map((e) => [e.name, e]));
  const planned: PlannedItem[] = [];
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
  return planned;
}

export interface SealResult { sealed: number; findings: Finding[]; planned: PlannedItem[] }

// Seal all findings in `dir` into `vault` (mutated in place; the caller
// persists it). Files are rewritten; the manifest is updated.
export function sealTree(dir: string, vault: VaultData): SealResult {
  const findings = scanTree(dir);
  if (!findings.length) return { sealed: 0, findings, planned: [] };
  const planned = resolvePlan(findings, vault);
  const byName = new Map(vault.entries.map((e) => [e.name, e]));
  const manifest = loadManifest(dir) || { v: 1 as const, project: projectOf(dir), entries: [] };
  const now = new Date().toISOString();
  let sealed = 0;

  const byFile = new Map<string, PlannedItem[]>();
  for (const p of planned) {
    if (p.f.blob) continue;
    const arr = byFile.get(p.f.file) || [];
    arr.push(p);
    byFile.set(p.f.file, arr);
  }
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
        const entry: VaultEntry = { name, value: f.value, file: f.file, kind: f.kind, sealedAt: now };
        vault.entries.push(entry);
        byName.set(name, entry);
      }
      if (!manifest.entries.some((m) => m.name === name)) {
        manifest.entries.push({ name, file: f.file, line: f.line, kind: f.kind });
      }
      sealed++;
    }
    writeFileSync(full, content);
  }
  // Binary blobs: bytes go into the vault, a tombstone stays in-tree.
  for (const { f, name } of planned) {
    if (!f.blob) continue;
    const full = join(dir, f.file);
    const bytes = readFileSync(full);
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    const existingBlob = byName.get(name);
    if (existingBlob && existingBlob.sha256 !== sha256) {
      existingBlob.blob = bytes.toString("base64");
      existingBlob.size = bytes.length;
      existingBlob.sha256 = sha256;
      existingBlob.meta = f.meta;
      existingBlob.sealedAt = now;
    } else if (!existingBlob) {
      const entry: VaultEntry = {
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
    sealed++;
  }
  saveManifest(dir, manifest);
  return { sealed, findings, planned };
}

export interface VerifyResult { ok: boolean; findings: Finding[]; drift: string[] }

export function verifyTree(dir: string): VerifyResult {
  const findings = scanTree(dir);
  const drift: string[] = [];
  const manifest = loadManifest(dir);
  if (manifest) {
    for (const m of manifest.entries) {
      const full = join(dir, m.file);
      const text = existsSync(full) ? readFileSync(full, "utf8") : "";
      if (!text.includes(TOKEN_PREFIX + m.name) && !text.includes("enclave-blob:" + m.name)) {
        drift.push(`${m.name} placeholder missing from ${m.file}`);
      }
    }
  }
  return { ok: findings.length === 0 && drift.length === 0, findings, drift };
}

export interface RestoreResult { restored: number; missing: number; warnings: string[] }

export function restoreTree(dir: string, vault: VaultData): RestoreResult {
  const manifest = loadManifest(dir);
  if (!manifest) throw new Error("no enclave.manifest.json — nothing to restore");
  const byName = new Map(vault.entries.map((e) => [e.name, e]));
  const warnings: string[] = [];
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
    const blobItems = items.filter((m) => m.kind.startsWith("blob:"));
    const textItems = items.filter((m) => !m.kind.startsWith("blob:"));
    for (const m of blobItems) {
      const e = byName.get(m.name);
      if (e && e.blob !== undefined) {
        const bytes = Buffer.from(e.blob, "base64");
        const sha = createHash("sha256").update(bytes).digest("hex");
        if (e.sha256 && sha !== e.sha256) { missing++; continue; }
        const tomb = readFileSync(full, "utf8");
        const tombSha = tomb.match(/^sha256:([0-9a-f]{64})$/m)?.[1];
        if (tombSha && e.sha256 && tombSha !== e.sha256) {
          warnings.push(`${m.file} tombstone sha does not match vault entry ${m.name} — skipped`);
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
  deleteManifest(dir);
  return { restored, missing, warnings };
}

const ENV_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
export function envEntries(vault: VaultData): VaultEntry[] {
  return vault.entries.filter((e) => e.blob === undefined && ENV_NAME_RE.test(e.name));
}

export function envQuote(v: string): string {
  return "'" + v.replace(/'/g, "'\\''") + "'";
}

export function injectEnvFile(vault: VaultData, out: string): number {
  const lines = envEntries(vault).map((e) => `${e.name}=${envQuote(e.value)}`);
  writeFileSync(out, lines.join("\n") + "\n", { mode: 0o600 });
  return lines.length;
}

export function extractBlobBytes(vault: VaultData, name: string): { entry: VaultEntry; bytes: Buffer } {
  const e = vault.entries.find((x) => x.name === name);
  if (!e) throw new Error(`no entry named ${name}`);
  if (e.blob === undefined) throw new Error(`${name} is a text secret, not a blob`);
  const bytes = Buffer.from(e.blob, "base64");
  const sha = createHash("sha256").update(bytes).digest("hex");
  if (e.sha256 && sha !== e.sha256) throw new Error("sha256 mismatch — vault entry is corrupt");
  return { entry: e, bytes };
}
