// home.ts — the home manager: enclave's care of the whole home dir.
// It inherits the stow machinery (reports package/link state for the
// configured stow directory) and adds rsync backups of *selected* home
// files to USB drives (path destinations), WebDAV shares (via their
// local mount point) and OpenDrive (its REST API). Every run is
// recorded per destination; that history is what the UI renders as
// pills — "last backup · when · where" — and what `enclave home
// status` prints.
//
// Config lives at ~/.enclave/home.json (mode 600, outside any tree).
// Credentials live at ~/.enclave/credentials.json (mode 600) or in
// OPENDRIVE_USERNAME / OPENDRIVE_PASSWORD; never in the config, never
// printed. Backups are plain mirrors (files are copied as-is into an
// "enclave-home" folder on the destination) — enclave does not encrypt
// them; the vault protects secrets at rest in trees, backups protect
// against losing the machine.
import { spawnSync } from "node:child_process";
import {
  existsSync, readFileSync, writeFileSync, mkdirSync, statSync,
  lstatSync, realpathSync, readdirSync, utimesSync, rmSync, rmdirSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { join, resolve, dirname, basename, sep } from "node:path";
import { listPackages, expandTarget, stowAvailable } from "./stow.ts";
import { loadManifest } from "./core.ts";
import { OpenDrive, type RemoteFile } from "./opendrive.ts";

export const BACKUP_ROOT_NAME = "enclave-home";

export function realHome(): string { return process.env.HOME || homedir(); }
export function enclaveDir(): string { return join(realHome(), ".enclave"); }
export function homeConfigPath(): string { return join(enclaveDir(), "home.json"); }
export function credentialsPath(): string { return join(enclaveDir(), "credentials.json"); }

/* ------------------------------- config ------------------------------- */

export type DestType = "path" | "webdav" | "opendrive";
export interface DestConfig {
  name: string;
  type: DestType;
  path?: string;         // path: backup root dir · webdav: local mount point
  url?: string;          // webdav: the share URL (identity/display; rsync uses the mount)
  folder?: string;       // opendrive: remote folder (default /EnclaveHome)
  requireMount?: boolean; // refuse unless `path` is a real mount point (webdav: default true)
}
export interface RunRecord { at: string; files: number; bytes: number; ok: boolean; note?: string }
export interface HomeConfig {
  v: 1;
  stowDir?: string;      // verbatim ("~/dotfiles" ok) — the stow side of home
  files: string[];       // home-relative paths selected for backup
  destinations: DestConfig[];
  history: Record<string, { backup?: RunRecord; restore?: RunRecord }>;
}

export function emptyHomeConfig(): HomeConfig {
  return { v: 1, files: [], destinations: [], history: {} };
}
export function loadHomeConfig(): HomeConfig | null {
  try {
    const c = JSON.parse(readFileSync(homeConfigPath(), "utf8")) as HomeConfig;
    if (!Array.isArray(c.files) || !Array.isArray(c.destinations)) return null;
    c.history = c.history || {};
    return c;
  } catch { return null; }
}
export function saveHomeConfig(cfg: HomeConfig): void {
  mkdirSync(enclaveDir(), { recursive: true });
  writeFileSync(homeConfigPath(), JSON.stringify(cfg, null, 2) + "\n", { mode: 0o600 });
}

/* ----------------------------- credentials ----------------------------- */

export interface Credentials { opendrive?: { username: string; password: string } }
export function loadCredentials(): Credentials {
  try { return JSON.parse(readFileSync(credentialsPath(), "utf8")) as Credentials; }
  catch { return {}; }
}
export function saveCredentials(c: Credentials): void {
  mkdirSync(enclaveDir(), { recursive: true });
  writeFileSync(credentialsPath(), JSON.stringify(c, null, 2) + "\n", { mode: 0o600 });
}
export function opendriveCreds(): { username: string; password: string } | null {
  const u = process.env.OPENDRIVE_USERNAME, p = process.env.OPENDRIVE_PASSWORD;
  if (u && p) return { username: u, password: p };
  const c = loadCredentials().opendrive;
  return c && c.username && c.password ? c : null;
}

/* ------------------------------ mutations ------------------------------ */

// Normalize a user-supplied path to a home-relative selection.
// Absolute paths under $HOME relativize; anything escaping $HOME is rejected.
export function normalizeSelection(p: string): string | null {
  let rel = p.trim();
  if (!rel) return null;
  if (rel === "~") return null; // the whole home is not a selection
  if (rel.startsWith("~/")) rel = rel.slice(2);
  else if (rel.startsWith("/")) {
    const home = realHome();
    if (rel !== home && rel.startsWith(home + sep)) rel = rel.slice(home.length + 1);
    else return null;
  }
  const parts: string[] = [];
  for (const seg of rel.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") { if (!parts.length) return null; parts.pop(); continue; }
    parts.push(seg);
  }
  return parts.length ? parts.join("/") : null;
}

export function addFiles(cfg: HomeConfig, paths: string[]): { added: string[]; rejected: string[] } {
  const added: string[] = [], rejected: string[] = [];
  for (const p of paths) {
    const rel = normalizeSelection(p);
    if (!rel) { rejected.push(p); continue; }
    if (!cfg.files.includes(rel)) { cfg.files.push(rel); added.push(rel); }
  }
  cfg.files.sort();
  return { added, rejected };
}
export function removeFile(cfg: HomeConfig, path: string): boolean {
  const rel = normalizeSelection(path);
  const i = rel ? cfg.files.indexOf(rel) : -1;
  if (i === -1) return false;
  cfg.files.splice(i, 1);
  return true;
}
export function addDest(cfg: HomeConfig, dest: DestConfig): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(dest.name)) throw new Error(`bad destination name '${dest.name}'`);
  if (cfg.destinations.some((d) => d.name === dest.name)) throw new Error(`destination '${dest.name}' already exists`);
  if (dest.type === "path" && !dest.path) throw new Error("a path destination needs --path <dir>");
  if (dest.type === "webdav" && !dest.path) throw new Error("a webdav destination needs --path <mount point> (mount the share first)");
  cfg.destinations.push(dest);
}
export function removeDest(cfg: HomeConfig, name: string): boolean {
  const i = cfg.destinations.findIndex((d) => d.name === name);
  if (i === -1) return false;
  cfg.destinations.splice(i, 1);
  delete cfg.history[name];
  return true;
}

/* ------------------------------ mount guard ----------------------------- */

export function readMounts(): string[] {
  try {
    return readFileSync("/proc/mounts", "utf8").split("\n")
      .map((l) => l.split(" ")[1])
      .filter(Boolean)
      .map((p) => p.replace(/\\040/g, " ").replace(/\\011/g, "\t").replace(/\\134/g, "\\"));
  } catch { return []; }
}
// True when `path` itself is a mount point: listed in /proc/mounts, or its
// device differs from its parent's (the classic mountpoint test).
export function isMountPoint(path: string, mounts: string[] = readMounts()): boolean {
  const p = resolve(path);
  if (mounts.includes(p)) return true;
  try {
    return statSync(p).dev !== statSync(dirname(p)).dev;
  } catch { return false; }
}
export function destNeedsMount(d: DestConfig): boolean {
  return d.requireMount ?? d.type === "webdav";
}

/* -------------------------------- rsync -------------------------------- */

type Env = Record<string, string | undefined>;
export function rsyncAvailable(env: Env = process.env): boolean {
  try { return spawnSync("rsync", ["--version"], { encoding: "utf8", env }).status === 0; }
  catch { return false; }
}

export interface TransferResult { files: number; bytes: number; skipped: string[]; notes: string[] }
export interface TransferOpts { deleteExtra?: boolean; env?: Env; mounts?: string[]; home?: string }

function parseStats(out: string): { files: number; bytes: number } {
  const files = /Number of regular files transferred:\s*([\d,]+)/.exec(out)?.[1];
  const bytes = /Total transferred file size:\s*([\d,]+)/.exec(out)?.[1];
  return {
    files: files ? parseInt(files.replace(/,/g, ""), 10) : 0,
    bytes: bytes ? parseInt(bytes.replace(/,/g, ""), 10) : 0,
  };
}

function destLocalRoot(dest: DestConfig): string {
  const base = expandTarget(dest.path as string);
  return join(base, BACKUP_ROOT_NAME);
}

function guardLocalDest(dest: DestConfig, opts: TransferOpts): string {
  if (dest.type === "opendrive") throw new Error("internal: opendrive has no local root");
  const base = expandTarget(dest.path as string);
  if (!existsSync(base)) {
    throw new Error(`destination '${dest.name}': ${base} does not exist — is the drive mounted / the share connected?`);
  }
  if (destNeedsMount(dest) && !isMountPoint(base, opts.mounts ?? readMounts())) {
    throw new Error(`destination '${dest.name}': ${base} is not a mount point — refusing to write a backup onto the local disk (mount the drive/share, or re-add the destination without the mount requirement)`);
  }
  return destLocalRoot(dest);
}

function runRsync(args: string[], cwd: string, env: Env): { files: number; bytes: number; output: string } {
  const r = spawnSync("rsync", args, { cwd, encoding: "utf8", env, maxBuffer: 64 * 1024 * 1024 });
  const out = (r.stdout || "") + (r.stderr || "");
  if (r.error) throw new Error("could not run rsync (" + r.error.message + ") — is rsync installed?");
  // 0 = ok · 24 = source files vanished mid-run (benign for a live home dir)
  if (r.status !== 0 && r.status !== 24) {
    const tail = out.trim().split("\n").slice(-3).join(" ");
    throw new Error(`rsync failed (exit ${r.status})${tail ? ": " + tail : ""}`);
  }
  return { ...parseStats(out), output: out };
}

// The exact set of destination-relative files the selection should
// produce — the yardstick for pruning. (rsync's own --delete with
// --relative never prunes files outside a source's subtree, e.g. at the
// destination root, so enclave prunes its managed folder itself.)
function expectedDestFiles(cfg: HomeConfig, home: string): Set<string> {
  const out = new Set<string>();
  const walk = (abs: string, rel: string) => {
    let st;
    try { st = lstatSync(abs); } catch { return; }
    if (st.isDirectory()) {
      for (const e of readdirSync(abs)) {
        if (e === ".git" || e === "node_modules") continue;
        walk(join(abs, e), rel + "/" + e);
      }
    } else out.add(rel);
  };
  for (const sel of cfg.files) {
    const abs = join(home, sel);
    if (existsSync(abs)) walk(abs, sel);
  }
  return out;
}

function pruneDest(root: string, keep: Set<string>): number {
  let removed = 0;
  const walk = (abs: string, rel: string) => {
    for (const e of readdirSync(abs, { withFileTypes: true })) {
      const a = join(abs, e.name);
      const r = rel ? rel + "/" + e.name : e.name;
      if (e.isDirectory()) {
        walk(a, r);
        try { if (readdirSync(a).length === 0) rmdirSync(a); } catch { /* kept */ }
      } else if (!keep.has(r)) {
        rmSync(a, { force: true });
        removed++;
      }
    }
  };
  walk(root, "");
  return removed;
}

export function rsyncBackup(cfg: HomeConfig, dest: DestConfig, opts: TransferOpts = {}): TransferResult {
  if (!rsyncAvailable(opts.env)) throw new Error("rsync is not installed (or not on PATH)");
  const home = opts.home || realHome();
  const root = guardLocalDest(dest, opts);
  mkdirSync(root, { recursive: true });
  const existing: string[] = [], skipped: string[] = [];
  for (const f of cfg.files) (existsSync(join(home, f)) ? existing : skipped).push(f);
  if (!existing.length) return { files: 0, bytes: 0, skipped, notes: ["nothing selected exists"] };
  const args = ["-a", "--relative", "--stats", "--", ...existing, root + "/"];
  const r = runRsync(args, home, opts.env ?? process.env);
  const notes: string[] = [];
  if (opts.deleteExtra) {
    const pruned = pruneDest(root, expectedDestFiles(cfg, home));
    if (pruned) notes.push(`pruned ${pruned} stale file(s) from the backup`);
  }
  return { files: r.files, bytes: r.bytes, skipped, notes };
}

export function rsyncRestore(cfg: HomeConfig, dest: DestConfig, opts: TransferOpts = {}): TransferResult {
  if (!rsyncAvailable(opts.env)) throw new Error("rsync is not installed (or not on PATH)");
  const home = opts.home || realHome();
  const root = guardLocalDest(dest, opts);
  const present: string[] = [], skipped: string[] = [];
  for (const f of cfg.files) (existsSync(join(root, f)) ? present : skipped).push(f);
  if (!present.length) return { files: 0, bytes: 0, skipped, notes: ["nothing in this backup matches the selection"] };
  const args = ["-a", "--relative", "--stats", "--", ...present, home + "/"];
  const r = runRsync(args, root, opts.env ?? process.env);
  return { files: r.files, bytes: r.bytes, skipped, notes: [] };
}

/* ------------------------------- OpenDrive ------------------------------ */

export interface OdOpts { fetchFn?: typeof fetch; apiBase?: string }

function expandSelections(cfg: HomeConfig, home: string): { files: string[]; skipped: string[] } {
  const files: string[] = [], skipped: string[] = [];
  const walk = (abs: string, rel: string) => {
    const st = statSync(abs);
    if (st.isDirectory()) {
      for (const e of readdirSync(abs, { withFileTypes: true })) {
        if (e.name === ".git" || e.name === "node_modules") continue;
        walk(join(abs, e.name), rel + "/" + e.name);
      }
    } else if (st.isFile()) files.push(rel);
  };
  for (const sel of cfg.files) {
    const abs = join(home, sel);
    if (!existsSync(abs)) { skipped.push(sel); continue; }
    walk(abs, sel);
  }
  return { files: files.sort(), skipped };
}

function sha256File(abs: string): string {
  return createHash("sha256").update(readFileSync(abs)).digest("hex");
}

async function odClient(opts: OdOpts): Promise<OpenDrive> {
  const creds = opendriveCreds();
  if (!creds) throw new Error("OpenDrive credentials are not set — run 'enclave home creds opendrive' or set OPENDRIVE_USERNAME / OPENDRIVE_PASSWORD");
  const od = new OpenDrive({ apiBase: opts.apiBase, fetchFn: opts.fetchFn });
  await od.login(creds.username, creds.password);
  return od;
}

export async function opendriveBackup(cfg: HomeConfig, dest: DestConfig, opts: OdOpts & { home?: string } = {}): Promise<TransferResult> {
  const home = opts.home || realHome();
  const od = await odClient(opts);
  const folder = (dest.folder || "/EnclaveHome") + "/" + BACKUP_ROOT_NAME;
  const baseId = await od.ensureFolderPath(folder);
  const remote = await od.listRecursive(baseId);
  const { files, skipped } = expandSelections(cfg, home);
  const dirIds = new Map<string, string>([["", baseId]]);
  const folderIdFor = async (relDir: string): Promise<string> => {
    if (!dirIds.has(relDir)) {
      dirIds.set(relDir, await od.ensureFolderPath(folder + (relDir ? "/" + relDir : "")));
    }
    return dirIds.get(relDir) as string;
  };
  let count = 0, bytes = 0;
  for (const rel of files) {
    const abs = join(home, rel);
    const st = statSync(abs);
    const r = remote.get(rel);
    const hash = r && /^[0-9a-f]{64}$/i.test(r.hash || "") ? sha256File(abs) : null;
    const fresh = r && r.size === st.size &&
      (hash ? r.hash!.toLowerCase() === hash : Math.abs(r.mtime - st.mtimeMs) < 2000);
    if (fresh) continue;
    const dir = rel.includes("/") ? rel.slice(0, rel.lastIndexOf("/")) : "";
    await od.uploadFile(await folderIdFor(dir), basename(rel), abs);
    count++;
    bytes += st.size;
  }
  return { files: count, bytes, skipped, notes: [] };
}

export async function opendriveRestore(cfg: HomeConfig, dest: DestConfig, opts: OdOpts & { home?: string } = {}): Promise<TransferResult> {
  const home = opts.home || realHome();
  const od = await odClient(opts);
  const folder = (dest.folder || "/EnclaveHome") + "/" + BACKUP_ROOT_NAME;
  const baseId = await od.ensureFolderPath(folder);
  const remote = await od.listRecursive(baseId);
  let count = 0, bytes = 0;
  const skipped: string[] = [];
  for (const sel of cfg.files) {
    const hits: [string, RemoteFile][] = [];
    const exact = remote.get(sel);
    if (exact) hits.push([sel, exact]);
    for (const [rel, rf] of remote) if (rel.startsWith(sel + "/")) hits.push([rel, rf]);
    if (!hits.length) { skipped.push(sel); continue; }
    for (const [rel, rf] of hits) {
      const buf = await od.downloadFile(rf.id);
      const abs = join(home, rel);
      mkdirSync(dirname(abs), { recursive: true });
      writeFileSync(abs, buf);
      if (rf.mtime) { try { utimesSync(abs, new Date(rf.mtime), new Date(rf.mtime)); } catch { /* best effort */ } }
      count++;
      bytes += buf.length;
    }
  }
  return { files: count, bytes, skipped, notes: [] };
}

/* --------------------------- run + record history ------------------------ */

function record(cfg: HomeConfig, destName: string, kind: "backup" | "restore", rec: RunRecord): void {
  cfg.history[destName] = { ...(cfg.history[destName] || {}), [kind]: rec };
  saveHomeConfig(cfg);
}

export async function backupTo(cfg: HomeConfig, destName: string, opts: TransferOpts & OdOpts = {}): Promise<RunRecord> {
  const dest = cfg.destinations.find((d) => d.name === destName);
  if (!dest) throw new Error(`no destination named '${destName}'`);
  try {
    const r = dest.type === "opendrive"
      ? await opendriveBackup(cfg, dest, opts)
      : rsyncBackup(cfg, dest, opts);
    const rec: RunRecord = {
      at: new Date().toISOString(), files: r.files, bytes: r.bytes, ok: true,
      note: [r.skipped.length ? `skipped (missing): ${r.skipped.join(", ")}` : "", ...r.notes].filter(Boolean).join("; ") || undefined,
    };
    record(cfg, destName, "backup", rec);
    return rec;
  } catch (e) {
    record(cfg, destName, "backup", {
      at: new Date().toISOString(), files: 0, bytes: 0, ok: false,
      note: e instanceof Error ? e.message.slice(0, 300) : String(e),
    });
    throw e;
  }
}

export async function restoreFrom(cfg: HomeConfig, destName: string, opts: TransferOpts & OdOpts = {}): Promise<RunRecord> {
  const dest = cfg.destinations.find((d) => d.name === destName);
  if (!dest) throw new Error(`no destination named '${destName}'`);
  try {
    const r = dest.type === "opendrive"
      ? await opendriveRestore(cfg, dest, opts)
      : rsyncRestore(cfg, dest, opts);
    const rec: RunRecord = {
      at: new Date().toISOString(), files: r.files, bytes: r.bytes, ok: true,
      note: [r.skipped.length ? `not in backup: ${r.skipped.join(", ")}` : "", ...r.notes].filter(Boolean).join("; ") || undefined,
    };
    record(cfg, destName, "restore", rec);
    return rec;
  } catch (e) {
    record(cfg, destName, "restore", {
      at: new Date().toISOString(), files: 0, bytes: 0, ok: false,
      note: e instanceof Error ? e.message.slice(0, 300) : String(e),
    });
    throw e;
  }
}

export async function backupAll(cfg: HomeConfig, opts: TransferOpts & OdOpts = {}): Promise<{ name: string; rec?: RunRecord; error?: string }[]> {
  const out: { name: string; rec?: RunRecord; error?: string }[] = [];
  for (const d of cfg.destinations) {
    try { out.push({ name: d.name, rec: await backupTo(cfg, d.name, opts) }); }
    catch (e) { out.push({ name: d.name, error: e instanceof Error ? e.message : String(e) }); }
  }
  return out;
}

/* --------------------------------- status -------------------------------- */
// Everything the pills need: per destination, where it is, whether it is
// reachable/mounted, and the last recorded backup + restore.

export interface FileStatus { path: string; exists: boolean; dir: boolean; size: number | null }
export interface DestStatus {
  name: string; type: DestType; where: string;
  mounted: boolean | null; // null = not applicable (opendrive)
  lastBackup: RunRecord | null; lastRestore: RunRecord | null;
}
export interface StowStatus { dir: string; target: string; packages: { name: string; stowed: boolean }[] }
export interface HomeStatus {
  configured: boolean;
  home: string;
  files: FileStatus[];
  destinations: DestStatus[];
  stow: StowStatus | null;
  rsyncAvailable: boolean;
  stowAvailable: boolean;
  opendriveConfigured: boolean;
}

export function destWhere(d: DestConfig): string {
  if (d.type === "opendrive") return `OpenDrive ${d.folder || "/EnclaveHome"}`;
  if (d.type === "webdav") return d.url || expandTarget(d.path as string);
  return expandTarget(d.path as string);
}

function stowStatus(cfg: HomeConfig): StowStatus | null {
  if (!cfg.stowDir) return null;
  const dir = expandTarget(cfg.stowDir);
  if (!existsSync(dir)) return { dir, target: "~", packages: [] };
  const manifest = loadManifest(dir);
  const targetRaw = manifest?.stow?.target || "~";
  const target = expandTarget(targetRaw);
  const packages = listPackages(dir).map((name) => {
    const pkgDir = join(dir, name);
    let entries: string[] = [];
    try { entries = readdirSync(pkgDir); } catch { /* unreadable */ }
    const stowed = entries.length > 0 && entries.some((e) => {
      const t = join(target, e);
      try {
        if (!lstatSync(t).isSymbolicLink()) return false;
        const real = realpathSync(t);
        return real === join(pkgDir, e) || real.startsWith(pkgDir + sep);
      } catch { return false; }
    });
    return { name, stowed };
  });
  return { dir, target: targetRaw, packages };
}

export function homeStatus(cfg: HomeConfig | null, opts: { mounts?: string[] } = {}): HomeStatus {
  const home = realHome();
  const empty: HomeStatus = {
    configured: !!cfg, home, files: [], destinations: [], stow: null,
    rsyncAvailable: rsyncAvailable(), stowAvailable: stowAvailable(),
    opendriveConfigured: !!opendriveCreds(),
  };
  if (!cfg) return empty;
  const mounts = opts.mounts ?? readMounts();
  return {
    ...empty,
    files: cfg.files.map((f) => {
      const abs = join(home, f);
      try {
        const st = statSync(abs);
        return { path: f, exists: true, dir: st.isDirectory(), size: st.isFile() ? st.size : null };
      } catch { return { path: f, exists: false, dir: false, size: null }; }
    }),
    destinations: cfg.destinations.map((d) => ({
      name: d.name, type: d.type, where: destWhere(d),
      mounted: d.type === "opendrive" ? null
        : existsSync(expandTarget(d.path as string)) ? isMountPoint(expandTarget(d.path as string), mounts) : false,
      lastBackup: cfg.history[d.name]?.backup ?? null,
      lastRestore: cfg.history[d.name]?.restore ?? null,
    })),
    stow: stowStatus(cfg),
  };
}

/** Human byte size for status output. */
export function fmtBytes(n: number): string {
  if (n < 1024) return n + " B";
  if (n < 1024 ** 2) return (n / 1024).toFixed(1) + " KB";
  if (n < 1024 ** 3) return (n / 1024 ** 2).toFixed(1) + " MB";
  return (n / 1024 ** 3).toFixed(2) + " GB";
}
