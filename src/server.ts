// server.ts — the enclave UI server (127.0.0.1 only).
// One in-memory session: a working directory plus, once unlocked, the
// decrypted vault and its passphrase (memory only — Lock wipes both;
// nothing session-shaped is ever written to disk). Scan/verify are
// read-only and work locked; everything that touches the vault or the
// tree's contents requires an unlocked session.
import { existsSync, readdirSync, statSync } from "node:fs";
import { join, resolve, basename, dirname } from "node:path";
import { homedir } from "node:os";
import { scanTree, mask } from "./scan.ts";
import { loadVault, saveVault, vaultExists, emptyVault, inspectVaultFile, type VaultData, type VaultAuth } from "./vault.ts";
import { pgpAvailable, listAllKeys, generateKey, loadConfig, saveConfig } from "./pgp.ts";
import {
  projectOf, defaultVaultPath, loadManifest, sealTree, verifyTree,
  restoreTree, envEntries, injectEnvFile, extractBlobBytes,
} from "./core.ts";

interface Session {
  dir: string;
  vault: VaultData | null;
  auth: VaultAuth | null;   // passphrase, or PGP recipient+keyring (+key passphrase)
  vaultIsNew: boolean;
}
const session: Session = { dir: process.cwd(), vault: null, auth: null, vaultIsNew: false };
let runningProc: ReturnType<typeof Bun.spawn> | null = null;

function vaultPath(): string { return defaultVaultPath(session.dir); }

function publicEntry(e: VaultData["entries"][number]) {
  return {
    name: e.name, kind: e.kind, file: e.file, sealedAt: e.sealedAt,
    masked: e.blob !== undefined ? null : mask(e.value),
    blob: e.blob !== undefined,
    size: e.size ?? null, sha256: e.sha256 ?? null, meta: e.meta ?? null,
  };
}

function stateJson() {
  const manifest = loadManifest(session.dir);
  const vp = vaultPath();
  let scheme: string = session.auth?.recipient ? "pgp" : "passphrase";
  let pgpRecipient: string | null = session.auth?.recipient ?? null;
  if (vaultExists(vp)) {
    const info = inspectVaultFile(vp);
    scheme = info.scheme;
    pgpRecipient = info.recipient ?? null;
  }
  return {
    locked: session.vault === null,
    dir: session.dir,
    project: projectOf(session.dir),
    vaultPath: vp,
    vaultExists: vaultExists(vp),
    vaultIsNew: session.vaultIsNew,
    vaultScheme: scheme,
    pgpRecipient,
    manifest: manifest ? { entries: manifest.entries } : null,
    entries: session.vault ? session.vault.entries.map(publicEntry) : [],
  };
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status, headers: { "content-type": "application/json" },
  });
}
function err(msg: string, status = 400): Response { return json({ error: msg }, status); }

async function body(req: Request): Promise<Record<string, unknown>> {
  try {
    const t = await req.text();
    return t ? (JSON.parse(t) as Record<string, unknown>) : {};
  } catch { return {}; }
}

function requireUnlocked(): Response | null {
  if (!session.vault || !session.auth) return err("vault is locked", 401);
  return null;
}

function persistVault(): void {
  if (session.vault && session.auth) {
    saveVault(vaultPath(), session.vault, session.auth);
    session.vaultIsNew = false;
  }
}

const PUBLIC_DIR = join(dirname(new URL(import.meta.url).pathname), "..", "public");
const MIME: Record<string, string> = {
  ".html": "text/html", ".css": "text/css", ".js": "text/javascript", ".svg": "image/svg+xml",
};

async function serveStatic(pathname: string): Promise<Response> {
  const rel = pathname === "/" ? "index.html" : pathname.slice(1);
  if (rel.includes("..")) return err("not found", 404);
  const file = Bun.file(join(PUBLIC_DIR, rel));
  if (!(await file.exists())) return err("not found", 404);
  const ext = rel.slice(rel.lastIndexOf("."));
  return new Response(file, { headers: { "content-type": MIME[ext] || "application/octet-stream" } });
}

export function startUiServer(port: number) {
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port,
    idleTimeout: 120,
    async fetch(req) {
      const url = new URL(req.url);
      const p = url.pathname;
      try {
        if (!p.startsWith("/api/")) return serveStatic(p);

        if (p === "/api/state" && req.method === "GET") return json(stateJson());

        if (p === "/api/project" && req.method === "POST") {
          const b = await body(req);
          const dir = resolve(String(b.dir || ""));
          if (!existsSync(dir) || !statSync(dir).isDirectory()) return err(`not a directory: ${dir}`);
          if (dir !== session.dir) { session.vault = null; session.auth = null; session.vaultIsNew = false; }
          session.dir = dir;
          return json(stateJson());
        }

        if (p === "/api/browse" && req.method === "GET") {
          const start = resolve(url.searchParams.get("path") || homedir());
          if (!existsSync(start)) return err(`no such path: ${start}`);
          const dirs = readdirSync(start, { withFileTypes: true })
            .filter((e) => e.isDirectory() && !["node_modules", ".git"].includes(e.name))
            .map((e) => e.name).sort();
          return json({ path: start, parent: dirname(start), dirs });
        }

        if (p === "/api/scan" && req.method === "POST") {
          const findings = scanTree(session.dir).map((f) => ({
            file: f.file, line: f.line, kind: f.kind, keyName: f.keyName,
            masked: f.blob ? null : mask(f.value),
            blob: !!f.blob, size: f.blob ? f.offsetEnd : null, meta: f.meta ?? null,
          }));
          return json({ findings });
        }

        if (p === "/api/verify" && req.method === "POST") {
          const r = verifyTree(session.dir);
          return json({
            ok: r.ok, drift: r.drift,
            findings: r.findings.map((f) => ({ file: f.file, line: f.line, kind: f.kind, keyName: f.keyName })),
          });
        }

        if (p === "/api/unlock" && req.method === "POST") {
          const b = await body(req);
          const pass = String(b.passphrase || "");
          const vp = vaultPath();
          if (vaultExists(vp)) {
            const info = inspectVaultFile(vp);
            const auth: VaultAuth = info.scheme === "pgp"
              ? { passphrase: pass === "" ? undefined : pass, recipient: info.recipient, keyring: info.keyring }
              : { passphrase: pass };
            if (info.scheme === "passphrase" && !pass) return err("empty passphrase");
            try { session.vault = loadVault(vp, auth); }
            catch (e) { return err(info.scheme === "pgp" ? "could not decrypt with that key/passphrase" : "wrong passphrase (or vault is corrupt)", 401); }
            session.auth = auth;
            session.vaultIsNew = false;
          } else if (b.scheme === "pgp") {
            const recipient = String(b.recipient || "");
            const keyring = b.keyring === "system" ? "system" : "dedicated";
            if (!recipient) return err("choose a PGP recipient");
            session.vault = emptyVault(projectOf(session.dir));
            session.auth = { recipient, keyring };
            session.vaultIsNew = true;
          } else {
            if (!pass) return err("empty passphrase");
            session.vault = emptyVault(projectOf(session.dir));
            session.auth = { passphrase: pass };
            session.vaultIsNew = true;
          }
          return json(stateJson());
        }

        if (p === "/api/lock" && req.method === "POST") {
          session.vault = null; session.auth = null; session.vaultIsNew = false;
          return json(stateJson());
        }

        if (p === "/api/pgp/keys" && req.method === "GET") {
          const cfg = loadConfig();
          return json({
            available: pgpAvailable(),
            keys: pgpAvailable() ? listAllKeys() : [],
            defaultRecipient: cfg.pgpRecipient ?? null,
          });
        }

        if (p === "/api/pgp/init" && req.method === "POST") {
          if (!pgpAvailable()) return err("gpg is not available on this system");
          const b = await body(req);
          const key = generateKey({
            name: String(b.name || "Enclave Vault"),
            email: String(b.email || "enclave@localhost"),
            passphrase: b.noProtection === true ? undefined : String(b.passphrase || ""),
          });
          saveConfig({ pgpRecipient: key.fingerprint, pgpKeyring: "dedicated" });
          return json({ key });
        }

        if (p === "/api/seal" && req.method === "POST") {
          const locked = requireUnlocked(); if (locked) return locked;
          const r = sealTree(session.dir, session.vault!);
          persistVault();
          return json({ sealed: r.sealed, state: stateJson() });
        }

        if (p === "/api/restore" && req.method === "POST") {
          const locked = requireUnlocked(); if (locked) return locked;
          const r = restoreTree(session.dir, session.vault!);
          return json({ ...r, state: stateJson() });
        }

        if (p === "/api/inject" && req.method === "POST") {
          const locked = requireUnlocked(); if (locked) return locked;
          const b = await body(req);
          const out = b.out ? resolve(String(b.out)) : join(session.dir, ".env.local");
          const count = injectEnvFile(session.vault!, out);
          return json({ count, out });
        }

        if (p === "/api/reveal" && req.method === "POST") {
          const locked = requireUnlocked(); if (locked) return locked;
          const b = await body(req);
          const e = session.vault!.entries.find((x) => x.name === String(b.name));
          if (!e) return err("no such entry", 404);
          if (e.blob !== undefined) return err("blob entry — use extract");
          return json({ name: e.name, value: e.value });
        }

        if (p === "/api/delete" && req.method === "POST") {
          const locked = requireUnlocked(); if (locked) return locked;
          const b = await body(req);
          const before = session.vault!.entries.length;
          session.vault!.entries = session.vault!.entries.filter((x) => x.name !== String(b.name));
          if (session.vault!.entries.length === before) return err("no such entry", 404);
          persistVault();
          return json({ state: stateJson() });
        }

        if (p === "/api/extract" && req.method === "GET") {
          const locked = requireUnlocked(); if (locked) return locked;
          const name = url.searchParams.get("name") || "";
          const { entry, bytes } = extractBlobBytes(session.vault!, name);
          return new Response(bytes, {
            headers: {
              "content-type": "application/octet-stream",
              "content-disposition": `attachment; filename="${basename(entry.file)}"`,
            },
          });
        }

        if (p === "/api/run" && req.method === "POST") {
          const locked = requireUnlocked(); if (locked) return locked;
          const b = await body(req);
          const cmd = String(b.cmd || "").trim();
          if (!cmd) return err("empty command");
          if (runningProc) return err("a command is already running", 409);
          const env: Record<string, string> = { ...process.env } as Record<string, string>;
          for (const e of envEntries(session.vault!)) env[e.name] = e.value;
          const proc = Bun.spawn(["sh", "-c", cmd], {
            cwd: session.dir, env,
            stdout: "pipe", stderr: "pipe",
          });
          runningProc = proc;
          const stream = new ReadableStream({
            async start(controller) {
              const enc = new TextEncoder();
              const send = (type: string, text: string) =>
                controller.enqueue(enc.encode(`data: ${JSON.stringify({ type, text })}\n\n`));
              const pump = async (s: ReadableStream<Uint8Array>, type: string) => {
                const reader = s.getReader();
                const dec = new TextDecoder();
                for (;;) {
                  const { done, value } = await reader.read();
                  if (done) break;
                  send(type, dec.decode(value, { stream: true }));
                }
              };
              await Promise.all([pump(proc.stdout as ReadableStream<Uint8Array>, "out"), pump(proc.stderr as ReadableStream<Uint8Array>, "err")]);
              const code = await proc.exited;
              runningProc = null;
              send("exit", String(code));
              controller.close();
            },
          });
          return new Response(stream, { headers: { "content-type": "text/event-stream", "cache-control": "no-cache" } });
        }

        if (p === "/api/run/stop" && req.method === "POST") {
          if (runningProc) { runningProc.kill(); runningProc = null; }
          return json({ stopped: true });
        }

        return err("unknown endpoint", 404);
      } catch (e) {
        return err(e instanceof Error ? e.message : String(e), 500);
      }
    },
  });
  return server;
}
