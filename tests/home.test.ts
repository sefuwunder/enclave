// home manager tests — config/selection/destination logic, real-rsync
// backup/restore against temp dirs, the mount guard, an in-memory
// OpenDrive stub server for the API destination, and the CLI flow.
// HOME is redirected per-suite so config/credentials land in tmp.
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync, writeFileSync, readFileSync, mkdirSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import {
  emptyHomeConfig, addFiles, removeFile, addDest, removeDest,
  normalizeSelection, isMountPoint, backupTo, restoreFrom, backupAll,
  homeStatus, loadHomeConfig, fmtBytes, type HomeConfig,
} from "../src/home.ts";

const savedHome = process.env.HOME;
const savedOdUser = process.env.OPENDRIVE_USERNAME;
const savedOdPass = process.env.OPENDRIVE_PASSWORD;

function freshHome(): string {
  const h = mkdtempSync(join(tmpdir(), "enclave-home-"));
  process.env.HOME = h;
  return h;
}

describe("home config logic", () => {
  test("normalizeSelection", () => {
    process.env.HOME = "/home/tester";
    expect(normalizeSelection("Documents/x.txt")).toBe("Documents/x.txt");
    expect(normalizeSelection("~/Documents/x.txt")).toBe("Documents/x.txt");
    expect(normalizeSelection("/home/tester/Documents/x.txt")).toBe("Documents/x.txt");
    expect(normalizeSelection("/etc/passwd")).toBeNull();
    expect(normalizeSelection("../escape")).toBeNull();
    expect(normalizeSelection("a/../b")).toBe("b");
    expect(normalizeSelection("~")).toBeNull();
    expect(normalizeSelection("")).toBeNull();
  });
  test("add/remove files and destinations", () => {
    const cfg = emptyHomeConfig();
    const r = addFiles(cfg, ["Documents", "Documents", "/etc/passwd", "notes.txt"]);
    expect(r.added).toEqual(["Documents", "notes.txt"]);
    expect(r.rejected).toEqual(["/etc/passwd"]);
    expect(removeFile(cfg, "notes.txt")).toBe(true);
    expect(removeFile(cfg, "notes.txt")).toBe(false);
    addDest(cfg, { name: "usb", type: "path", path: "/media/x" });
    expect(() => addDest(cfg, { name: "usb", type: "path", path: "/y" })).toThrow(/already exists/);
    expect(() => addDest(cfg, { name: "bad name!", type: "path", path: "/y" })).toThrow(/bad destination name/);
    expect(() => addDest(cfg, { name: "np", type: "path" })).toThrow(/needs --path/);
    expect(() => addDest(cfg, { name: "wd", type: "webdav" })).toThrow(/mount point/);
    cfg.history["usb"] = { backup: { at: "2026-01-01T00:00:00Z", files: 1, bytes: 2, ok: true } };
    expect(removeDest(cfg, "usb")).toBe(true);
    expect(cfg.history["usb"]).toBeUndefined();
  });
  test("isMountPoint: listed mount or device change", () => {
    const dir = mkdtempSync(join(tmpdir(), "enclave-mp-"));
    expect(isMountPoint(dir, [dir])).toBe(true);          // listed
    expect(isMountPoint(dir, [])).toBe(false);            // plain dir, same device as /tmp
    expect(isMountPoint("/dev/shm", [])).toBe(true);      // tmpfs: device differs from /
    rmSync(dir, { recursive: true, force: true });
  });
  test("fmtBytes", () => {
    expect(fmtBytes(10)).toBe("10 B");
    expect(fmtBytes(2048)).toBe("2.0 KB");
    expect(fmtBytes(3 * 1024 * 1024)).toBe("3.0 MB");
  });
});

describe("rsync backup/restore (real rsync, temp dirs)", () => {
  let home: string, cfg: HomeConfig;
  beforeAll(() => {
    home = freshHome();
    mkdirSync(join(home, "Documents"), { recursive: true });
    mkdirSync(join(home, ".config", "app"), { recursive: true });
    mkdirSync(join(home, "usb"), { recursive: true });
    writeFileSync(join(home, "Documents", "notes.txt"), "hello home\n");
    writeFileSync(join(home, ".config", "app", "settings.json"), "{\"a\":1}\n");
    cfg = emptyHomeConfig();
    addFiles(cfg, ["Documents", ".config/app/settings.json", "missing.txt"]);
    addDest(cfg, { name: "usb", type: "path", path: join(home, "usb") });
  });
  afterAll(() => { rmSync(home, { recursive: true, force: true }); });

  test("backup mirrors the selection and records history (the pill data)", async () => {
    const rec = await backupTo(cfg, "usb");
    expect(rec.ok).toBe(true);
    expect(rec.files).toBe(2);
    expect(rec.note).toContain("missing.txt");
    expect(readFileSync(join(home, "usb", "enclave-home", "Documents", "notes.txt"), "utf8")).toBe("hello home\n");
    expect(existsSync(join(home, "usb", "enclave-home", ".config", "app", "settings.json"))).toBe(true);
    const onDisk = loadHomeConfig();
    expect(onDisk?.history["usb"]?.backup?.files).toBe(2);
    const st = homeStatus(onDisk);
    const d = st.destinations.find((x) => x.name === "usb");
    expect(d?.lastBackup?.files).toBe(2);
    expect(d?.where).toBe(join(home, "usb"));
    expect(st.files.find((f) => f.path === "missing.txt")?.exists).toBe(false);
  });

  test("no --delete by default; --delete prunes", async () => {
    const stale = join(home, "usb", "enclave-home", "stale.txt");
    writeFileSync(stale, "old");
    await backupTo(cfg, "usb");
    expect(existsSync(stale)).toBe(true);
    await backupTo(cfg, "usb", { deleteExtra: true });
    expect(existsSync(stale)).toBe(false);
  });

  test("restore brings a deleted file back", async () => {
    rmSync(join(home, "Documents", "notes.txt"));
    const rec = await restoreFrom(cfg, "usb");
    expect(rec.ok).toBe(true);
    expect(rec.files).toBeGreaterThanOrEqual(1);
    expect(readFileSync(join(home, "Documents", "notes.txt"), "utf8")).toBe("hello home\n");
    expect(loadHomeConfig()?.history["usb"]?.restore?.ok).toBe(true);
  });

  test("mount guard refuses an unmounted webdav destination and records the failure", async () => {
    const cfg2 = emptyHomeConfig();
    addFiles(cfg2, ["Documents"]);
    addDest(cfg2, { name: "dav", type: "webdav", path: join(home, "usb"), url: "https://dav.example.com/home" });
    await expect(backupTo(cfg2, "dav")).rejects.toThrow(/not a mount point/);
    const hist = loadHomeConfig()?.history["dav"]?.backup;
    // note: cfg2's history was saved over cfg's file — both live in the same HOME
    expect(hist?.ok).toBe(false);
    // …but with the mount faked via the mounts list, the same destination works
    const rec = await backupTo(cfg2, "dav", { mounts: [join(home, "usb")] });
    expect(rec.ok).toBe(true);
  });

  test("backupAll collects per-destination results", async () => {
    const results = await backupAll(cfg);
    expect(results.length).toBe(1);
    expect(results[0].rec?.ok).toBe(true);
  });
});

/* ------------------------- OpenDrive stub server ------------------------- */

interface StubFile { id: string; name: string; dirId: string; bytes: Buffer; mtime: number }
class OdStub {
  folders = new Map<string, { id: string; name: string; parent: string }>();
  files = new Map<string, StubFile>();
  temps = new Map<string, { fileId: string; chunks: Map<number, Buffer> }>();
  seq = 0;
  constructor() { this.folders.set("0", { id: "0", name: "", parent: "" }); }
  list(fid: string) {
    const Folders = [...this.folders.values()].filter((f) => f.parent === fid && f.id !== "0")
      .map((f) => ({ Name: f.name, FolderID: f.id }));
    const Files = [...this.files.values()].filter((f) => f.dirId === fid).map((f) => ({
      Name: f.name, FileId: f.id, Size: f.bytes.length,
      DateModified: Math.floor(f.mtime / 1000),
      FileHash: createHash("sha256").update(f.bytes).digest("hex"),
    }));
    return { Folders, Files };
  }
  async handle(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const p = url.pathname;
    const json = (o: unknown) => new Response(JSON.stringify(o), { headers: { "content-type": "application/json" } });
    if (p === "/session/login.json") {
      const b = await req.json() as { username: string; passwd: string };
      if (b.username !== "od-user" || b.passwd !== "od-pass") return json({ error: { code: 401, message: "bad login" } });
      return json({ SessionID: "S1" });
    }
    if (p === "/folder.json") {
      const b = await req.json() as { folder_name: string; folder_sub_parent: string };
      const id = "F" + ++this.seq;
      this.folders.set(id, { id, name: b.folder_name, parent: b.folder_sub_parent });
      return json({ FolderID: id });
    }
    const listM = p.match(/^\/folder\/list\.json\/S1\/(.+)$/);
    if (listM) return json(this.list(listM[1]));
    if (p === "/upload/create_file.json") {
      const b = await req.json() as { folder_id: string; file_name: string };
      const existing = [...this.files.values()].find((f) => f.dirId === b.folder_id && f.name === b.file_name);
      const id = existing ? existing.id : "FILE" + ++this.seq;
      if (!existing) this.files.set(id, { id, name: b.file_name, dirId: b.folder_id, bytes: Buffer.alloc(0), mtime: Date.now() });
      this.temps.set("T" + id, { fileId: id, chunks: new Map() });
      return json({ FileId: id, TempLocation: "T" + id, RequireHashOnly: 0 });
    }
    const chunkM = p.match(/^\/upload\/upload_file_chunk2\.json\/S1\/(.+)$/);
    if (chunkM) {
      const form = await req.formData();
      const data = form.get("file_data") as Blob;
      const buf = Buffer.from(await data.arrayBuffer());
      const temp = this.temps.get(url.searchParams.get("temp_location") || "");
      if (temp) temp.chunks.set(Number(url.searchParams.get("chunk_offset")), buf);
      return json({ TotalWritten: buf.length });
    }
    if (p === "/upload/close_file_upload.json") {
      const b = await req.json() as { file_id: string; temp_location: string; file_time: string };
      const temp = this.temps.get(b.temp_location);
      const f = this.files.get(b.file_id);
      if (temp && f) {
        const parts = [...temp.chunks.entries()].sort((a, z) => a[0] - z[0]).map(([, v]) => v);
        f.bytes = Buffer.concat(parts);
        f.mtime = Number(b.file_time) * 1000;
      }
      return json({ FileID: b.file_id });
    }
    if (p === "/file/filesettings.json") return json({});
    const dlM = p.match(/^\/download\/file\.json\/(.+)$/);
    if (dlM) {
      const f = this.files.get(dlM[1]);
      if (!f) return new Response("nope", { status: 404 });
      return new Response(f.bytes);
    }
    return new Response("unhandled " + p, { status: 500 });
  }
}

describe("OpenDrive destination (stub server)", () => {
  let home: string, server: ReturnType<typeof Bun.serve>, cfg: HomeConfig;
  const stub = new OdStub();
  beforeAll(() => {
    home = freshHome();
    process.env.OPENDRIVE_USERNAME = "od-user";
    process.env.OPENDRIVE_PASSWORD = "od-pass";
    mkdirSync(join(home, "docs"), { recursive: true });
    writeFileSync(join(home, "a.txt"), "hello-od");
    writeFileSync(join(home, "docs", "b.txt"), "second file");
    server = Bun.serve({ port: 0, fetch: (r) => stub.handle(r) });
    cfg = emptyHomeConfig();
    addFiles(cfg, ["a.txt", "docs"]);
    addDest(cfg, { name: "od", type: "opendrive", folder: "/EnclaveHome" });
  });
  afterAll(() => {
    server.stop(true);
    rmSync(home, { recursive: true, force: true });
  });

  test("backup uploads, skips the unchanged, restores the deleted", async () => {
    const apiBase = `http://127.0.0.1:${server.port}`;
    const r1 = await backupTo(cfg, "od", { apiBase });
    expect(r1.ok).toBe(true);
    expect(r1.files).toBe(2);
    const names = [...stub.files.values()].map((f) => f.name).sort();
    expect(names).toEqual(["a.txt", "b.txt"]);
    // unchanged second run: hash comparison skips both
    const r2 = await backupTo(cfg, "od", { apiBase });
    expect(r2.files).toBe(0);
    // change one file → exactly one upload
    writeFileSync(join(home, "a.txt"), "hello-od-v2");
    const r3 = await backupTo(cfg, "od", { apiBase });
    expect(r3.files).toBe(1);
    // delete a local file → restore brings it back from OpenDrive
    rmSync(join(home, "docs", "b.txt"));
    const rr = await restoreFrom(cfg, "od", { apiBase });
    expect(rr.files).toBeGreaterThanOrEqual(1);
    expect(readFileSync(join(home, "docs", "b.txt"), "utf8")).toBe("second file");
  });

  test("missing credentials are a clear error, recorded in history", async () => {
    delete process.env.OPENDRIVE_USERNAME;
    delete process.env.OPENDRIVE_PASSWORD;
    const cfg2 = emptyHomeConfig();
    addFiles(cfg2, ["a.txt"]);
    addDest(cfg2, { name: "od2", type: "opendrive" });
    await expect(backupTo(cfg2, "od2", { apiBase: `http://127.0.0.1:${server.port}` }))
      .rejects.toThrow(/credentials are not set/);
    process.env.OPENDRIVE_USERNAME = "od-user";
    process.env.OPENDRIVE_PASSWORD = "od-pass";
  });
});

describe("CLI home flow", () => {
  let home: string;
  async function runCli(args: string[]) {
    const env = { ...process.env, HOME: home, ENCLAVE_PASSPHRASE: undefined };
    delete (env as Record<string, unknown>).ENCLAVE_PASSPHRASE;
    const p = Bun.spawn(["bun", "run", join(import.meta.dir, "..", "src", "cli.ts"), ...args],
      { env, stdout: "pipe", stderr: "pipe" });
    const code = await p.exited;
    return { code, out: await new Response(p.stdout).text(), err: await new Response(p.stderr).text() };
  }
  beforeAll(() => {
    home = freshHome();
    mkdirSync(join(home, "usb"), { recursive: true });
    writeFileSync(join(home, "keep.txt"), "precious\n");
  });
  afterAll(() => { rmSync(home, { recursive: true, force: true }); });

  test("init → add → dest add → backup → status → restore", async () => {
    expect((await runCli(["home", "init"])).code).toBe(0);
    expect((await runCli(["home", "add", "keep.txt"])).code).toBe(0);
    expect((await runCli(["home", "dest", "add", "usb", "--type", "path", "--path", join(home, "usb")])).code).toBe(0);
    const b = await runCli(["home", "backup", "usb"]);
    expect(b.code).toBe(0);
    expect(existsSync(join(home, "usb", "enclave-home", "keep.txt"))).toBe(true);
    const st = await runCli(["home", "status"]);
    expect(st.out).toContain("usb");
    expect(st.out).toContain("last backup");
    rmSync(join(home, "keep.txt"));
    expect((await runCli(["home", "restore", "usb"])).code).toBe(0);
    expect(readFileSync(join(home, "keep.txt"), "utf8")).toBe("precious\n");
  });

  test("backup to an unmounted webdav destination fails loudly", async () => {
    expect((await runCli(["home", "dest", "add", "dav", "--type", "webdav", "--path", join(home, "usb"), "--url", "https://dav.example.com"])).code).toBe(0);
    const b = await runCli(["home", "backup", "dav"]);
    expect(b.code).not.toBe(0);
    expect(b.out + b.err).toContain("not a mount point");
  });
});

afterAll(() => {
  if (savedHome === undefined) delete process.env.HOME; else process.env.HOME = savedHome;
  if (savedOdUser === undefined) delete process.env.OPENDRIVE_USERNAME; else process.env.OPENDRIVE_USERNAME = savedOdUser;
  if (savedOdPass === undefined) delete process.env.OPENDRIVE_PASSWORD; else process.env.OPENDRIVE_PASSWORD = savedOdPass;
});
