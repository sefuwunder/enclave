// UI server integration tests — real HTTP against startUiServer on an
// ephemeral port, driving the whole flow the browser would.
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync, mkdirSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { startUiServer } from "../src/server.ts";

let server: ReturnType<typeof startUiServer>;
let base: string;
let root: string;   // fixture project
let home: string;   // redirected HOME so the vault lands in tmp
const envOrig = "API_KEY=ui-test-secret-123\nPORT=3000\n";
let photo: Buffer;

async function post(path: string, body: Record<string, unknown> = {}) {
  const res = await fetch(base + path, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  });
  return { status: res.status, data: await res.json().catch(() => ({})) };
}
async function get(path: string) {
  const res = await fetch(base + path);
  return { status: res.status, text: await res.text() };
}

beforeAll(() => {
  home = mkdtempSync(join(tmpdir(), "enclave-ui-home-"));
  process.env.HOME = home;
  root = mkdtempSync(join(tmpdir(), "enclave-ui-proj-"));
  writeFileSync(join(root, ".env"), envOrig);
  // tiny EXIF jpeg (Make only)
  const tiff = Buffer.alloc(64);
  tiff.write("II", 0, "latin1"); tiff.writeUInt16LE(42, 2); tiff.writeUInt32LE(8, 4);
  tiff.writeUInt16LE(1, 8);
  tiff.writeUInt16LE(0x010f, 10); tiff.writeUInt16LE(2, 12); tiff.writeUInt32LE(6, 14); tiff.writeUInt32LE(26, 18);
  tiff.writeUInt32LE(0, 22);
  tiff.write("Canon\0", 26, "latin1");
  const app1 = Buffer.concat([Buffer.from("Exif\0\0", "latin1"), tiff]);
  const len = Buffer.alloc(2); len.writeUInt16BE(app1.length + 2, 0);
  photo = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe1]), len, app1, Buffer.from([0xff, 0xd9])]);
  writeFileSync(join(root, "photo.jpg"), photo);
  server = startUiServer(0);
  base = `http://127.0.0.1:${server.port}`;
});
afterAll(() => {
  server.stop(true);
  rmSync(root, { recursive: true, force: true });
  rmSync(home, { recursive: true, force: true });
});

describe("enclave UI server", () => {
  test("static assets serve", async () => {
    const idx = await get("/");
    expect(idx.status).toBe(200);
    expect(idx.text).toContain("Enclave");
    expect((await get("/styles.css")).status).toBe(200);
    expect((await get("/app.js")).status).toBe(200);
  });

  test("project + scan without unlock", async () => {
    const p = await post("/api/project", { dir: root });
    expect(p.status).toBe(200);
    expect(p.data.locked).toBe(true);
    const s = await post("/api/scan");
    const kinds = s.data.findings.map((f: { kind: string }) => f.kind);
    expect(kinds).toContain("env");
    expect(kinds).toContain("blob:photo-exif");
    expect(JSON.stringify(s.data)).not.toContain("ui-test-secret-123");
  });

  test("seal is refused while locked", async () => {
    expect((await post("/api/seal")).status).toBe(401);
    expect((await post("/api/reveal", { name: "API_KEY" })).status).toBe(401);
  });

  test("unlock with wrong-then-right passphrase flow", async () => {
    const u = await post("/api/unlock", { passphrase: "ui-pass-1" });
    expect(u.status).toBe(200);
    expect(u.data.vaultIsNew).toBe(true);
    expect(u.data.locked).toBe(false);
  });

  test("seal via API encrypts and masks state", async () => {
    const r = await post("/api/seal");
    expect(r.status).toBe(200);
    expect(r.sealed ?? r.data.sealed).toBeGreaterThanOrEqual(2);
    const st = await get("/api/state").then((x) => JSON.parse(x.text));
    expect(st.entries.length).toBeGreaterThanOrEqual(2);
    expect(JSON.stringify(st)).not.toContain("ui-test-secret-123");
    expect(existsSync(join(home, ".enclave"))).toBe(true);
    expect(readFileSync(join(root, ".env"), "utf8")).toContain("enclave:API_KEY");
    expect((await post("/api/verify")).data.ok).toBe(true);
  });

  test("reveal, inject, run, extract", async () => {
    const rev = await post("/api/reveal", { name: "API_KEY" });
    expect(rev.data.value).toBe("ui-test-secret-123");
    const inj = await post("/api/inject");
    expect(inj.data.count).toBeGreaterThanOrEqual(1);
    expect(readFileSync(join(root, ".env.local"), "utf8")).toContain("API_KEY='ui-test-secret-123'");

    const res = await fetch(base + "/api/run", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ cmd: 'test -n "$API_KEY" && echo ENV_OK' }),
    });
    const sse = await res.text();
    expect(sse).toContain("ENV_OK");
    expect(sse).toContain('"type":"exit"');

    const ext = await fetch(base + "/api/extract?name=PHOTO_PHOTO_EXIF");
    expect(ext.status).toBe(200);
    const bytes = Buffer.from(await ext.arrayBuffer());
    expect(bytes.equals(photo)).toBe(true);
  });

  test("delete + lock + restore", async () => {
    const entries0 = (await get("/api/state").then((x) => JSON.parse(x.text))).entries.length;
    const del = await post("/api/delete", { name: "PHOTO_PHOTO_EXIF" });
    expect(del.data.state.entries.length).toBe(entries0 - 1);
    await post("/api/lock");
    expect((await post("/api/reveal", { name: "API_KEY" })).status).toBe(401);
    // wrong passphrase against the real vault now fails
    expect((await post("/api/unlock", { passphrase: "nope" })).status).toBe(401);
    expect((await post("/api/unlock", { passphrase: "ui-pass-1" })).status).toBe(200);
    const rst = await post("/api/restore");
    expect(rst.data.restored).toBeGreaterThanOrEqual(1);
    expect(readFileSync(join(root, ".env"), "utf8")).toBe(envOrig);
  });
});

describe("enclave UI stow endpoints", () => {
  const bashrc = "export API_TOKEN=abc123def456ghi\n";
  let sroot: string, starget: string, sbin: string, slog: string;
  const savedPath = process.env.PATH;

  beforeAll(() => {
    sbin = mkdtempSync(join(tmpdir(), "enclave-ui-stow-bin-"));
    slog = join(sbin, "calls.log");
    writeFileSync(join(sbin, "stow"), "#!/bin/sh\necho \"$@\" >> \"" + slog + "\"\nexit 0\n");
    chmodSync(join(sbin, "stow"), 0o755);
    process.env.PATH = sbin + ":" + (savedPath || "");
    sroot = mkdtempSync(join(tmpdir(), "enclave-ui-stow-"));
    starget = mkdtempSync(join(tmpdir(), "enclave-ui-stow-target-"));
    mkdirSync(join(sroot, "shell"));
    writeFileSync(join(sroot, "shell", ".bashrc"), bashrc);
  });
  afterAll(async () => {
    process.env.PATH = savedPath;
    await post("/api/project", { dir: root }); // hand the session back
    rmSync(sroot, { recursive: true, force: true });
    rmSync(starget, { recursive: true, force: true });
    rmSync(sbin, { recursive: true, force: true });
  });

  test("state reports stow fields; stow + unstow round-trip via API", async () => {
    const p = await post("/api/project", { dir: sroot });
    expect(p.data.stow).toBeNull();
    expect(p.data.stowAvailable).toBe(true);
    expect((await post("/api/unlock", { passphrase: "ui-stow-pass" })).status).toBe(200);
    expect((await post("/api/seal")).status).toBe(200);
    expect(readFileSync(join(sroot, "shell", ".bashrc"), "utf8")).toContain("enclave:API_TOKEN");

    const st = await post("/api/stow", { target: starget });
    expect(st.status).toBe(200);
    expect(st.data.packages).toEqual(["shell"]);
    expect(st.data.restored).toBe(1);
    expect(readFileSync(join(sroot, "shell", ".bashrc"), "utf8")).toBe(bashrc);
    expect(readFileSync(slog, "utf8")).toContain(`-d ${sroot} -t ${starget} shell`);
    expect(st.data.state.stow.target).toBe(starget);

    const un = await post("/api/unstow");
    expect(un.status).toBe(200);
    expect(un.data.sealed).toBe(1);
    expect(readFileSync(join(sroot, "shell", ".bashrc"), "utf8")).toContain("enclave:API_TOKEN");
    expect(readFileSync(slog, "utf8")).toContain("-D shell");
  });
});

describe("enclave UI home manager", () => {
  async function getHome() {
    const res = await fetch(base + "/api/home/state");
    return { status: res.status, data: await res.json() };
  }

  test("config → selection → destination → backup pill → restore", async () => {
    // fixture home files (HOME is the ui tmp home from beforeAll)
    mkdirSync(join(home, "Documents"), { recursive: true });
    mkdirSync(join(home, "usbdrive"), { recursive: true });
    writeFileSync(join(home, "Documents", "notes.txt"), "home notes\n");

    const s0 = await getHome();
    expect(s0.data.configured).toBe(false);
    expect(s0.data.rsyncAvailable).toBe(true);

    const cfg = await post("/api/home/config", {});
    expect(cfg.data.configured).toBe(true);

    const bad = await post("/api/home/add", { path: "/etc/passwd" });
    expect(bad.status).toBe(400);
    const add = await post("/api/home/add", { path: "Documents/notes.txt" });
    expect(add.data.files).toEqual([{ path: "Documents/notes.txt", exists: true, dir: false, size: 11 }]);

    const dest = await post("/api/home/dest/add", { name: "usb", type: "path", path: join(home, "usbdrive") });
    expect(dest.data.destinations.length).toBe(1);
    expect(dest.data.destinations[0].lastBackup).toBeNull();
    expect(dest.data.destinations[0].where).toBe(join(home, "usbdrive"));

    const bk = await post("/api/home/backup", { dest: "usb" });
    expect(bk.status).toBe(200);
    expect(bk.data.results[0].rec.ok).toBe(true);
    // the pill data: a recorded backup with counts, on the destination
    const pill = bk.data.status.destinations[0].lastBackup;
    expect(pill.files).toBe(1);
    expect(typeof pill.at).toBe("string");
    expect(readFileSync(join(home, "usbdrive", "enclave-home", "Documents", "notes.txt"), "utf8")).toBe("home notes\n");

    rmSync(join(home, "Documents", "notes.txt"));
    const rs = await post("/api/home/restore", { dest: "usb" });
    expect(rs.status).toBe(200);
    expect(rs.data.rec.ok).toBe(true);
    expect(readFileSync(join(home, "Documents", "notes.txt"), "utf8")).toBe("home notes\n");
    expect(rs.data.status.destinations[0].lastRestore.ok).toBe(true);
  });

  test("opendrive credentials save without ever being echoed", async () => {
    const r = await post("/api/home/creds", { username: "od-person@example.com", password: "od-secret-pw" });
    expect(r.status).toBe(200);
    expect(r.data.opendriveConfigured).toBe(true);
    expect(JSON.stringify(r.data)).not.toContain("od-secret-pw");
    const s = await getHome();
    expect(JSON.stringify(s.data)).not.toContain("od-secret-pw");
  });
});
