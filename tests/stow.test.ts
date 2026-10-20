// stow tests — GNU Stow integration. The real stow binary is replaced by
// a stub shell script on PATH that logs its argv, so the suite is hermetic
// and verifies the exact arguments enclave passes.
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync, writeFileSync, readFileSync, mkdirSync, rmSync, existsSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { tmpdir, homedir } from "node:os";
import { listPackages, runStow, stowAvailable, expandTarget } from "../src/stow.ts";
import { loadManifest } from "../src/core.ts";

let stubDir: string;
let logPath: string;
let stubEnv: Record<string, string | undefined>;

function stubLog(): string {
  return existsSync(logPath) ? readFileSync(logPath, "utf8") : "";
}

beforeAll(() => {
  stubDir = mkdtempSync(join(tmpdir(), "enclave-stow-bin-"));
  logPath = join(stubDir, "calls.log");
  const script = [
    "#!/bin/sh",
    `echo "$@" >> "${logPath}"`,
    'if [ "$STOW_STUB_FAIL" = "1" ]; then echo "stub: conflicting target file" >&2; exit 2; fi',
    "exit 0",
    "",
  ].join("\n");
  writeFileSync(join(stubDir, "stow"), script);
  chmodSync(join(stubDir, "stow"), 0o755);
  stubEnv = { ...process.env, PATH: stubDir + ":" + (process.env.PATH || "") };
});
afterAll(() => { rmSync(stubDir, { recursive: true, force: true }); });

describe("stow helpers", () => {
  test("availability via PATH", () => {
    expect(stowAvailable(stubEnv)).toBe(true);
    expect(stowAvailable({ PATH: "/nonexistent-dir" })).toBe(false);
  });
  test("listPackages returns package dirs only", () => {
    const dir = mkdtempSync(join(tmpdir(), "enclave-pkgs-"));
    mkdirSync(join(dir, "shell"));
    mkdirSync(join(dir, "git"));
    mkdirSync(join(dir, ".git"));
    mkdirSync(join(dir, ".hidden"));
    mkdirSync(join(dir, "node_modules"));
    writeFileSync(join(dir, "README.md"), "x");
    expect(listPackages(dir)).toEqual(["git", "shell"]);
    rmSync(dir, { recursive: true, force: true });
  });
  test("expandTarget", () => {
    expect(expandTarget(undefined)).toBe(homedir());
    expect(expandTarget("~")).toBe(homedir());
    expect(expandTarget("~/dot")).toBe(join(homedir(), "dot"));
    expect(expandTarget("/abs/target")).toBe("/abs/target");
  });
  test("runStow builds the right argv per mode", () => {
    writeFileSync(logPath, "");
    const env = stubEnv;
    const a = runStow("/stowdir", "/target", ["shell", "git"], "stow", { env });
    expect(a.args).toEqual(["-d", "/stowdir", "-t", "/target", "shell", "git"]);
    runStow("/stowdir", "/target", ["shell"], "unstow", { env });
    runStow("/stowdir", "/target", ["shell"], "restow", { env });
    runStow("/stowdir", "/target", ["shell"], "stow", { env, adopt: true });
    const lines = stubLog().trim().split("\n");
    expect(lines[0]).toBe("-d /stowdir -t /target shell git");
    expect(lines[1]).toBe("-d /stowdir -t /target -D shell");
    expect(lines[2]).toBe("-d /stowdir -t /target -R shell");
    expect(lines[3]).toBe("-d /stowdir -t /target --adopt shell");
  });
  test("runStow surfaces stow's failure", () => {
    const env = { ...stubEnv, STOW_STUB_FAIL: "1" };
    expect(() => runStow("/d", "/t", ["shell"], "stow", { env })).toThrow(/conflicting target file/);
  });
});

describe("CLI stow flow: seal --stow -> stow -> unstow", () => {
  const bashrc = "export API_TOKEN=abc123def456ghi\nalias ll='ls -la'\n";
  let root: string, home: string, target: string;

  async function runCli(args: string[]) {
    const env = {
      ...process.env,
      ENCLAVE_PASSPHRASE: "stow-pass-1",
      HOME: home,
      PATH: stubDir + ":" + (process.env.PATH || ""),
    };
    const p = Bun.spawn(["bun", "run", join(import.meta.dir, "..", "src", "cli.ts"), ...args],
      { env, stdout: "pipe", stderr: "pipe" });
    const code = await p.exited;
    return { code, out: await new Response(p.stdout).text(), err: await new Response(p.stderr).text() };
  }

  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), "enclave-stow-proj-"));
    home = mkdtempSync(join(tmpdir(), "enclave-stow-home-"));
    target = mkdtempSync(join(tmpdir(), "enclave-stow-target-"));
    mkdirSync(join(root, "shell"));
    writeFileSync(join(root, "shell", ".bashrc"), bashrc);
  });
  afterAll(() => {
    rmSync(root, { recursive: true, force: true });
    rmSync(home, { recursive: true, force: true });
    rmSync(target, { recursive: true, force: true });
  });

  test("the full dotfile lifecycle", async () => {
    writeFileSync(logPath, "");
    // 1. seal, recording the tree as a stow directory with this target
    const seal = await runCli(["seal", root, "--apply", "--stow", "--target", target]);
    expect(seal.code).toBe(0);
    expect(readFileSync(join(root, "shell", ".bashrc"), "utf8")).toContain("enclave:API_TOKEN");
    let manifest = loadManifest(root);
    expect(manifest?.stow?.target).toBe(target);
    expect(manifest?.entries.length).toBe(1);

    // 2. stow: values restored into the package, stub stow links them
    const stow = await runCli(["stow", root]);
    expect(stow.code).toBe(0);
    expect(readFileSync(join(root, "shell", ".bashrc"), "utf8")).toBe(bashrc);
    expect(stubLog()).toContain(`-d ${root} -t ${target} shell`);
    manifest = loadManifest(root);
    expect(manifest?.entries.length).toBe(0);
    expect(manifest?.stow?.target).toBe(target); // config survives the restore

    // 3. unstow: stub gets -D, secrets are sealed back into the vault
    const unstow = await runCli(["unstow", root]);
    expect(unstow.code).toBe(0);
    expect(stubLog()).toContain(`-d ${root} -t ${target} -D shell`);
    const sealed = readFileSync(join(root, "shell", ".bashrc"), "utf8");
    expect(sealed).toContain("enclave:API_TOKEN");
    expect(sealed).not.toContain("abc123def456ghi");
    manifest = loadManifest(root);
    expect(manifest?.entries.length).toBe(1);
    expect(manifest?.stow?.target).toBe(target);

    // 4. and the tree verifies clean afterwards
    const verify = await runCli(["verify", root]);
    expect(verify.code).toBe(0);
  });

  test("named packages are passed through", async () => {
    writeFileSync(logPath, "");
    const r = await runCli(["stow", root, "shell"]);
    expect(r.code).toBe(0);
    // (the log also holds "--version" availability probes)
    expect(stubLog().trim().split("\n")).toContain(`-d ${root} -t ${target} shell`);
    // leave the tree sealed again for cleanliness
    const u = await runCli(["unstow", root, "shell"]);
    expect(u.code).toBe(0);
  });
});
