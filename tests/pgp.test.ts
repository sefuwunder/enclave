// PGP scheme tests — real gpg, tmp HOME (dedicated keyring lives there).
// Skipped wholesale when gpg is unavailable on the machine running tests.
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { pgpAvailable, generateKey, listKeys, findKey, pgpEncrypt, pgpDecrypt } from "../src/pgp.ts";
import { saveVault, loadVault, inspectVaultFile, emptyVault } from "../src/vault.ts";

const hasGpg = pgpAvailable();
const d = hasGpg ? describe : describe.skip;

let home: string;
const cli = join(import.meta.dir, "..", "src", "cli.ts");

async function runCli(args: string[], env: Record<string, string> = {}, cwd?: string) {
  const p = Bun.spawn(["bun", "run", cli, ...args], {
    env: { ...process.env, HOME: home, ...env },
    stdout: "pipe", stderr: "pipe", cwd,
  });
  const code = await p.exited;
  return { code, out: await new Response(p.stdout).text(), err: await new Response(p.stderr).text() };
}

beforeAll(() => { home = mkdtempSync(join(tmpdir(), "enclave-pgp-home-")); process.env.HOME = home; });
afterAll(() => { if (home) rmSync(home, { recursive: true, force: true }); });

d("pgp keys + raw crypto", () => {
  test("generate a dedicated key (passphrase-protected)", () => {
    const key = generateKey({ name: "Enclave Test", email: "test@enclave.local", passphrase: "key-pass-123" });
    expect(key.fingerprint).toMatch(/^[0-9A-F]{40}$/);
    expect(key.hasSecret).toBe(true);
    expect(key.keyring).toBe("dedicated");
    const all = listKeys("dedicated");
    expect(all.some((k) => k.fingerprint === key.fingerprint)).toBe(true);
    expect(findKey(key.fingerprint.slice(-8))?.fingerprint).toBe(key.fingerprint);
    expect(findKey("test@enclave.local")?.fingerprint).toBe(key.fingerprint);
  });

  test("encrypt/decrypt roundtrip; wrong passphrase fails", () => {
    const key = listKeys("dedicated")[0];
    const cipher = pgpEncrypt(key.fingerprint, "dedicated", Buffer.from("hello enclave"));
    expect(cipher.subarray(0, 1)[0]).not.toBe(0x7b); // not JSON — real PGP packet
    expect(pgpDecrypt("dedicated", "key-pass-123", cipher).toString()).toBe("hello enclave");
    expect(() => pgpDecrypt("dedicated", "wrong-pass", cipher)).toThrow();
  });
});

d("pgp vault via CLI", () => {
  test("init -> seal --pgp -> list -> convert -> restore", async () => {
    const init = await runCli(["pgp", "init", "--name", "CLI Key", "--email", "cli@enclave.local"], { ENCLAVE_PASSPHRASE: "cli-key-pass" });
    expect(init.code).toBe(0);
    expect(init.out).toContain("Created dedicated enclave key");

    const root = mkdtempSync(join(tmpdir(), "enclave-pgp-proj-"));
    writeFileSync(join(root, ".env"), "API_KEY=pgp-secret-789\n");
    const seal = await runCli(["seal", root, "--apply", "--pgp"], {}, root);
    expect(seal.code).toBe(0);
    expect(seal.out).toContain("PGP →");
    const vpath = join(home, ".enclave", "config.json");
    expect(existsSync(vpath)).toBe(true);
    const vaultFile = join(home, ".enclave", (root.split("/").pop() || "") + ".vault.enc");
    const info = inspectVaultFile(vaultFile);
    expect(info.scheme).toBe("pgp");
    expect(info.keyring).toBe("dedicated");
    expect(readFileSync(join(root, ".env"), "utf8")).toContain("enclave:API_KEY");

    const list = await runCli(["list"], { ENCLAVE_PASSPHRASE: "cli-key-pass" }, root);
    expect(list.code).toBe(0);
    expect(list.out).toContain("Scheme: PGP");
    expect(list.out).toContain("API_KEY");
    expect(list.out).not.toContain("pgp-secret-789");

    // wrong key passphrase cannot open it
    const bad = await runCli(["list"], { ENCLAVE_PASSPHRASE: "nope" }, root);
    expect(bad.code).not.toBe(0);

    // convert PGP -> passphrase, then restore with the passphrase
    const conv = await runCli(["pgp", "convert", root], { ENCLAVE_PASSPHRASE: "cli-key-pass" }, root);
    // convert prompts for the NEW passphrase via getPassphrase(true) = env value (same var) — fine
    expect(conv.code).toBe(0);
    expect(inspectVaultFile(vaultFile).scheme).toBe("passphrase");
    const restore = await runCli(["restore", root], { ENCLAVE_PASSPHRASE: "cli-key-pass" }, root);
    expect(restore.code).toBe(0);
    expect(readFileSync(join(root, ".env"), "utf8")).toBe("API_KEY=pgp-secret-789\n");
    rmSync(root, { recursive: true, force: true });
  });

  test("vault file saves/loads with pgp auth directly", () => {
    const key = listKeys("dedicated")[0];
    const p = join(home, "direct.vault.enc");
    const data = emptyVault("direct");
    data.entries.push({ name: "X", value: "y", file: ".env", kind: "env", sealedAt: new Date().toISOString() });
    saveVault(p, data, { recipient: key.fingerprint, keyring: "dedicated" });
    expect(JSON.parse(readFileSync(p, "utf8")).scheme).toBe("pgp");
    const loaded = loadVault(p, { passphrase: "key-pass-123" });
    expect(loaded.entries[0].value).toBe("y");
    expect(() => loadVault(p, { passphrase: "bad" })).toThrow();
  });
});
