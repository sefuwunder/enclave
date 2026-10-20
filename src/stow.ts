// stow.ts — GNU Stow integration for dotfile management.
// A stow directory holds one subdirectory per package; GNU stow symlinks
// each package's files into a target tree (usually $HOME). Enclave wraps
// the two moments that matter for secrets:
//   stow:   restore the vault's values into the packages, then link them
//   unstow: unlink the packages, then seal the values back into the vault
// so plaintext secrets only ever live in the tree while it is stowed.
// Enclave never writes to the target tree itself — stow owns the links.
import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

type Env = Record<string, string | undefined>;

export function stowAvailable(env: Env = process.env): boolean {
  try {
    return spawnSync("stow", ["--version"], { encoding: "utf8", env }).status === 0;
  } catch { return false; }
}

const NOT_PACKAGES = new Set([".git", "node_modules", ".enclave", "target", "dist"]);

// Packages are the stow dir's subdirectories (dot-names and tool dirs excluded).
export function listPackages(dir: string): string[] {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return []; }
  return entries
    .filter((e) => e.isDirectory() && !e.name.startsWith(".") && !NOT_PACKAGES.has(e.name))
    .map((e) => e.name)
    .sort();
}

// "~" and "~/..." expand against the home dir; anything else is used as-is.
// The manifest stores the target verbatim (usually "~") so a committed
// manifest never leaks an absolute home path.
export function expandTarget(target: string | undefined): string {
  const raw = target && target.trim() ? target.trim() : "~";
  if (raw === "~") return homedir();
  if (raw.startsWith("~/")) return join(homedir(), raw.slice(2));
  return raw;
}

export type StowMode = "stow" | "unstow" | "restow";
export interface StowRun { args: string[]; output: string }

export function runStow(
  dir: string, target: string, packages: string[], mode: StowMode,
  opts: { adopt?: boolean; env?: Env } = {},
): StowRun {
  if (!packages.length) throw new Error("no packages given and none found in " + dir);
  const args = ["-d", dir, "-t", target];
  if (mode === "unstow") args.push("-D");
  if (mode === "restow") args.push("-R");
  if (opts.adopt) args.push("--adopt");
  args.push(...packages);
  const r = spawnSync("stow", args, { encoding: "utf8", env: opts.env ?? process.env });
  const output = ((r.stdout || "") + (r.stderr || "")).trim();
  if (r.error) {
    throw new Error("could not run GNU stow (" + r.error.message + ") — is stow installed?");
  }
  if (r.status !== 0) {
    throw new Error(`stow ${mode} failed (exit ${r.status})${output ? ": " + output : ""}`);
  }
  return { args, output };
}
