# enclave

A secrets enclave manager for source trees. `enclave` sweeps a project
for secrets and personal data — in text *and* in binary blobs — seals
them into an encrypted vault that lives **outside** the tree, and
leaves placeholders behind. Restore is byte-exact; `run` and `inject`
put secrets back only where they're needed, never back on disk in the
tree.

Bun + zero dependencies. The crypto is Node's built-in `scrypt` +
AES-256-GCM.

## Quick start

```sh
enclave scan                 # what would be sealed (values masked)
enclave seal                 # dry-run plan
enclave seal --apply         # seal into ~/.enclave/<project>.vault.enc
enclave verify               # CI gate: exit 1 if plaintext remains
enclave run -- bun run dev   # run with the secrets as env vars
enclave restore              # put everything back, byte-exact
```

The passphrase comes from `ENCLAVE_PASSPHRASE`, or a hidden prompt on a
TTY (asked twice when a vault is created). The vault path can be
overridden with `--vault <path>`.

## What it detects

**Text secrets**
- `.env` entries with secret-y names, long values, or high entropy
  (plain config like `PORT=3000` is left alone)
- Private-key blocks (`-----BEGIN … PRIVATE KEY-----`, whole block)
- Known token shapes: AWS key ids, GitHub tokens, Slack tokens,
  Stripe live keys, JWTs
- Secret-named assignments (`api_key = "…"`, `"db_password": "…"`)
- Bare high-entropy quoted strings

Detectors are calibrated by file kind, because code is not data. In
code files (`.ts`, `.py`, `.go`, …) only a *quoted string literal*
assigned to a secret-named key counts — an unquoted right-hand side is
a reference (`process.env.X`), an expression, or a regex literal, and
flagging those drowned real findings in false positives. Outside code
(config, shell, docs) bare values count too, since a bare word there is
the literal. Character-set constants (base64 alphabets, keyboard maps)
are never flagged, and neither are placeholder values. Known token
*shapes* (AWS/GitHub/Stripe/…) are always flagged, in every file kind —
a shape match is unambiguous. The test suite's own fixture strings are
shaped like secrets on purpose, so scanning this repo flags those and
only those.

**Personal data (PII)**
- SSNs (any text file)
- Email addresses in data files (`.csv`, `.sql`, `.json`, `.xml`, …) —
  code files are exempt, dumps are not

**Binary blobs** (whole-file findings: metadata is reported as *what*
is present — GPS, author, … — never the values)
- Photos: JPEG/PNG with EXIF GPS coordinates, camera make/model, artist
- PDFs with Author/Creator/Producer/Title metadata or XMP
- Office docs: OOXML `docProps/core.xml` creator / lastModifiedBy /
  title; legacy OLE documents
- SQLite databases (rows are opaque — assume personal)
- Archives (zip: contents are opaque)
- Key material by extension: `.pem .key .p12 .pfx .jks .der .crt …`

Skipped: `.git`, `node_modules`, build output, lockfiles, files over
25 MB. Add an `.enclaveignore` (glob lines) for tree-specific skips.
Placeholder-looking values (`your-api-key`, `changeme`, `${…}`,
`process.env.…`) are never flagged.

## How sealing works

- **Text**: the value is replaced in place with `enclave:NAME`. A
  manifest at `enclave.manifest.json` records names, files and kinds —
  never values — so it's safe to commit.
- **Blobs**: the file's bytes go into the vault (sha256 recorded) and
  the path is left with a small text tombstone:
  `enclave-blob:NAME` + sha256 + size. Re-sealing a changed blob
  updates the vault entry; restore refuses if tombstone and vault
  disagree on the hash.
- The vault itself is one encrypted JSON file:
  scrypt (N=2¹⁵, r=8, p=1) derives the key; AES-256-GCM encrypts and
  authenticates. A wrong passphrase or a single flipped bit fails
  loudly. Vault files are written mode 600, as are injected env files.

## Commands

| command | does |
| --- | --- |
| `enclave scan [dir]` | list findings, values masked |
| `enclave seal [dir] [--apply]` | dry-run by default; `--apply` seals |
| `enclave verify [dir]` | exit 1 on plaintext secrets or placeholder drift |
| `enclave list` | vault contents (masked; blobs show size + what was found) |
| `enclave show <name> [--reveal]` | one text entry |
| `enclave extract <name> [--out f]` | write a blob out, sha256-checked |
| `enclave inject [dir] [--out f]` | write env file (default `.env.local`, mode 600) |
| `enclave run [dir] -- <cmd…>` | run a command with vault entries as env vars |
| `enclave restore [dir]` | undo a seal, byte-exact; manifest removed, vault kept |
| `enclave stow [dir] [pkg…]` | restore secrets, then GNU-stow the packages into the target |
| `enclave unstow [dir] [pkg…]` | GNU-stow `-D` the packages, then seal the secrets back |

Blobs are never exported as env vars by `inject`/`run`.

## Dotfiles with GNU Stow

If your dotfiles live in a [GNU Stow](https://www.gnu.org/software/stow/)
tree — one subdirectory per package, symlinked into `$HOME` — enclave
wraps the two moments that matter:

```sh
cd ~/dotfiles
enclave seal --apply --stow            # seal; record target "~" in the manifest
enclave stow                           # restore values, then stow links them live
enclave unstow                         # stow -D removes the links, secrets seal back
```

`seal --stow [--target <dir>]` stores the target in the manifest
(verbatim — `~` by default — so a committed manifest never leaks an
absolute home path). `enclave stow [pkg…]` restores the vault's values
into the packages first, then runs real GNU stow (`-R` with `--restow`,
`--adopt` passes through); with no package names, every package
directory in the tree is stowed. `enclave unstow` unlinks first, then
seals — afterwards the tree is safe to commit and the target no longer
reaches the secrets. Plaintext exists in the tree only while it is
stowed.

Notes:

- Scan the stow *directory*, not the target: scan doesn't follow
  symlinks, so a stowed `$HOME` shows nothing (by design).
- `enclave restore` on a stow tree removes the manifest, stow target
  record included — prefer `stow`/`unstow`, which preserve it.
- GNU stow must be installed (`apt install stow` / `brew install
  stow`); enclave shells out to it and never writes links itself. The
  UI shows **Stow…** / **Unstow + Seal** buttons in the Vault toolbar
  for stow-managed trees when stow is on the machine.

## Web UI

```sh
enclave ui              # http://127.0.0.1:3039 (--port N to change)
```

A macOS-style three-pane app (Keychain Access is the model) for
everything the CLI does — no decorative chrome, every control works:

- **Sidebar**: views (Scan / Vault / Console), the current project
  (folder picker with a real directory browser), vault state and
  lock/unlock. The passphrase is held in the server's memory only;
  Lock wipes it.
- **Scan**: findings table (sortable, filterable), live verify badge,
  Seal… with a confirmation sheet naming the count and vault path.
- **Vault**: entries with an inspector — Reveal/Hide, Copy (clipboard),
  Extract… (blob download, sha-checked), Delete… (with the drift
  warning spelled out), Write .env.local, Restore….
- **Console**: run any command in the project folder with the vault's
  secrets in its environment; output streams live, Stop kills it.

Light/dark follows the system. The server binds 127.0.0.1 only and the
vault file format is identical to the CLI's — seal in one, open in the
other.

## PGP vaults

By default a vault is passphrase-encrypted (scrypt + AES-256-GCM).
It can instead be **OpenPGP-encrypted to a key** — seal with the
public key, open with the private key, using the system `gpg`. The
vault file stays one JSON envelope; the scheme, recipient fingerprint
and keyring are recorded in the clear so tools know what to ask for.
The encrypted payload is a standard OpenPGP message (extract `data`,
base64-decode, `gpg -d`) — no lock-in.

```sh
enclave pgp init                    # create a dedicated key in ~/.enclave/gnupg
enclave pgp list                      # keys in the dedicated + your system keyring
enclave pgp use <fingerprint|uid>     # seal to one of YOUR existing keys
enclave seal --pgp --apply            # new vault, PGP scheme
enclave pgp convert                   # re-encrypt a vault to the other scheme
```

Two keyrings are kept apart: your own (default GNUPGHOME — enclave
never writes to it except reading public keys and decrypting) and a
dedicated one at `~/.enclave/gnupg` for keys enclave creates. The
dedicated keyring ships a `gpg-agent.conf` with cache TTL 0: a
protected vault key asks for its passphrase every time, like the
passphrase scheme. Keys are Ed25519/Cv25519. Opening a PGP vault
takes the key's passphrase via `ENCLAVE_PASSPHRASE` or the prompt —
for unprotected keys, or keys your gpg-agent already holds, blank
works. `pgp convert` needs the old scheme's credential and the new
one; the UI opens both schemes transparently, and new vaults can be
created as PGP from the unlock sheet.

## Notes & limits

- Blob size cap is 25 MB per file; the vault grows ~1.4× the blob
  size (base64 inside the encrypted payload).
- Sealing text literals in code leaves `enclave:NAME` references —
  your code must read the value from the environment (`enclave run`)
  or you restore before running. `.env` files keep working with any
  loader that treats the value as opaque config you resolve at deploy.
- Detection is deterministic pattern matching, not AI. It will miss
  novel secret formats and can flag lookalikes; `scan` first, always.
