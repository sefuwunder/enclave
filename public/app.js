/* Enclave UI controller — every control is wired to the real API. */
"use strict";
const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

const S = {
  state: null,          // /api/state payload
  findings: [],
  view: "scan",
  selected: null,       // selected vault entry name
  revealed: new Map(),  // name -> plaintext (client memory only)
  sort: { scan: ["file", 1], vault: ["name", 1] },
  home: null,           // /api/home/state payload
  confirmAction: null,
  browsePath: "",
};

async function api(path, body) {
  const res = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || ("HTTP " + res.status));
  return data;
}
const post = (path, body = {}) => api(path, body);

function setStatus(text, right = "") {
  $("#status-text").textContent = text;
  $("#status-right").textContent = right;
}

/* ---------------- sheets ---------------- */
function openSheet(id) {
  $("#sheet-backdrop").classList.remove("hidden");
  $$(".sheet").forEach((s) => s.classList.add("hidden"));
  $(id).classList.remove("hidden");
}
function closeSheets() {
  $("#sheet-backdrop").classList.add("hidden");
  $$(".sheet").forEach((s) => s.classList.add("hidden"));
}
function showConfirm({ title, msg, confirmLabel = "OK", danger = false, onConfirm }) {
  $("#confirm-title").textContent = title;
  $("#confirm-msg").textContent = msg;
  const btn = $("#btn-do-confirm");
  btn.textContent = confirmLabel;
  btn.className = "tbtn " + (danger ? "danger-confirm" : "primary");
  S.confirmAction = onConfirm;
  openSheet("#sheet-confirm");
}

/* ---------------- sidebar / state ---------------- */
function renderState() {
  const st = S.state;
  if (!st) return;
  $("#proj-name").textContent = st.project;
  $("#proj-path").textContent = st.dir;
  $("#vault-path").textContent = st.vaultPath;
  $("#nav-vault-count").textContent = st.locked ? "" : String(st.entries.length);
  const lockBtn = $("#btn-lock");
  if (st.locked) {
    $("#vault-state").textContent = st.vaultExists ? "Locked" : "No vault yet";
    lockBtn.textContent = st.vaultExists ? "Unlock…" : "Create Vault…";
  } else {
    $("#vault-state").textContent = st.vaultIsNew ? "Unlocked (new — seals on first Seal)" : "Unlocked";
    lockBtn.textContent = "Lock";
  }
  if (st.vaultScheme === "pgp") {
    $("#vault-state").textContent += " · PGP";
    if (st.pgpRecipient) $("#vault-path").textContent = st.vaultPath + "\n→ " + st.pgpRecipient.slice(-16);
  }
  // Stow controls exist only for stow-managed trees on machines with stow.
  const showStow = !!(st.stow && st.stowAvailable);
  $("#btn-stow").classList.toggle("hidden", !showStow);
  $("#btn-unstow").classList.toggle("hidden", !showStow);
  renderVault();
}

async function refreshState() {
  S.state = await api("/api/state");
  renderState();
}

/* ---------------- scan view ---------------- */
function findingValue(f) {
  if (f.blob) return `[${f.size} bytes · ${f.meta || f.kind}]`;
  return f.masked;
}
function renderScan() {
  const q = $("#search").value.toLowerCase();
  const [key, dir] = S.sort.scan;
  const rows = S.findings
    .filter((f) => !q || (f.file + f.kind + f.keyName).toLowerCase().includes(q))
    .sort((a, b) => String(a[key]).localeCompare(String(b[key]), undefined, { numeric: true }) * dir);
  const body = $("#scan-body");
  body.innerHTML = "";
  for (const f of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = "";
    const cells = [f.file, f.line, "", f.keyName, ""];
    cells.forEach((c, i) => {
      const td = document.createElement("td");
      if (i === 2) { const s = document.createElement("span"); s.className = "kind-chip"; s.textContent = f.kind; td.appendChild(s); }
      else if (i === 4) { td.textContent = findingValue(f); td.className = "mono"; }
      else td.textContent = c;
      tr.appendChild(td);
    });
    body.appendChild(tr);
  }
  $("#scan-empty").classList.toggle("hidden", S.findings.length > 0);
  const files = new Set(S.findings.map((f) => f.file)).size;
  setStatus(S.findings.length ? `${S.findings.length} finding(s) in ${files} file(s)` : "No findings",
            S.state ? S.state.dir : "");
}

async function doScan(quiet = false) {
  if (!quiet) setStatus("Scanning…");
  const { findings } = await post("/api/scan");
  S.findings = findings;
  renderScan();
}

/* ---------------- verify ---------------- */
async function doVerify() {
  try {
    const r = await post("/api/verify");
    const badge = $("#verify-badge");
    if (r.ok) {
      badge.className = "verify-badge ok";
      badge.innerHTML = '<span class="dot"></span>Verified clean';
    } else {
      badge.className = "verify-badge bad";
      badge.innerHTML = `<span class="dot"></span>${r.findings.length} plaintext · ${r.drift.length} drift`;
    }
    return r;
  } catch { return null; }
}

/* ---------------- vault view ---------------- */
function renderVault() {
  const st = S.state;
  const body = $("#vault-body");
  body.innerHTML = "";
  if (!st) return;
  const locked = st.locked;
  $("#vault-locked").classList.toggle("hidden", !locked);
  $("#vault-empty").classList.toggle("hidden", locked || st.entries.length > 0);
  const q = $("#search").value.toLowerCase();
  const [key, dir] = S.sort.vault;
  const rows = st.entries
    .filter((e) => !q || (e.name + e.kind + e.file).toLowerCase().includes(q))
    .sort((a, b) => String(a[key] ?? "").localeCompare(String(b[key] ?? "")) * dir);
  for (const e of rows) {
    const tr = document.createElement("tr");
    if (e.name === S.selected) tr.className = "selected";
    const vals = [e.name, "", e.file, new Date(e.sealedAt).toLocaleDateString(), ""];
    vals.forEach((v, i) => {
      const td = document.createElement("td");
      if (i === 1) { const s = document.createElement("span"); s.className = "kind-chip"; s.textContent = e.kind; td.appendChild(s); }
      else if (i === 4) { td.textContent = e.blob ? `[blob · ${e.size} bytes]` : (S.revealed.get(e.name) ?? e.masked); td.className = "mono"; }
      else td.textContent = v;
      tr.appendChild(td);
    });
    tr.addEventListener("click", () => selectEntry(e.name));
    tr.addEventListener("dblclick", () => { selectEntry(e.name); toggleReveal(); });
    body.appendChild(tr);
  }
  if (S.selected && !st.entries.some((e) => e.name === S.selected)) closeInspector();
}

function selectEntry(name) {
  S.selected = name;
  const e = S.state.entries.find((x) => x.name === name);
  if (!e) return;
  $("#inspector").classList.remove("hidden");
  $("#insp-name").textContent = e.name;
  $("#insp-kind").textContent = e.kind;
  $("#insp-file").textContent = e.file;
  $("#insp-sealed").textContent = new Date(e.sealedAt).toLocaleString();
  const hasMeta = !!e.meta;
  $("#insp-meta-label").classList.toggle("hidden", !hasMeta);
  $("#insp-meta").classList.toggle("hidden", !hasMeta);
  if (hasMeta) $("#insp-meta").textContent = e.meta;
  const hasSha = !!e.sha256;
  $("#insp-sha-label").classList.toggle("hidden", !hasSha);
  $("#insp-sha").classList.toggle("hidden", !hasSha);
  if (hasSha) $("#insp-sha").textContent = e.sha256.slice(0, 16) + "…";
  $("#insp-value").textContent = e.blob ? `${e.size} bytes (binary)` : (S.revealed.get(name) ?? e.masked);
  $("#btn-reveal").textContent = S.revealed.has(name) ? "Hide" : "Reveal";
  $("#btn-reveal").classList.toggle("hidden", e.blob);
  $("#btn-copy").classList.toggle("hidden", e.blob);
  $("#btn-extract").classList.toggle("hidden", !e.blob);
  $("#insp-note").textContent = e.blob
    ? "Binary blob. Extract writes the original bytes to a file of your choice via download; Restore puts it back in the tree."
    : "Reveal shows the value here only. Copy puts it on your clipboard.";
  renderVault();
}
function closeInspector() {
  S.selected = null;
  $("#inspector").classList.add("hidden");
}

async function toggleReveal() {
  const name = S.selected;
  if (!name) return;
  if (S.revealed.has(name)) { S.revealed.delete(name); selectEntry(name); return; }
  try {
    const { value } = await post("/api/reveal", { name });
    S.revealed.set(name, value);
    selectEntry(name);
  } catch (e) { setStatus("Reveal failed: " + e.message); }
}

/* ---------------- actions ---------------- */
async function doSeal() {
  if (S.state.locked) { openUnlock("Seal needs the vault — unlock first."); return; }
  if (!S.findings.length) { setStatus("Nothing to seal — scan is clean."); return; }
  const files = new Set(S.findings.map((f) => f.file)).size;
  showConfirm({
    title: "Seal " + S.findings.length + " secret(s)?",
    msg: `Findings from ${files} file(s) will be encrypted into:\n${S.state.vaultPath}\n\nIn the tree they become enclave:NAME references (text) or tombstones (binary blobs). The manifest records names and locations only.`,
    confirmLabel: "Seal",
    onConfirm: async () => {
      try {
        const r = await post("/api/seal");
        S.state = r.state;
        renderState();
        await doScan(true);
        await doVerify();
        setStatus(`Sealed ${r.sealed} secret(s) into the vault.`);
      } catch (e) { setStatus("Seal failed: " + e.message); }
    },
  });
}

async function doRestore() {
  if (S.state.locked) { openUnlock("Restore needs the vault — unlock first."); return; }
  const n = S.state.manifest ? S.state.manifest.entries.length : 0;
  if (!n) { setStatus("Nothing to restore — no manifest in this tree."); return; }
  showConfirm({
    title: "Restore " + n + " secret(s) into the tree?",
    msg: "Sealed values will be written back into the source files, byte-exact, replacing the enclave references. The manifest is then removed (the vault is kept).",
    confirmLabel: "Restore",
    danger: true,
    onConfirm: async () => {
      try {
        const r = await post("/api/restore");
        S.state = r.state;
        S.revealed.clear();
        renderState();
        await doScan(true);
        await doVerify();
        setStatus(`Restored ${r.restored} secret(s)${r.missing ? `, ${r.missing} not found` : ""}.`);
      } catch (e) { setStatus("Restore failed: " + e.message); }
    },
  });
}

async function doStow() {
  if (S.state.locked) { openUnlock("Stow needs the vault — unlock first."); return; }
  const target = S.state.stow ? S.state.stow.target : "~";
  showConfirm({
    title: "Restore secrets and stow the packages?",
    msg: "Sealed values are written back into the packages first, then GNU Stow links them into " + target + ". Plaintext lives in the tree while it is stowed — use Unstow + Seal to lock it away again.",
    confirmLabel: "Stow",
    onConfirm: async () => {
      try {
        const r = await post("/api/stow");
        S.state = r.state;
        S.revealed.clear();
        renderState();
        await doScan(true);
        setStatus(`Stowed ${r.packages.length} package(s) into ${r.target}${r.restored ? ` · restored ${r.restored} secret(s)` : ""}: ${r.packages.join(", ")}`);
      } catch (e) { setStatus("Stow failed: " + e.message); }
    },
  });
}

async function doUnstow() {
  if (S.state.locked) { openUnlock("Unstow needs the vault — unlock first."); return; }
  const target = S.state.stow ? S.state.stow.target : "~";
  showConfirm({
    title: "Unstow and seal the secrets back?",
    msg: "GNU Stow removes the package links from " + target + ", then every plaintext secret in the tree is sealed into the vault. The tree is left safe to commit.",
    confirmLabel: "Unstow + Seal",
    onConfirm: async () => {
      try {
        const r = await post("/api/unstow");
        S.state = r.state;
        S.revealed.clear();
        renderState();
        await doScan(true);
        await doVerify();
        setStatus(`Unstowed ${r.packages.length} package(s) from ${r.target} · sealed ${r.sealed} secret(s).`);
      } catch (e) { setStatus("Unstow failed: " + e.message); }
    },
  });
}

async function doInject() {
  if (S.state.locked) { openUnlock("Inject needs the vault — unlock first."); return; }
  try {
    const r = await post("/api/inject");
    setStatus(`Wrote ${r.count} variable(s) to ${r.out} (mode 600).`);
  } catch (e) { setStatus("Inject failed: " + e.message); }
}

/* ---------------- home manager ---------------- */
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}
function relTime(iso) {
  const s = Math.max(0, (Date.now() - new Date(iso)) / 1000);
  if (s < 90) return "just now";
  if (s < 3600) return Math.round(s / 60) + "m ago";
  if (s < 86400) return Math.round(s / 3600) + "h ago";
  if (s < 86400 * 30) return Math.round(s / 86400) + "d ago";
  return new Date(iso).toLocaleDateString();
}
function fmtBytes(n) {
  if (n == null) return "";
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  if (n < 1073741824) return (n / 1048576).toFixed(1) + " MB";
  return (n / 1073741824).toFixed(2) + " GB";
}
function pillEl(cls, text, title) {
  const p = el("span", "pill " + cls, text);
  if (title) p.title = title;
  return p;
}
// The pill: last backup — when, and where it went.
function backupPill(d) {
  const b = d.lastBackup;
  if (!b) return pillEl("never", "○ No backups yet — " + d.where, "Nothing has been backed up to this destination yet");
  const abs = new Date(b.at).toLocaleString() + " · " + b.files + " file(s) · " + fmtBytes(b.bytes);
  if (!b.ok) return pillEl("error", "✗ Backup failed " + relTime(b.at) + " — " + d.where, b.note || abs);
  const ageH = (Date.now() - new Date(b.at)) / 36e5;
  return pillEl(ageH < 24 ? "fresh" : "stale", "● Backed up " + relTime(b.at) + " → " + d.where, abs);
}

function renderHome() {
  const st = S.home;
  if (!st) return;
  $("#home-unconfigured").classList.toggle("hidden", st.configured);
  $("#home-main").classList.toggle("hidden", !st.configured);
  $("#btn-home-backup-all").disabled = !st.configured || !st.destinations.length;
  if (!st.configured) return;

  const wrap = $("#home-dests");
  wrap.innerHTML = "";
  if (!st.destinations.length) {
    wrap.appendChild(el("div", "home-note", "No destinations yet — add one below. Backups land in an “enclave-home” folder on the destination."));
  }
  for (const d of st.destinations) {
    const card = el("div", "dest-card");
    const head = el("div", "dest-head");
    head.append(el("span", "dest-name", d.name), el("span", "dest-type", d.type), el("span", "dest-where", d.where));
    card.appendChild(head);
    const pills = el("div", "dest-pills");
    pills.appendChild(backupPill(d));
    if (d.mounted === false) pills.appendChild(pillEl("warn", "⚠ Not mounted", "Not a live mount point — backups will refuse until the drive/share is mounted"));
    else if (d.mounted === true) pills.appendChild(pillEl("stale", "Mounted", "The destination is a live mount point"));
    if (d.lastRestore) {
      const r = d.lastRestore;
      pills.appendChild(pillEl(r.ok ? "stale" : "error",
        (r.ok ? "Restored " : "Restore failed ") + relTime(r.at) + " · " + r.files + " file(s)",
        new Date(r.at).toLocaleString()));
    }
    card.appendChild(pills);
    if (d.lastBackup && d.lastBackup.note) card.appendChild(el("div", "dest-note", d.lastBackup.note));
    const actions = el("div", "dest-actions");
    const bBtn = el("button", "tbtn primary", "Back up");
    bBtn.addEventListener("click", () => doHomeBackup(d.name));
    const rBtn = el("button", "tbtn", "Restore…");
    rBtn.addEventListener("click", () => doHomeRestore(d));
    const xBtn = el("button", "tbtn danger", "Remove");
    xBtn.addEventListener("click", () => doHomeDestRemove(d));
    actions.append(bBtn, rBtn, xBtn);
    card.appendChild(actions);
    wrap.appendChild(card);
  }

  const needsOd = st.destinations.some((d) => d.type === "opendrive");
  $("#home-od-creds").classList.toggle("hidden", !(needsOd && !st.opendriveConfigured));

  const fw = $("#home-files");
  fw.innerHTML = "";
  if (!st.files.length) fw.appendChild(el("div", "home-note", "Nothing selected yet — add home-relative paths below (files or folders)."));
  for (const f of st.files) {
    const row = el("div", "home-file-row");
    row.appendChild(el("span", "home-file-path", f.path));
    row.appendChild(el("span", "home-file-meta", f.exists ? (f.dir ? "folder" : fmtBytes(f.size)) : "missing"));
    const rm = el("button", "tbtn", "Remove");
    rm.addEventListener("click", async () => {
      try { S.home = await post("/api/home/remove", { path: f.path }); renderHome(); }
      catch (e) { setStatus("Remove failed: " + e.message); }
    });
    row.appendChild(rm);
    fw.appendChild(row);
  }

  const sw = $("#home-stow");
  sw.innerHTML = "";
  if (st.stow) {
    sw.appendChild(el("div", "home-note", st.stow.dir + " → " + st.stow.target + (st.stow.packages.length ? "" : " · no packages found")));
    if (st.stow.packages.length) {
      const prow = el("div", "dest-pills");
      for (const p of st.stow.packages) {
        prow.appendChild(pillEl(p.stowed ? "fresh" : "never",
          (p.stowed ? "● " : "○ ") + p.name + (p.stowed ? " stowed" : " not stowed"),
          "Package " + p.name));
      }
      sw.appendChild(prow);
    }
    const actions = el("div", "dest-actions");
    const ob = el("button", "tbtn", "Open dotfiles project");
    ob.title = "Switch the project to the stow directory — Stow / Unstow live in its Vault toolbar";
    ob.addEventListener("click", async () => {
      try {
        S.state = await post("/api/project", { dir: st.stow.dir });
        renderState();
        switchView("vault");
      } catch (e) { setStatus("Open failed: " + e.message); }
    });
    actions.appendChild(ob);
    sw.appendChild(actions);
    if (document.activeElement !== $("#home-stowdir")) $("#home-stowdir").value = st.stow.dir;
  } else {
    sw.appendChild(el("div", "home-note", "No stow directory configured — set one below (e.g. ~/dotfiles), or leave it if you don't use GNU Stow."));
  }
}

async function refreshHome() {
  try { S.home = await api("/api/home/state"); renderHome(); }
  catch (e) { setStatus("Home state failed: " + e.message); }
}
async function doHomeBackup(name) {
  setStatus("Backing up" + (name ? " to " + name : " to all destinations") + "…");
  try {
    const r = await post("/api/home/backup", name ? { dest: name } : {});
    S.home = r.status;
    renderHome();
    setStatus("Backup done — " + r.results.map((x) => x.rec
      ? `${x.name}: ${x.rec.files} file(s), ${fmtBytes(x.rec.bytes)}`
      : `${x.name}: FAILED — ${x.error}`).join(" · "));
  } catch (e) { await refreshHome(); setStatus("Backup failed: " + e.message); }
}
function doHomeRestore(d) {
  showConfirm({
    title: "Restore from " + d.name + "?",
    msg: "Selected files will be copied back from " + d.where + " into your home directory, overwriting what is there. Anything outside the selection is untouched.",
    confirmLabel: "Restore",
    danger: true,
    onConfirm: async () => {
      try {
        const r = await post("/api/home/restore", { dest: d.name });
        S.home = r.status;
        renderHome();
        setStatus(`Restored ${r.rec.files} file(s) from ${d.name}.`);
      } catch (e) { await refreshHome(); setStatus("Restore failed: " + e.message); }
    },
  });
}
function doHomeDestRemove(d) {
  showConfirm({
    title: "Remove destination " + d.name + "?",
    msg: "Its config and backup history are removed. Files already backed up there are NOT deleted.",
    confirmLabel: "Remove",
    danger: true,
    onConfirm: async () => {
      try { S.home = await post("/api/home/dest/remove", { name: d.name }); renderHome(); }
      catch (e) { setStatus("Remove failed: " + e.message); }
    },
  });
}
async function doHomeInit() {
  try { S.home = await post("/api/home/config", {}); renderHome(); setStatus("Home config created at ~/.enclave/home.json"); }
  catch (e) { setStatus("Init failed: " + e.message); }
}
async function doHomeAddFile() {
  const path = $("#home-add-input").value.trim();
  if (!path) return;
  try {
    S.home = await post("/api/home/add", { path });
    $("#home-add-input").value = "";
    renderHome();
  } catch (e) { setStatus("Add failed: " + e.message); }
}
async function doDestAdd() {
  const type = $("#dest-type").value;
  const body = { name: $("#dest-name").value.trim(), type };
  const pathVal = $("#dest-path").value.trim();
  if (type === "opendrive") { if (pathVal) body.folder = pathVal.startsWith("/") ? pathVal : "/" + pathVal; }
  else if (pathVal) body.path = pathVal;
  const url = $("#dest-url").value.trim();
  if (url) body.url = url;
  if (!body.name) { setStatus("Give the destination a name first."); return; }
  try { S.home = await post("/api/home/dest/add", body); renderHome(); setStatus("Destination added: " + body.name); }
  catch (e) { setStatus("Add destination failed: " + e.message); }
}
async function doOdSave() {
  const username = $("#od-user").value.trim();
  const password = $("#od-pass").value;
  if (!username || !password) { setStatus("OpenDrive username and password are both needed."); return; }
  try {
    S.home = await post("/api/home/creds", { username, password });
    $("#od-pass").value = "";
    renderHome();
    setStatus("OpenDrive credentials saved (never shown back).");
  } catch (e) { setStatus("Save failed: " + e.message); }
}
async function doStowDirSave() {
  try {
    S.home = await post("/api/home/config", { stowDir: $("#home-stowdir").value.trim() });
    renderHome();
    setStatus("Stow directory saved.");
  } catch (e) { setStatus("Save failed: " + e.message); }
}

async function doDelete() {
  const name = S.selected;
  if (!name) return;
  showConfirm({
    title: `Delete ${name} from the vault?`,
    msg: "The sealed value is gone for good. Any enclave reference to it left in the tree can never be restored — verification will report it as drift.",
    confirmLabel: "Delete",
    danger: true,
    onConfirm: async () => {
      try {
        const r = await post("/api/delete", { name });
        S.state = r.state;
        S.revealed.delete(name);
        closeInspector();
        renderState();
        await doVerify();
        setStatus(`Deleted ${name} from the vault.`);
      } catch (e) { setStatus("Delete failed: " + e.message); }
    },
  });
}

/* ---------------- unlock / lock ---------------- */
let unlockScheme = "passphrase";
let keysLoaded = false;
function setSeg(scheme) {
  unlockScheme = scheme;
  $("#seg-pass").classList.toggle("selected", scheme === "passphrase");
  $("#seg-pgp").classList.toggle("selected", scheme === "pgp");
  $("#unlock-pgp-picker").classList.toggle("hidden", scheme !== "pgp");
  if (scheme === "pgp" && !keysLoaded) loadKeys();
}
async function loadKeys() {
  try {
    const r = await api("/api/pgp/keys");
    const sel = $("#unlock-key");
    sel.innerHTML = "";
    if (!r.available) {
      $("#seg-pgp").disabled = true;
      $("#seg-pgp").textContent = "PGP Key (no gpg)";
      return;
    }
    for (const k of r.keys) {
      const opt = document.createElement("option");
      opt.value = k.fingerprint;
      opt.dataset.keyring = k.keyring;
      opt.textContent = `${k.uid} — …${k.fingerprint.slice(-8)} (${k.keyring}${k.hasSecret ? ", secret ✓" : ", public only"})`;
      if (k.fingerprint === r.defaultRecipient) opt.selected = true;
      sel.appendChild(opt);
    }
    const gen = document.createElement("option");
    gen.value = "__generate";
    gen.textContent = "Generate a new enclave key…";
    sel.appendChild(gen);
    keysLoaded = true;
  } catch { /* leave picker empty; seal will surface errors */ }
}
function openUnlock(msg) {
  const st = S.state;
  const creating = !(st && st.vaultExists);
  const isPgp = st && st.vaultScheme === "pgp" && st.vaultExists;
  $("#unlock-title").textContent = isPgp ? "Unlock PGP Vault" : creating ? "Create Vault" : "Unlock Vault";
  $("#btn-do-unlock").textContent = creating ? "Create" : "Unlock";
  $("#unlock-pgp").classList.toggle("hidden", !creating);
  if (creating) setSeg("passphrase");
  if (isPgp) {
    $("#unlock-msg").textContent = `This vault is OpenPGP-encrypted to …${(st.pgpRecipient || "").slice(-8)}. Enter the key's passphrase — leave blank for an unprotected key or your GPG agent.`;
    $("#unlock-pass").placeholder = "PGP key passphrase (may be blank)";
  } else {
    $("#unlock-pass").placeholder = "Passphrase";
    if (msg) $("#unlock-msg").textContent = msg;
    else if (creating) $("#unlock-msg").textContent = "Choose how this project's vault is protected. The passphrase (or key) is kept in this server's memory only until you lock.";
  }
  $("#unlock-error").classList.add("hidden");
  $("#unlock-pass").value = "";
  openSheet("#sheet-unlock");
  setTimeout(() => $("#unlock-pass").focus(), 60);
}
async function doUnlock() {
  const pass = $("#unlock-pass").value;
  const body = { passphrase: pass };
  try {
    if (S.state && !S.state.vaultExists && unlockScheme === "pgp") {
      const sel = $("#unlock-key");
      if (sel.value === "__generate") {
        const r = await post("/api/pgp/init", {
          name: "Enclave Vault",
          email: "enclave@" + S.state.project + ".local",
          passphrase: pass,
        });
        body.scheme = "pgp";
        body.recipient = r.key.fingerprint;
        body.keyring = "dedicated";
      } else if (sel.value) {
        body.scheme = "pgp";
        body.recipient = sel.value;
        body.keyring = sel.selectedOptions[0].dataset.keyring || "dedicated";
      } else {
        throw new Error("no PGP key selected");
      }
    }
    S.state = await post("/api/unlock", body);
    $("#unlock-pass").value = "";
    closeSheets();
    renderState();
    await doScan(true);
    await doVerify();
    setStatus(S.state.vaultIsNew ? "Vault created — first Seal encrypts into it." : "Vault unlocked.");
  } catch (e) {
    const errEl = $("#unlock-error");
    errEl.textContent = e.message;
    errEl.classList.remove("hidden");
    $("#sheet-unlock").classList.remove("shake");
    void $("#sheet-unlock").offsetWidth;
    $("#sheet-unlock").classList.add("shake");
  }
}

/* ---------------- project picker ---------------- */
async function browseTo(path) {
  try {
    const r = await api("/api/browse?path=" + encodeURIComponent(path));
    S.browsePath = r.path;
    $("#proj-input").value = r.path;
    const list = $("#browse-list");
    list.innerHTML = "";
    for (const d of r.dirs) {
      const item = document.createElement("div");
      item.className = "browse-item";
      item.textContent = d;
      item.addEventListener("click", () => browseTo(r.path + "/" + d));
      list.appendChild(item);
    }
    if (!r.dirs.length) list.innerHTML = '<div class="browse-item">(no subfolders)</div>';
    $("#btn-browse-up").onclick = () => browseTo(r.parent);
  } catch (e) { setStatus("Browse failed: " + e.message); }
}
async function doProject() {
  const dir = $("#proj-input").value.trim();
  try {
    S.state = await post("/api/project", { dir });
    closeSheets();
    S.revealed.clear();
    closeInspector();
    renderState();
    await doScan(true);
    await doVerify();
    setStatus("Project: " + S.state.dir);
    if (S.state.vaultExists && S.state.locked) openUnlock();
  } catch (e) { setStatus("Open project failed: " + e.message); }
}

/* ---------------- console ---------------- */
function appendOutput(text, cls = "") {
  const out = $("#run-output");
  if (!cls) { out.appendChild(document.createTextNode(text)); }
  else {
    const span = document.createElement("span");
    span.className = cls;
    span.textContent = text;
    out.appendChild(span);
  }
  out.scrollTop = out.scrollHeight;
}
async function doRun() {
  const cmd = $("#run-input").value.trim();
  if (!cmd) return;
  if (S.state.locked) { openUnlock("Run needs the vault — unlock first."); return; }
  $("#btn-run").disabled = true;
  $("#btn-stop").disabled = false;
  appendOutput(`❯ ${cmd}\n`, "meta");
  try {
    const res = await fetch("/api/run", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ cmd }),
    });
    if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.error || "HTTP " + res.status); }
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = "";
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let idx;
      while ((idx = buf.indexOf("\n\n")) !== -1) {
        const line = buf.slice(0, idx); buf = buf.slice(idx + 2);
        if (!line.startsWith("data: ")) continue;
        const ev = JSON.parse(line.slice(6));
        if (ev.type === "exit") appendOutput(`\n— exited with code ${ev.text}\n`, "meta");
        else appendOutput(ev.text, ev.type === "err" ? "err" : "");
      }
    }
  } catch (e) { appendOutput("\nrun failed: " + e.message + "\n", "err"); }
  $("#btn-run").disabled = false;
  $("#btn-stop").disabled = true;
}

/* ---------------- view switching ---------------- */
function switchView(view) {
  S.view = view;
  $$(".nav-item").forEach((b) => b.classList.toggle("selected", b.dataset.view === view));
  ["scan", "vault", "console", "home"].forEach((v) => {
    $("#view-" + v).classList.toggle("hidden", v !== view);
    $("#toolbar-" + v)?.classList.toggle("hidden", v !== view);
  });
  $("#search").style.visibility = view === "console" || view === "home" ? "hidden" : "visible";
  if (view !== "vault") closeInspector();
  if (view === "vault" && S.state) setStatus(S.state.locked ? "Vault is locked" : `${S.state.entries.length} entr(ies) in the ${S.state.project} vault`, S.state.dir);
  if (view === "console") setStatus("Console — commands run in the project folder with vault secrets in the environment", S.state ? S.state.dir : "");
  if (view === "home") { refreshHome(); setStatus("Home — backups and stow state for this machine", S.home ? S.home.home : ""); }
  if (view === "scan") renderScan();
}

/* ---------------- wiring ---------------- */
function init() {
  $$(".nav-item").forEach((b) => b.addEventListener("click", () => switchView(b.dataset.view)));
  $("#btn-rescan").addEventListener("click", () => doScan());
  $("#btn-seal").addEventListener("click", doSeal);
  $("#btn-restore").addEventListener("click", doRestore);
  $("#btn-stow").addEventListener("click", doStow);
  $("#btn-unstow").addEventListener("click", doUnstow);
  $("#btn-inject").addEventListener("click", doInject);
  $("#btn-clear-output").addEventListener("click", () => { $("#run-output").innerHTML = ""; });
  $("#btn-home-refresh").addEventListener("click", refreshHome);
  $("#btn-home-backup-all").addEventListener("click", () => doHomeBackup(null));
  $("#btn-home-init").addEventListener("click", doHomeInit);
  $("#btn-home-add").addEventListener("click", doHomeAddFile);
  $("#home-add-input").addEventListener("keydown", (e) => { if (e.key === "Enter") doHomeAddFile(); });
  $("#btn-dest-add").addEventListener("click", doDestAdd);
  $("#btn-od-save").addEventListener("click", doOdSave);
  $("#btn-home-stowdir").addEventListener("click", doStowDirSave);
  $("#verify-badge").addEventListener("click", async () => { await doVerify(); setStatus("Verification re-run."); });
  $("#search").addEventListener("input", () => { renderScan(); renderVault(); });
  $("#btn-lock").addEventListener("click", async () => {
    if (S.state && !S.state.locked) {
      await post("/api/lock");
      S.revealed.clear();
      closeInspector();
      await refreshState();
      setStatus("Vault locked. Passphrase wiped from memory.");
    } else openUnlock();
  });
  $("#btn-unlock-2").addEventListener("click", () => openUnlock());
  $("#btn-do-unlock").addEventListener("click", doUnlock);
  $("#seg-pass").addEventListener("click", () => setSeg("passphrase"));
  $("#seg-pgp").addEventListener("click", () => setSeg("pgp"));
  $("#unlock-pass").addEventListener("keydown", (e) => { if (e.key === "Enter") doUnlock(); });
  $("#btn-change-project").addEventListener("click", async () => {
    openSheet("#sheet-project");
    await browseTo(S.state ? S.state.dir : "~");
  });
  $("#btn-do-project").addEventListener("click", doProject);
  $("#proj-input").addEventListener("keydown", (e) => { if (e.key === "Enter") doProject(); });
  $("#btn-do-confirm").addEventListener("click", async () => {
    const fn = S.confirmAction;
    S.confirmAction = null;
    closeSheets();
    if (fn) await fn();
  });
  $$("[data-close]").forEach((b) => b.addEventListener("click", closeSheets));
  $("#sheet-backdrop").addEventListener("click", (e) => { if (e.target === e.currentTarget) closeSheets(); });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeSheets();
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "f") { e.preventDefault(); $("#search").focus(); }
  });
  $("#btn-reveal").addEventListener("click", toggleReveal);
  $("#btn-copy").addEventListener("click", async () => {
    const name = S.selected;
    if (!name) return;
    try {
      const value = S.revealed.get(name) ?? (await post("/api/reveal", { name })).value;
      await navigator.clipboard.writeText(value);
      setStatus(`Copied ${name} to the clipboard.`);
    } catch (e) { setStatus("Copy failed: " + e.message); }
  });
  $("#btn-extract").addEventListener("click", () => {
    if (S.selected) window.location.href = "/api/extract?name=" + encodeURIComponent(S.selected);
  });
  $("#btn-delete").addEventListener("click", doDelete);
  $("#btn-run").addEventListener("click", doRun);
  $("#btn-stop").addEventListener("click", async () => { await post("/api/run/stop"); });
  $("#run-input").addEventListener("keydown", (e) => { if (e.key === "Enter") doRun(); });
  $$("th[data-sort]").forEach((th) => th.addEventListener("click", () => {
    const view = th.closest(".view").id === "view-scan" ? "scan" : "vault";
    const key = th.dataset.sort;
    const cur = S.sort[view];
    S.sort[view] = [key, cur[0] === key ? -cur[1] : 1];
    renderScan(); renderVault();
  }));

  (async () => {
    await refreshState();
    await doScan(true);
    await doVerify();
    if (S.state.vaultExists && S.state.locked) openUnlock();
  })();
}
document.addEventListener("DOMContentLoaded", init);
