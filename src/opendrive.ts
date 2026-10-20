// opendrive.ts — minimal OpenDrive.com REST client for the home manager.
// Ported from folio's production-verified sync backend (same endpoints,
// same upload dance): session login, folder ensure/list, chunked upload,
// download. Used directionally: backup uploads, restore downloads.
//   POST /session/login.json            {username, passwd} -> {SessionID}
//   POST /folder.json                   create folder
//   GET  /folder/list.json/{sid}/{fid}  -> {Folders, Files} (0 = root)
//   POST /upload/create_file.json       -> {FileId, TempLocation, RequireHashOnly}
//   POST /upload/open_file_upload.json  -> {TempLocation} (fallback)
//   POST /upload/upload_file_chunk2.json/{sid}/{fid}?temp_location=&chunk_offset=&chunk_size=
//   POST /upload/close_file_upload.json
//   PUT  /file/filesettings.json        set mtime
//   GET  /download/file.json/{fid}?session_id=
import { readFileSync, statSync } from "node:fs";

export const OPENDRIVE_API_BASE = "https://dev.opendrive.com/api/v1";
const CHUNK_SIZE = 10 * 1024 * 1024;

export class OpenDriveError extends Error {
  code: unknown;
  data?: unknown;
  constructor(code: unknown, message: string) {
    super(message);
    this.code = code;
  }
}

function parseApi(bodyText: string, what: string): Record<string, unknown> {
  let data: Record<string, unknown>;
  try { data = JSON.parse(bodyText) as Record<string, unknown>; }
  catch { throw new OpenDriveError("bad-json", `${what}: could not parse response`); }
  const errObj = data?.error as { code?: unknown; message?: string } | undefined;
  if (errObj) {
    const e = new OpenDriveError(errObj.code ?? "api", `${what}: ${errObj.message || "unknown API error"}`);
    e.data = data;
    throw e;
  }
  return data;
}

function httpError(status: number, what: string, bodyText: string): OpenDriveError {
  let msg = `${what}: HTTP ${status}`;
  let data: unknown = null;
  try {
    data = JSON.parse(bodyText);
    const m = (data as { error?: { message?: string } })?.error?.message;
    if (m) msg = `${what}: ${m}`;
  } catch { /* keep generic */ }
  const e = new OpenDriveError(status, msg);
  e.data = data;
  return e;
}

function isSessionError(e: unknown): boolean {
  if (!(e instanceof OpenDriveError)) return false;
  if (e.code === 401) return true;
  return /session|expired|invalid|re-?login|not logged/i.test(e.message);
}
function isTransientError(e: unknown): boolean {
  if (!(e instanceof OpenDriveError)) return false;
  return [408, 423, 429, 500, 502, 503, 504].includes(e.code as number);
}

export interface RemoteFile { id: string; name: string; mtime: number; size: number; hash: string | null; dirId: string }

export class OpenDrive {
  apiBase: string;
  fetchFn: typeof fetch;
  timeoutMs: number;
  sessionId: string | null = null;
  private username: string | null = null;
  private password: string | null = null;

  constructor(opts: { apiBase?: string; fetchFn?: typeof fetch; timeoutMs?: number } = {}) {
    this.apiBase = (opts.apiBase || OPENDRIVE_API_BASE).replace(/\/$/, "");
    this.fetchFn = opts.fetchFn || fetch;
    this.timeoutMs = opts.timeoutMs || 30000;
  }

  private get signal(): AbortSignal { return AbortSignal.timeout(this.timeoutMs); }

  async login(username: string, password: string): Promise<void> {
    this.username = username;
    this.password = password;
    const res = await this.fetchFn(`${this.apiBase}/session/login.json`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, passwd: password }),
      signal: this.signal,
    });
    let data: Record<string, unknown>;
    try {
      data = parseApi(await res.text(), "login");
    } catch (e) {
      if (e instanceof OpenDriveError && e.code === 401 &&
          (e.data as { captcha_key?: unknown } | undefined)?.captcha_key) {
        throw new OpenDriveError(401, "login: OpenDrive is asking for a captcha after repeated failed logins — sign in once at opendrive.com, then retry");
      }
      throw e;
    }
    if (!data.SessionID) throw new OpenDriveError("login", "login: no session id returned");
    this.sessionId = String(data.SessionID);
  }

  /** Run fn; re-login on session expiry, backoff-retry transient errors. */
  private async withSession<T>(fn: () => Promise<T>): Promise<T> {
    let last: unknown;
    for (let attempt = 0; attempt < 4; attempt++) {
      try { return await fn(); }
      catch (e) {
        last = e;
        if (isSessionError(e) && this.username) {
          await this.login(this.username, this.password as string);
          continue;
        }
        if (isTransientError(e)) {
          await new Promise((r) => setTimeout(r, Math.min(500 * 2 ** attempt, 4000)));
          continue;
        }
        throw e;
      }
    }
    throw last;
  }

  private async api(method: string, path: string, json?: Record<string, unknown>): Promise<Record<string, unknown>> {
    const call = async () => {
      const res = await this.fetchFn(`${this.apiBase}${path}`, {
        method,
        headers: json ? { "Content-Type": "application/json" } : undefined,
        body: json ? JSON.stringify({ session_id: this.sessionId, ...json }) : undefined,
        signal: this.signal,
      });
      if (res.status === 401) throw new OpenDriveError(401, "unauthorized (session may have expired)");
      if (!res.ok) throw httpError(res.status, path, await res.text().catch(() => ""));
      return parseApi(await res.text(), path);
    };
    return this.withSession(call);
  }

  private async apiGetSessionPath(template: string): Promise<Record<string, unknown>> {
    const call = async () => {
      const path = template.replace("{sid}", this.sessionId as string);
      const res = await this.fetchFn(`${this.apiBase}${path}`, { signal: this.signal });
      if (res.status === 401) throw new OpenDriveError(401, "unauthorized (session may have expired)");
      if (!res.ok) throw httpError(res.status, path, await res.text().catch(() => ""));
      return parseApi(await res.text(), path);
    };
    return this.withSession(call);
  }

  /** Ensure a '/'-separated remote folder path exists; return its id. */
  async ensureFolderPath(remoteFolder: string): Promise<string> {
    const segs = String(remoteFolder || "/").split("/").filter(Boolean);
    let parentId = "0";
    for (const seg of segs) {
      const list = await this.apiGetSessionPath(`/folder/list.json/{sid}/${parentId}`);
      const folders = (list.Folders as Record<string, unknown>[] | undefined) || [];
      const found = folders.find((f) => String(f.Name).toLowerCase() === seg.toLowerCase());
      if (found) { parentId = String(found.FolderID); continue; }
      const created = await this.api("POST", "/folder.json", {
        folder_name: seg, folder_sub_parent: parentId,
        folder_is_public: 0, folder_public_upl: 0, folder_public_display: 0, folder_public_dnl: 0,
      });
      if (!created.FolderID) throw new OpenDriveError("folder", `could not create remote folder '${seg}'`);
      parentId = String(created.FolderID);
    }
    return parentId;
  }

  /** Recursively list a folder → Map<posix rel path, RemoteFile>. */
  async listRecursive(folderId: string): Promise<Map<string, RemoteFile>> {
    const out = new Map<string, RemoteFile>();
    const walk = async (fid: string, prefix: string): Promise<void> => {
      const list = await this.apiGetSessionPath(`/folder/list.json/{sid}/${fid}`);
      for (const f of (list.Folders as Record<string, unknown>[] | undefined) || []) {
        await walk(String(f.FolderID), prefix ? `${prefix}/${f.Name}` : String(f.Name));
      }
      for (const file of (list.Files as Record<string, unknown>[] | undefined) || []) {
        const rel = prefix ? `${prefix}/${file.Name}` : String(file.Name);
        out.set(rel, {
          id: String(file.FileId || file.FileID),
          name: String(file.Name),
          mtime: Number(file.DateModified) * 1000 || 0,
          size: Number(file.Size) || 0,
          hash: (file.FileHash as string) || null,
          dirId: fid,
        });
      }
    };
    await walk(folderId, "");
    return out;
  }

  /** Chunked upload; re-uploading an existing name overwrites. */
  async uploadFile(folderId: string, name: string, absPath: string): Promise<{ id: string; mtime: number; size: number }> {
    const st = statSync(absPath);
    const size = st.size;
    const mtimeSec = Math.floor(st.mtimeMs / 1000);

    const created = await this.api("POST", "/upload/create_file.json", {
      folder_id: folderId, file_name: name, open_if_exists: 1,
    });
    const fileId = String(created.FileId || created.FileID || "");
    if (!fileId) throw new OpenDriveError("upload", "create_file: no file id returned");
    let tempLocation = (created.TempLocation || created.Temp_Location || null) as string | null;
    const hashOnly = created.RequireHashOnly === 1 || created.RequireHashOnly === "1";

    if (!hashOnly) {
      if (!tempLocation) {
        const opened = await this.api("POST", "/upload/open_file_upload.json", {
          file_id: fileId, file_size: size,
        });
        tempLocation = (opened.TempLocation as string) || null;
      }
      if (!tempLocation) throw new OpenDriveError("upload", "upload: no temp location returned");
      const buf = readFileSync(absPath);
      let offset = 0;
      while (offset < size) {
        const chunk = buf.subarray(offset, Math.min(offset + CHUNK_SIZE, size));
        const reply = await this.withSession(async () => {
          const form = new FormData();
          form.set("file_data", new Blob([chunk]), name);
          const url = `${this.apiBase}/upload/upload_file_chunk2.json/${this.sessionId}/${fileId}` +
            `?temp_location=${encodeURIComponent(tempLocation as string)}` +
            `&chunk_offset=${offset}&chunk_size=${chunk.length}`;
          const res = await this.fetchFn(url, { method: "POST", body: form, signal: this.signal });
          if (res.status === 401) throw new OpenDriveError(401, "unauthorized (session may have expired)");
          if (!res.ok) throw httpError(res.status, "upload_file_chunk2", await res.text().catch(() => ""));
          return parseApi(await res.text(), "upload_file_chunk2");
        });
        if (Number(reply.TotalWritten) !== chunk.length) {
          throw new OpenDriveError("upload", `incomplete chunk write (${reply.TotalWritten}/${chunk.length})`);
        }
        offset += chunk.length;
      }
    }

    const closed = await this.api("POST", "/upload/close_file_upload.json", {
      file_id: fileId, file_size: size, temp_location: tempLocation, file_time: String(mtimeSec),
    });
    const remoteId = String(closed.FileID || closed.FileId || fileId);
    try {
      await this.api("PUT", "/file/filesettings.json", {
        file_id: remoteId, file_modification_time: String(mtimeSec),
      });
    } catch (e) {
      if (!isTransientError(e)) throw e;
    }
    return { id: remoteId, mtime: mtimeSec * 1000, size };
  }

  async downloadFile(fileId: string): Promise<Buffer> {
    const call = async () => {
      const res = await this.fetchFn(
        `${this.apiBase}/download/file.json/${fileId}?session_id=${encodeURIComponent(this.sessionId as string)}`,
        { signal: this.signal },
      );
      if (res.status === 401) throw new OpenDriveError(401, "unauthorized (session may have expired)");
      if (!res.ok) throw httpError(res.status, "download", await res.text().catch(() => ""));
      return Buffer.from(await res.arrayBuffer());
    };
    return this.withSession(call);
  }
}
