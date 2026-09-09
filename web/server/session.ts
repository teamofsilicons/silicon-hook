import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { mkdir, readFile, open, rename, chmod, unlink } from "node:fs/promises";
import { join } from "node:path";

export interface Tokens {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  actor: { type: string; id: string };
  org_id?: string;
  scopes: string[];
}
export interface Plane {
  name: string;
  key?: string;
  tokens?: Tokens;
  expiresAt?: number;
  refresh?: { key: string; started: number };
}
export interface Session {
  expires: number;
  planes: Record<string, Plane>;
  login?: { state: string; expires: number; mutation: string };
}
const ttl = 7 * 24 * 60 * 60 * 1000;
export class SessionStore {
  private locks = new Map<string, Promise<unknown>>();
  constructor(
    private folder: string,
    private key: Buffer,
  ) {
    if (key.length !== 32)
      throw new Error("HOOK_SESSION_KEY must decode to 32 bytes");
  }
  newId() {
    return randomBytes(32).toString("hex");
  }
  async read(id: string): Promise<Session> {
    if (!/^[a-f0-9]{64}$/.test(id))
      throw new Error("Invalid session identifier");
    try {
      const sealed = await readFile(join(this.folder, id));
      const decipher = createDecipheriv(
        "aes-256-gcm",
        this.key,
        sealed.subarray(0, 12),
      );
      decipher.setAAD(Buffer.from(id));
      decipher.setAuthTag(sealed.subarray(12, 28));
      const session = JSON.parse(
        Buffer.concat([
          decipher.update(sealed.subarray(28)),
          decipher.final(),
        ]).toString(),
      ) as Session;
      if (session.expires > Date.now()) return session;
      await unlink(join(this.folder, id));
    } catch (error) {
      if (
        (error as NodeJS.ErrnoException).code !== "ENOENT" &&
        !(
          error instanceof Error &&
          /authenticate|Unsupported state/.test(error.message)
        )
      )
        throw error;
    }
    return {
      expires: Date.now() + ttl,
      planes: { production: { name: "Production" } },
    };
  }
  async save(id: string, session: Session) {
    await mkdir(this.folder, { recursive: true, mode: 0o700 });
    await chmod(this.folder, 0o700);
    const iv = randomBytes(12),
      cipher = createCipheriv("aes-256-gcm", this.key, iv);
    cipher.setAAD(Buffer.from(id));
    const body = Buffer.concat([
      cipher.update(JSON.stringify(session)),
      cipher.final(),
    ]);
    const temp = join(this.folder, `${id}.${randomBytes(8).toString("hex")}`);
    const file = await open(temp, "wx", 0o600);
    try {
      await file.writeFile(Buffer.concat([iv, cipher.getAuthTag(), body]));
      await file.sync();
    } finally {
      await file.close();
    }
    await rename(temp, join(this.folder, id));
    if (process.platform !== "win32") {
      const directory = await open(this.folder, "r");
      try {
        await directory.sync();
      } finally {
        await directory.close();
      }
    }
  }
  async locked<T>(id: string, work: () => Promise<T>): Promise<T> {
    const before = this.locks.get(id) || Promise.resolve();
    const next = before.catch(() => {}).then(work);
    this.locks.set(id, next);
    try {
      return await next;
    } finally {
      if (this.locks.get(id) === next) this.locks.delete(id);
    }
  }
}
