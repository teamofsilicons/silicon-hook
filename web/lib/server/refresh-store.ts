/** Durable, encrypted session state. No OAuth call may precede its operation's CAS write. */
import { createHash } from "node:crypto";
import { mkdirSync, chmodSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DynamoDBClient, GetItemCommand, PutItemCommand } from "@aws-sdk/client-dynamodb";
import { awsCredentialsProvider } from "@vercel/oidc-aws-credentials-provider";
import { seal, unseal } from "./seal";
import { serverEnv } from "./env";

export interface Entry<T> { version: number; value: T }
export interface RefreshStore {
  read<T>(key: string): Promise<Entry<T> | null>;
  /** null creates only; a version replaces only that exact version. */
  write<T>(key: string, previous: number | null, value: T, expires: number): Promise<boolean>;
}
const purpose = (key: string) => `refresh-state:${key}`;
function decode<T>(key: string, payload: string): T {
  const value = unseal<T>(payload, purpose(key));
  if (value === null) throw new Error("Session state could not be opened.");
  return value;
}
export const stateKey = (kind: string, id: string) => `${serverEnv().appId}#${kind}#${id}`;
export const legacyKey = (token: string) => stateKey("legacy", createHash("sha256").update(token).digest("hex"));

export function dynamoStore(table: string, region: string): RefreshStore {
  const client = new DynamoDBClient({ region, maxAttempts: 3,
    ...(process.env.REFRESH_STATE_ROLE_ARN ? { credentials: awsCredentialsProvider({ roleArn: process.env.REFRESH_STATE_ROLE_ARN }) } : {}),
    requestHandler: { connectionTimeout: 3_000, requestTimeout: 5_000 },
  });
  return {
    async read<T>(key: string) {
      const { Item: row } = await client.send(new GetItemCommand({ TableName: table, Key: { pk: { S: key } }, ConsistentRead: true }));
      if (!row || Number(row.expires?.N) * 1000 <= Date.now()) return null;
      return { version: Number(row.version.N), value: decode<T>(key, row.payload.S!) };
    },
    async write<T>(key: string, previous: number | null, value: T, expires: number) {
      try {
        await client.send(new PutItemCommand({ TableName: table,
          Item: { pk: { S: key }, version: { N: String((previous ?? -1) + 1) }, payload: { S: seal(value, purpose(key)) }, expires: { N: String(Math.ceil(expires / 1000)) } },
          ConditionExpression: previous === null ? "attribute_not_exists(pk)" : "#version = :previous",
          ...(previous === null ? {} : { ExpressionAttributeNames: { "#version": "version" }, ExpressionAttributeValues: { ":previous": { N: String(previous) } } }),
        }));
        return true;
      } catch (error) {
        if (error instanceof Error && error.name === "ConditionalCheckFailedException") return false;
        throw error;
      }
    },
  };
}

/** A persistent local volume for a single host, or development. SQLite serializes independent Node processes. */
async function sqliteStore(path: string): Promise<RefreshStore> {
  const { DatabaseSync } = await import("node:sqlite");
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const db = new DatabaseSync(path);
  chmodSync(path, 0o600);
  db.exec("PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS refresh_state (pk TEXT PRIMARY KEY, version INTEGER NOT NULL, payload TEXT NOT NULL, expires INTEGER NOT NULL)");
  db.prepare("DELETE FROM refresh_state WHERE expires <= ?").run(Date.now());
  return {
    async read<T>(key: string) {
      const row = db.prepare("SELECT version, payload FROM refresh_state WHERE pk = ? AND expires > ?").get(key, Date.now());
      return row ? { version: Number(row.version), value: decode<T>(key, String(row.payload)) } : null;
    },
    async write<T>(key: string, previous: number | null, value: T, expires: number) {
      const payload = seal(value, purpose(key));
      const result = previous === null
        ? db.prepare("INSERT OR IGNORE INTO refresh_state (pk, version, payload, expires) VALUES (?, 0, ?, ?)").run(key, payload, expires)
        : db.prepare("UPDATE refresh_state SET version = version + 1, payload = ?, expires = ? WHERE pk = ? AND version = ?").run(payload, expires, key, previous);
      return result.changes === 1;
    },
  };
}
let cached: { config: string; store: Promise<RefreshStore> } | undefined;
let testStore: RefreshStore | undefined;
/** Unit-test injection only. Production never falls back to memory or a serverless temporary file. */
export function setRefreshStoreForTests(store?: RefreshStore): void {
  if (process.env.NODE_ENV === "production") throw new Error("Test store is disabled in production.");
  testStore = store;
}
export function refreshStore(): Promise<RefreshStore> {
  if (testStore) return Promise.resolve(testStore);
  const table = process.env.REFRESH_STATE_TABLE;
  const region = process.env.REFRESH_STATE_REGION;
  const path = process.env.REFRESH_STATE_PATH;
  const config = JSON.stringify([table, region, path, process.env.REFRESH_STATE_ROLE_ARN]);
  if (cached?.config === config) return cached.store;
  let store: Promise<RefreshStore>;
  if (table && region) store = Promise.resolve(dynamoStore(table, region));
  else if (path && !process.env.VERCEL) store = sqliteStore(resolve(path));
  else if (process.env.NODE_ENV !== "production" && !process.env.VERCEL) store = sqliteStore(resolve(".dev/refresh-state.sqlite"));
  else throw new Error("Durable session storage is not configured.");
  cached = { config, store };
  void store.catch(() => { if (cached?.store === store) cached = undefined; });
  return store;
}
