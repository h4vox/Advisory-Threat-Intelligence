/**
 * Account persistence: users and password sessions.
 *
 * MongoDB (production): dedicated collections `aie_users` and `aie_sessions` in the configured
 * database, so credential records never mix with threat-intelligence documents. Usernames are
 * unique; expired sessions are removed by a TTL index. Local fallback (no MONGODB_URI): two tables
 * created on first use in the app's SQL database (PGLite in this workspace, which is in-memory and
 * resets on restart; Postgres when DATABASE_URL is set).
 */
import type { Collection } from "mongodb";
import { getSql, type Sql } from "@/lib/db";
import { getMongoDb, isMongoConfigured } from "./client.server";
import type { AccountRole, AccountStorage } from "../aie/accounts/types";

export type UserRecord = {
  id: string;
  /** Lowercase, unique. */
  username: string;
  displayName: string;
  email: string | null;
  role: AccountRole;
  passwordHash: string;
  /** scrypt hash of the AIE_ADMIN_PASSWORD this account was last provisioned from (bootstrap administrator only). */
  bootstrapHash: string | null;
  weakPassword: boolean;
  disabled: boolean;
  failedAttempts: number;
  lockedUntil: Date | null;
  createdAt: Date;
  updatedAt: Date;
  lastLoginAt: Date | null;
  passwordChangedAt: Date | null;
  createdBy: string | null;
};

export type SessionRecord = {
  /** SHA-256 of the session token. */
  tokenHash: string;
  userId: string;
  createdAt: Date;
  expiresAt: Date;
  lastSeenAt: Date;
  userAgent: string | null;
  ip: string | null;
};

export type UserPatch = Partial<Omit<UserRecord, "id" | "createdAt" | "createdBy">>;

export class DuplicateUsernameError extends Error {
  constructor(username: string) {
    super(`The username "${username}" is already taken.`);
    this.name = "DuplicateUsernameError";
  }
}

export interface AccountsStore {
  readonly kind: AccountStorage;
  countUsers(): Promise<number>;
  listUsers(): Promise<UserRecord[]>;
  findUserByUsername(username: string): Promise<UserRecord | null>;
  /** First enabled-or-disabled account with this (lowercased) email, or null. Email is not unique. */
  findUserByEmail(email: string): Promise<UserRecord | null>;
  findUserById(id: string): Promise<UserRecord | null>;
  /** Throws DuplicateUsernameError when the username exists. */
  insertUser(user: UserRecord): Promise<void>;
  updateUser(id: string, patch: UserPatch): Promise<void>;
  /** Atomically adds one failed sign-in and returns the new count (concurrent failures each count). */
  incrementFailedAttempts(id: string, at: Date): Promise<number>;
  deleteUser(id: string): Promise<void>;
  insertSession(session: SessionRecord): Promise<void>;
  findSession(tokenHash: string): Promise<SessionRecord | null>;
  touchSession(tokenHash: string, at: Date): Promise<void>;
  deleteSession(tokenHash: string): Promise<void>;
  /** Revokes every session of the user except `keepTokenHash`; returns how many were removed. */
  deleteUserSessions(userId: string, keepTokenHash?: string): Promise<number>;
  countActiveSessions(userId: string, now: Date): Promise<number>;
}

export function accountsStorage(): AccountStorage {
  return isMongoConfigured() ? "mongodb" : "local";
}

const g = globalThis as typeof globalThis & {
  __aieAccountIndexes__?: Promise<void>;
  __aieAccountTables__?: Promise<Sql>;
};

// ---------------------------------------------------------------------------
// MongoDB
// ---------------------------------------------------------------------------

const USERS_COLLECTION = "aie_users";
const SESSIONS_COLLECTION = "aie_sessions";

function isDuplicateKey(err: unknown): boolean {
  return Boolean(err && typeof err === "object" && (err as { code?: number }).code === 11000);
}

async function mongoCollections(): Promise<{ users: Collection<UserRecord>; sessions: Collection<SessionRecord> }> {
  const db = await getMongoDb();
  const users = db.collection<UserRecord>(USERS_COLLECTION);
  const sessions = db.collection<SessionRecord>(SESSIONS_COLLECTION);
  g.__aieAccountIndexes__ ??= Promise.all([
    users.createIndex({ username: 1 }, { unique: true, name: "username_unique" }),
    users.createIndex({ id: 1 }, { unique: true, name: "id_unique" }),
    sessions.createIndex({ tokenHash: 1 }, { unique: true, name: "token_unique" }),
    sessions.createIndex({ userId: 1 }, { name: "user" }),
    sessions.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0, name: "expires_ttl" }),
  ]).then(
    () => undefined,
    (err) => {
      // Usernames are still checked before insert; the TTL index only tidies expired sessions.
      console.warn("[accounts] MongoDB index creation skipped:", (err as Error).message);
    },
  );
  await g.__aieAccountIndexes__;
  return { users, sessions };
}

const NO_ID = { projection: { _id: 0 } } as const;

const mongoStore: AccountsStore = {
  kind: "mongodb",
  async countUsers() {
    const { users } = await mongoCollections();
    return users.countDocuments({});
  },
  async listUsers() {
    const { users } = await mongoCollections();
    return (await users.find({}, NO_ID).sort({ username: 1 }).limit(1000).toArray()) as UserRecord[];
  },
  async findUserByUsername(username) {
    const { users } = await mongoCollections();
    return (await users.findOne({ username }, NO_ID)) as UserRecord | null;
  },
  async findUserByEmail(email) {
    const { users } = await mongoCollections();
    return (await users.findOne({ email }, NO_ID)) as UserRecord | null;
  },
  async findUserById(id) {
    const { users } = await mongoCollections();
    return (await users.findOne({ id }, NO_ID)) as UserRecord | null;
  },
  async insertUser(user) {
    const { users } = await mongoCollections();
    if (await users.findOne({ username: user.username }, NO_ID)) throw new DuplicateUsernameError(user.username);
    try {
      await users.insertOne({ ...user });
    } catch (err) {
      if (isDuplicateKey(err)) throw new DuplicateUsernameError(user.username);
      throw err;
    }
  },
  async updateUser(id, patch) {
    const { users } = await mongoCollections();
    try {
      await users.updateOne({ id }, { $set: { ...patch, updatedAt: patch.updatedAt ?? new Date() } });
    } catch (err) {
      if (isDuplicateKey(err) && patch.username) throw new DuplicateUsernameError(patch.username);
      throw err;
    }
  },
  async incrementFailedAttempts(id, at) {
    const { users } = await mongoCollections();
    const doc = await users.findOneAndUpdate(
      { id },
      { $inc: { failedAttempts: 1 }, $set: { updatedAt: at } },
      { returnDocument: "after", projection: { _id: 0, failedAttempts: 1 } },
    );
    return Number((doc as { failedAttempts?: number } | null)?.failedAttempts ?? 0);
  },
  async deleteUser(id) {
    const { users, sessions } = await mongoCollections();
    await users.deleteOne({ id });
    await sessions.deleteMany({ userId: id });
  },
  async insertSession(session) {
    const { sessions } = await mongoCollections();
    await sessions.insertOne({ ...session });
  },
  async findSession(tokenHash) {
    const { sessions } = await mongoCollections();
    return (await sessions.findOne({ tokenHash }, NO_ID)) as SessionRecord | null;
  },
  async touchSession(tokenHash, at) {
    const { sessions } = await mongoCollections();
    await sessions.updateOne({ tokenHash }, { $set: { lastSeenAt: at } });
  },
  async deleteSession(tokenHash) {
    const { sessions } = await mongoCollections();
    await sessions.deleteOne({ tokenHash });
  },
  async deleteUserSessions(userId, keepTokenHash) {
    const { sessions } = await mongoCollections();
    const res = await sessions.deleteMany(keepTokenHash ? { userId, tokenHash: { $ne: keepTokenHash } } : { userId });
    return res.deletedCount ?? 0;
  },
  async countActiveSessions(userId, now) {
    const { sessions } = await mongoCollections();
    return sessions.countDocuments({ userId, expiresAt: { $gt: now } });
  },
};

// ---------------------------------------------------------------------------
// Local SQL (PGLite / Postgres)
// ---------------------------------------------------------------------------

async function localSql(): Promise<Sql> {
  g.__aieAccountTables__ ??= (async () => {
    const sql = await getSql();
    await sql`create table if not exists aie_users (
      id text primary key,
      username text not null unique,
      display_name text not null,
      email text,
      role text not null,
      password_hash text not null,
      bootstrap_hash text,
      weak_password boolean not null default false,
      disabled boolean not null default false,
      failed_attempts integer not null default 0,
      locked_until timestamptz,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now(),
      last_login_at timestamptz,
      password_changed_at timestamptz,
      created_by text
    )`;
    await sql`create table if not exists aie_sessions (
      token_hash text primary key,
      user_id text not null,
      created_at timestamptz not null default now(),
      expires_at timestamptz not null,
      last_seen_at timestamptz not null default now(),
      user_agent text,
      ip text
    )`;
    await sql`create index if not exists aie_sessions_user on aie_sessions (user_id)`;
    return sql;
  })().catch((err) => {
    g.__aieAccountTables__ = undefined;
    throw err;
  });
  return g.__aieAccountTables__;
}

type UserRow = {
  id: string;
  username: string;
  display_name: string;
  email: string | null;
  role: string;
  password_hash: string;
  bootstrap_hash: string | null;
  weak_password: boolean;
  disabled: boolean;
  failed_attempts: number;
  locked_until: Date | string | null;
  created_at: Date | string;
  updated_at: Date | string;
  last_login_at: Date | string | null;
  password_changed_at: Date | string | null;
  created_by: string | null;
};

type SessionRow = {
  token_hash: string;
  user_id: string;
  created_at: Date | string;
  expires_at: Date | string;
  last_seen_at: Date | string;
  user_agent: string | null;
  ip: string | null;
};

const toDate = (v: Date | string): Date => (v instanceof Date ? v : new Date(v));
const toDateOrNull = (v: Date | string | null): Date | null => (v === null || v === undefined ? null : toDate(v));

function fromUserRow(r: UserRow): UserRecord {
  return {
    id: r.id,
    username: r.username,
    displayName: r.display_name,
    email: r.email,
    role: r.role === "admin" ? "admin" : "analyst",
    passwordHash: r.password_hash,
    bootstrapHash: r.bootstrap_hash,
    weakPassword: Boolean(r.weak_password),
    disabled: Boolean(r.disabled),
    failedAttempts: Number(r.failed_attempts) || 0,
    lockedUntil: toDateOrNull(r.locked_until),
    createdAt: toDate(r.created_at),
    updatedAt: toDate(r.updated_at),
    lastLoginAt: toDateOrNull(r.last_login_at),
    passwordChangedAt: toDateOrNull(r.password_changed_at),
    createdBy: r.created_by,
  };
}

function fromSessionRow(r: SessionRow): SessionRecord {
  return {
    tokenHash: r.token_hash,
    userId: r.user_id,
    createdAt: toDate(r.created_at),
    expiresAt: toDate(r.expires_at),
    lastSeenAt: toDate(r.last_seen_at),
    userAgent: r.user_agent,
    ip: r.ip,
  };
}

/** Patch field → column. Only these can be updated. */
const USER_COLUMNS: Record<keyof UserPatch, string> = {
  username: "username",
  displayName: "display_name",
  email: "email",
  role: "role",
  passwordHash: "password_hash",
  bootstrapHash: "bootstrap_hash",
  weakPassword: "weak_password",
  disabled: "disabled",
  failedAttempts: "failed_attempts",
  lockedUntil: "locked_until",
  updatedAt: "updated_at",
  lastLoginAt: "last_login_at",
  passwordChangedAt: "password_changed_at",
};

function isUniqueViolation(err: unknown): boolean {
  return Boolean(err && typeof err === "object" && (err as { code?: string }).code === "23505") || /unique|duplicate key/i.test(String((err as Error)?.message ?? ""));
}

const localStore: AccountsStore = {
  kind: "local",
  async countUsers() {
    const sql = await localSql();
    const rows = await sql<{ n: number }>`select count(*)::int as n from aie_users`;
    return Number(rows[0]?.n ?? 0);
  },
  async listUsers() {
    const sql = await localSql();
    return (await sql<UserRow>`select * from aie_users order by username limit 1000`).map(fromUserRow);
  },
  async findUserByUsername(username) {
    const sql = await localSql();
    const rows = await sql<UserRow>`select * from aie_users where username = ${username} limit 1`;
    return rows[0] ? fromUserRow(rows[0]) : null;
  },
  async findUserByEmail(email) {
    const sql = await localSql();
    const rows = await sql<UserRow>`select * from aie_users where email = ${email} order by created_at limit 1`;
    return rows[0] ? fromUserRow(rows[0]) : null;
  },
  async findUserById(id) {
    const sql = await localSql();
    const rows = await sql<UserRow>`select * from aie_users where id = ${id} limit 1`;
    return rows[0] ? fromUserRow(rows[0]) : null;
  },
  async insertUser(u) {
    const sql = await localSql();
    try {
      await sql`
        insert into aie_users (id, username, display_name, email, role, password_hash, bootstrap_hash, weak_password, disabled,
          failed_attempts, locked_until, created_at, updated_at, last_login_at, password_changed_at, created_by)
        values (${u.id}, ${u.username}, ${u.displayName}, ${u.email}, ${u.role}, ${u.passwordHash}, ${u.bootstrapHash}, ${u.weakPassword},
          ${u.disabled}, ${u.failedAttempts}, ${u.lockedUntil}, ${u.createdAt}, ${u.updatedAt}, ${u.lastLoginAt}, ${u.passwordChangedAt}, ${u.createdBy})
      `;
    } catch (err) {
      if (isUniqueViolation(err)) throw new DuplicateUsernameError(u.username);
      throw err;
    }
  },
  async updateUser(id, patch) {
    const sql = await localSql();
    const sets: string[] = [];
    const params: unknown[] = [];
    const full: UserPatch = { ...patch, updatedAt: patch.updatedAt ?? new Date() };
    for (const [key, value] of Object.entries(full) as Array<[keyof UserPatch, unknown]>) {
      const column = USER_COLUMNS[key];
      if (!column || value === undefined) continue;
      params.push(value);
      sets.push(`${column} = $${params.length}`);
    }
    if (sets.length === 0) return;
    params.push(id);
    try {
      await sql.query(`update aie_users set ${sets.join(", ")} where id = $${params.length}`, params);
    } catch (err) {
      if (isUniqueViolation(err) && patch.username) throw new DuplicateUsernameError(patch.username);
      throw err;
    }
  },
  async incrementFailedAttempts(id, at) {
    const sql = await localSql();
    const rows = await sql<{ failed_attempts: number }>`update aie_users set failed_attempts = failed_attempts + 1, updated_at = ${at} where id = ${id} returning failed_attempts`;
    return Number(rows[0]?.failed_attempts ?? 0);
  },
  async deleteUser(id) {
    const sql = await localSql();
    await sql`delete from aie_sessions where user_id = ${id}`;
    await sql`delete from aie_users where id = ${id}`;
  },
  async insertSession(s) {
    const sql = await localSql();
    await sql`
      insert into aie_sessions (token_hash, user_id, created_at, expires_at, last_seen_at, user_agent, ip)
      values (${s.tokenHash}, ${s.userId}, ${s.createdAt}, ${s.expiresAt}, ${s.lastSeenAt}, ${s.userAgent}, ${s.ip})
    `;
  },
  async findSession(tokenHash) {
    const sql = await localSql();
    const rows = await sql<SessionRow>`select * from aie_sessions where token_hash = ${tokenHash} limit 1`;
    return rows[0] ? fromSessionRow(rows[0]) : null;
  },
  async touchSession(tokenHash, at) {
    const sql = await localSql();
    await sql`update aie_sessions set last_seen_at = ${at} where token_hash = ${tokenHash}`;
  },
  async deleteSession(tokenHash) {
    const sql = await localSql();
    await sql`delete from aie_sessions where token_hash = ${tokenHash}`;
  },
  async deleteUserSessions(userId, keepTokenHash) {
    const sql = await localSql();
    const rows = keepTokenHash
      ? await sql<{ token_hash: string }>`delete from aie_sessions where user_id = ${userId} and token_hash <> ${keepTokenHash} returning token_hash`
      : await sql<{ token_hash: string }>`delete from aie_sessions where user_id = ${userId} returning token_hash`;
    // Expired rows are not swept by a TTL index here; drop them whenever sessions are revoked.
    await sql`delete from aie_sessions where expires_at < now()`;
    return rows.length;
  },
  async countActiveSessions(userId, now) {
    const sql = await localSql();
    const rows = await sql<{ n: number }>`select count(*)::int as n from aie_sessions where user_id = ${userId} and expires_at > ${now}`;
    return Number(rows[0]?.n ?? 0);
  },
};

export function getAccountsStore(): AccountsStore {
  return isMongoConfigured() ? mongoStore : localStore;
}
