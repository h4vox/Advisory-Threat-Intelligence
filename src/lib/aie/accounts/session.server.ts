/**
 * Password accounts and sessions (server-only).
 *
 * - The administrator is provisioned from the environment: AIE_ADMIN_USERNAME (default "havox")
 *   and AIE_ADMIN_PASSWORD. It is created on first use when missing. Changing AIE_ADMIN_PASSWORD
 *   later resets that account's password on the next start (the recovery path), while a password
 *   changed in the app survives restarts as long as the variable stays the same.
 * - A session is a random token in an HttpOnly, SameSite=Lax cookie (`__Host-` and Secure over
 *   HTTPS). Embedded previews, where the cookie cannot be used, send the same token from
 *   sessionStorage instead; it is checked exactly like the cookie.
 * - Failed sign-ins lock an account for 15 minutes after 5 attempts, and an address after 30
 *   failures in 15 minutes. Unknown usernames cost the same scrypt work as known ones.
 */
import { deleteCookie, getCookie, getRequestHeader, getRequestIP, getRequestProtocol, setCookie } from "@tanstack/react-start/server";
import {
  DuplicateUsernameError,
  accountsStorage,
  getAccountsStore,
  type AccountsStore,
  type UserPatch,
  type UserRecord,
} from "../../mongodb/accounts-repo.server";
import {
  DEFAULT_ADMIN_USERNAME,
  IP_MAX_FAILURES,
  IP_WINDOW_MS,
  LOCKOUT_MAX_FAILURES,
  LOCKOUT_MS,
  PASSWORD_MAX_LENGTH,
  SESSION_TTL_MS,
  isLocked,
  isWeakPassword,
  lockoutAfter,
  minutesUntil,
  normalizeUsername,
  passwordError,
  releaseAttempt,
  reserveAttempt,
  usernameError,
  type AttemptWindow,
} from "./policy";
import {
  dummyPasswordHash,
  hashPassword,
  hashSessionToken,
  looksLikeSessionToken,
  newAccountId,
  newSessionToken,
  verifyPassword,
} from "./password.server";
import type { AccountRole, AccountSessionInfo, PublicAccount } from "./types";

export class AccountError extends Error {
  constructor(
    message: string,
    readonly status = 400,
  ) {
    super(message);
    this.name = "AccountError";
  }
}

const COOKIE_SECURE = "__Host-aie.session";
const COOKIE_PLAIN = "aie.session";
const STORE_TIMEOUT_MS = 8000;

function env(key: string): string | undefined {
  const v = process.env[key]?.trim();
  return v ? v : undefined;
}

export function withTimeout<T>(promise: Promise<T>, ms: number, message: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new AccountError(message, 503)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

function adminUsername(): string {
  return normalizeUsername(env("AIE_ADMIN_USERNAME") ?? DEFAULT_ADMIN_USERNAME);
}

function adminPassword(): string | undefined {
  const raw = process.env.AIE_ADMIN_PASSWORD;
  return raw && raw.trim() ? raw.trim() : undefined;
}

export function adminConfigured(): boolean {
  return Boolean(adminPassword()) && !usernameError(adminUsername());
}

async function bootstrapAdmin(store: AccountsStore): Promise<void> {
  const password = adminPassword();
  if (!password) return;
  const username = adminUsername();
  const invalid = usernameError(username);
  if (invalid) {
    console.error(`[accounts] AIE_ADMIN_USERNAME is not a valid username: ${invalid}`);
    return;
  }
  if (password.length > PASSWORD_MAX_LENGTH) {
    console.error(`[accounts] AIE_ADMIN_PASSWORD is longer than ${PASSWORD_MAX_LENGTH} characters; administrator not provisioned.`);
    return;
  }
  const now = new Date();
  const existing = await store.findUserByUsername(username);
  if (!existing) {
    const [passwordHash, bootstrapHash] = await Promise.all([hashPassword(password), hashPassword(password)]);
    try {
      await store.insertUser({
        id: newAccountId(),
        username,
        displayName: username,
        email: env("AIE_ADMIN_EMAIL")?.toLowerCase() ?? null,
        role: "admin",
        passwordHash,
        bootstrapHash,
        weakPassword: isWeakPassword(password),
        disabled: false,
        failedAttempts: 0,
        lockedUntil: null,
        createdAt: now,
        updatedAt: now,
        lastLoginAt: null,
        passwordChangedAt: now,
        createdBy: "environment",
      });
      console.info(`[accounts] administrator "${username}" provisioned from AIE_ADMIN_PASSWORD (${store.kind})`);
    } catch (err) {
      if (!(err instanceof DuplicateUsernameError)) throw err; // another instance won the race
    }
    return;
  }
  const unchanged = existing.bootstrapHash ? await verifyPassword(password, existing.bootstrapHash) : false;
  if (unchanged) return;
  // AIE_ADMIN_PASSWORD changed since this account was provisioned: the operator is resetting it.
  const [passwordHash, bootstrapHash] = await Promise.all([hashPassword(password), hashPassword(password)]);
  await store.updateUser(existing.id, {
    passwordHash,
    bootstrapHash,
    weakPassword: isWeakPassword(password),
    role: "admin",
    disabled: false,
    failedAttempts: 0,
    lockedUntil: null,
    passwordChangedAt: now,
  });
  await store.deleteUserSessions(existing.id);
  invalidateSessionCache();
  console.info(`[accounts] administrator "${username}" password reset from AIE_ADMIN_PASSWORD (${store.kind})`);
}

const g = globalThis as typeof globalThis & {
  __aieAccountsReady__?: Promise<void>;
  __aieAccountsReadyFor__?: string;
  __aieSessionCache__?: Map<string, { user: UserRecord; until: number }>;
  __aieIpAttempts__?: Map<string, AttemptWindow>;
  __aieUserAttempts__?: Map<string, AttemptWindow>;
};

/**
 * The account store, with the administrator provisioned. Provisioning runs once per process (again
 * if the store or the admin settings change); only that promise is kept, so the store itself is
 * always the current module's.
 */
export async function ensureAccountsReady(): Promise<AccountsStore> {
  const key = `${accountsStorage()}|${adminUsername()}|${adminPassword() ? "set" : "unset"}`;
  if (!g.__aieAccountsReady__ || g.__aieAccountsReadyFor__ !== key) {
    g.__aieAccountsReadyFor__ = key;
    g.__aieAccountsReady__ = bootstrapAdmin(getAccountsStore()).catch((err) => {
      g.__aieAccountsReady__ = undefined;
      throw err;
    });
  }
  await g.__aieAccountsReady__;
  return getAccountsStore();
}

/** Shown to visitors who may not be signed in: the kind of failure, never hosts, paths or driver text (those go to the server log). */
function storeError(err: unknown): string {
  if (err instanceof AccountError) return err.message;
  console.warn("[accounts] account store error:", err instanceof Error ? err.message : err);
  return accountsStorage() === "mongodb"
    ? "MongoDB is not reachable. Check MONGODB_URI and the database's network access (details are in the server log)."
    : "The local account database failed to start (details are in the server log).";
}

// ---------------------------------------------------------------------------
// Public shape
// ---------------------------------------------------------------------------

const iso = (d: Date | null): string | null => (d ? d.toISOString() : null);

export function toPublicAccount(u: UserRecord): PublicAccount {
  return {
    id: u.id,
    username: u.username,
    displayName: u.displayName || u.username,
    email: u.email,
    role: u.role,
    disabled: u.disabled,
    createdAt: u.createdAt.toISOString(),
    createdBy: u.createdBy,
    lastLoginAt: iso(u.lastLoginAt),
    passwordChangedAt: iso(u.passwordChangedAt),
    weakPassword: u.weakPassword,
    lockedUntil: u.lockedUntil && u.lockedUntil.getTime() > Date.now() ? u.lockedUntil.toISOString() : null,
    bootstrap: u.createdBy === "environment" || Boolean(u.bootstrapHash),
  };
}

// ---------------------------------------------------------------------------
// Cookie
// ---------------------------------------------------------------------------

function requestIsHttps(): boolean {
  try {
    return getRequestProtocol() === "https";
  } catch {
    return false;
  }
}

export function readSessionCookie(): string | null {
  try {
    return getCookie(COOKIE_SECURE) ?? getCookie(COOKIE_PLAIN) ?? null;
  } catch {
    return null;
  }
}

function writeSessionCookie(token: string): void {
  const secure = requestIsHttps();
  const options = { httpOnly: true, sameSite: "lax" as const, path: "/", maxAge: Math.floor(SESSION_TTL_MS / 1000) };
  if (secure) {
    setCookie(COOKIE_SECURE, token, { ...options, secure: true });
    if (getCookie(COOKIE_PLAIN)) deleteCookie(COOKIE_PLAIN, { path: "/" });
  } else {
    // Plain HTTP (local development, LAN): browsers drop Secure cookies outside localhost, so the session would vanish.
    setCookie(COOKIE_PLAIN, token, { ...options, secure: false });
  }
}

function clearSessionCookie(): void {
  try {
    if (getCookie(COOKIE_SECURE)) deleteCookie(COOKIE_SECURE, { path: "/", secure: true });
    if (getCookie(COOKIE_PLAIN)) deleteCookie(COOKIE_PLAIN, { path: "/" });
  } catch {
    /* no request context */
  }
}

// ---------------------------------------------------------------------------
// Session resolution
// ---------------------------------------------------------------------------

const CACHE_MS = 30_000;
const TOUCH_MS = 5 * 60_000;

function sessionCache() {
  g.__aieSessionCache__ ??= new Map();
  return g.__aieSessionCache__;
}

function invalidateSessionCache(userId?: string): void {
  const cache = sessionCache();
  if (!userId) {
    cache.clear();
    return;
  }
  for (const [k, v] of cache) if (v.user.id === userId) cache.delete(k);
}

/** The enabled account behind a session token, or null (expired, revoked, disabled, unknown). */
export async function resolveSessionToken(token: string | null | undefined): Promise<UserRecord | null> {
  if (!looksLikeSessionToken(token)) return null;
  const tokenHash = hashSessionToken(token);
  const now = Date.now();
  const cache = sessionCache();
  const hit = cache.get(tokenHash);
  if (hit && hit.until > now) return hit.user;
  const store = await withTimeout(ensureAccountsReady(), STORE_TIMEOUT_MS, "The account store did not respond.");
  const session = await withTimeout(store.findSession(tokenHash), STORE_TIMEOUT_MS, "The account store did not respond.");
  if (!session || session.expiresAt.getTime() <= now) {
    cache.delete(tokenHash);
    if (session) void store.deleteSession(tokenHash).catch(() => undefined);
    return null;
  }
  const user = await store.findUserById(session.userId);
  if (!user || user.disabled) {
    cache.delete(tokenHash);
    return null;
  }
  if (now - session.lastSeenAt.getTime() > TOUCH_MS) void store.touchSession(tokenHash, new Date(now)).catch(() => undefined);
  if (cache.size > 2000) cache.clear();
  cache.set(tokenHash, { user, until: Math.min(now + CACHE_MS, session.expiresAt.getTime()) });
  return user;
}

/** The session token this request carries: the cookie, else the token an embedded preview forwarded. */
export function requestSessionToken(embeddedToken?: string | null): string | null {
  const cookie = readSessionCookie();
  if (looksLikeSessionToken(cookie)) return cookie;
  return looksLikeSessionToken(embeddedToken) ? embeddedToken : null;
}

export async function resolveRequestAccount(embeddedToken?: string | null): Promise<UserRecord | null> {
  const token = requestSessionToken(embeddedToken);
  if (!token) return null;
  return resolveSessionToken(token);
}

async function devAccessAllowed(): Promise<boolean> {
  if (process.env.NODE_ENV === "production" || env("DATABASE_URL")) return false;
  const [{ authConfigured }, { gateIdentityEnabled }] = await Promise.all([
    import("@/lib/auth/verify.server"),
    import("@/lib/auth/gate-identity.server"),
  ]);
  return !authConfigured && !gateIdentityEnabled();
}

/** Everything the sign-in gate needs. Never throws: an unreachable store is reported, not raised. */
export async function describeAccountSession(embeddedToken?: string | null): Promise<AccountSessionInfo> {
  const base = {
    storage: accountsStorage(),
    adminConfigured: adminConfigured(),
    devAccess: await devAccessAllowed().catch(() => false),
  };
  try {
    const store = await withTimeout(ensureAccountsReady(), STORE_TIMEOUT_MS, "The account store did not respond within 8 seconds.");
    const user = await resolveRequestAccount(embeddedToken);
    if (user) return { ...base, user: toPublicAccount(user), available: true, hasAccounts: true };
    if (readSessionCookie()) clearSessionCookie(); // stale or revoked
    const count = await withTimeout(store.countUsers(), STORE_TIMEOUT_MS, "The account store did not respond within 8 seconds.");
    return { ...base, user: null, available: true, hasAccounts: count > 0 };
  } catch (err) {
    return { ...base, user: null, available: false, error: storeError(err), hasAccounts: base.adminConfigured };
  }
}

// ---------------------------------------------------------------------------
// Sign-in / sign-out
// ---------------------------------------------------------------------------

function clientIp(): string {
  try {
    return getRequestIP({ xForwardedFor: true }) ?? "unknown";
  } catch {
    return "unknown";
  }
}

/** In-memory attempt windows (per server instance), on top of the account lock kept in the store. */
function attemptWindows() {
  g.__aieIpAttempts__ ??= new Map();
  g.__aieUserAttempts__ ??= new Map();
  return { byIp: g.__aieIpAttempts__, byUser: g.__aieUserAttempts__ };
}

const INVALID = "Incorrect username or password.";

function lockedMessage(until: Date | string, now: Date, justLocked = false): string {
  const minutes = minutesUntil(until, now);
  return justLocked
    ? `Too many failed sign-ins. This account is now locked for ${minutes} minutes.`
    : `Too many failed sign-ins. This account is locked for ${minutes} more minute${minutes === 1 ? "" : "s"}.`;
}

export async function signInWithPassword(input: { username: string; password: string }): Promise<{ user: PublicAccount; token: string; expiresAt: string }> {
  const now = new Date();
  const ip = clientIp();
  const username = normalizeUsername(input.username);
  const password = input.password;
  // Reserve the attempt before any await: a burst of parallel guesses is cut off at the limit, not after it.
  const { byIp, byUser } = attemptWindows();
  if (!reserveAttempt(byIp, ip, IP_MAX_FAILURES, IP_WINDOW_MS, now.getTime())) {
    throw new AccountError(`Too many failed sign-ins from this network. Try again in ${minutesUntil(new Date(byIp.get(ip)!.resetAt), now)} minutes.`, 429);
  }
  if (!reserveAttempt(byUser, username, LOCKOUT_MAX_FAILURES, LOCKOUT_MS, now.getTime())) {
    releaseAttempt(byIp, ip);
    throw new AccountError(lockedMessage(new Date(byUser.get(username)!.resetAt), now), 429);
  }
  if (!password || password.length > PASSWORD_MAX_LENGTH) throw new AccountError(INVALID, 401);

  let store: AccountsStore;
  try {
    store = await withTimeout(ensureAccountsReady(), STORE_TIMEOUT_MS, "The account store did not respond within 8 seconds.");
  } catch (err) {
    releaseAttempt(byIp, ip);
    releaseAttempt(byUser, username);
    throw new AccountError(storeError(err), 503);
  }
  const user = usernameError(username) ? null : await store.findUserByUsername(username);
  if (!user) {
    await verifyPassword(password, await dummyPasswordHash());
    throw new AccountError(INVALID, 401);
  }
  if (isLocked(user.lockedUntil, now)) throw new AccountError(lockedMessage(user.lockedUntil!, now), 429);
  if (!(await verifyPassword(password, user.passwordHash))) {
    const lockedUntil = lockoutAfter(await store.incrementFailedAttempts(user.id, now), now);
    if (lockedUntil) {
      await store.updateUser(user.id, { failedAttempts: 0, lockedUntil });
      throw new AccountError(lockedMessage(lockedUntil, now, true), 429);
    }
    throw new AccountError(INVALID, 401);
  }
  // Checked after the password so the account's state is not revealed to someone without it.
  if (user.disabled) throw new AccountError("This account is disabled. Ask an administrator to enable it.", 403);
  releaseAttempt(byIp, ip);
  byUser.delete(username);

  const token = newSessionToken();
  const expiresAt = new Date(now.getTime() + SESSION_TTL_MS);
  await store.insertSession({
    tokenHash: hashSessionToken(token),
    userId: user.id,
    createdAt: now,
    expiresAt,
    lastSeenAt: now,
    userAgent: (safeHeader("user-agent") ?? "").slice(0, 300) || null,
    ip: ip === "unknown" ? null : ip,
  });
  await store.updateUser(user.id, { failedAttempts: 0, lockedUntil: null, lastLoginAt: now });
  writeSessionCookie(token);
  console.info(`[accounts] ${user.username} signed in (${store.kind})`);
  return { user: toPublicAccount({ ...user, failedAttempts: 0, lockedUntil: null, lastLoginAt: now }), token, expiresAt: expiresAt.toISOString() };
}

function safeHeader(name: "user-agent"): string | undefined {
  try {
    return getRequestHeader(name);
  } catch {
    return undefined;
  }
}

export async function signOutPassword(embeddedToken?: string | null): Promise<void> {
  const token = requestSessionToken(embeddedToken);
  clearSessionCookie();
  if (!token) return;
  const tokenHash = hashSessionToken(token);
  sessionCache().delete(tokenHash);
  try {
    const store = await withTimeout(ensureAccountsReady(), STORE_TIMEOUT_MS, "The account store did not respond.");
    await store.deleteSession(tokenHash);
  } catch (err) {
    console.warn("[accounts] sign-out could not delete the session:", err instanceof Error ? err.message : err);
  }
}

// ---------------------------------------------------------------------------
// Own account
// ---------------------------------------------------------------------------

export async function changeOwnPassword(
  user: UserRecord,
  embeddedToken: string | null | undefined,
  input: { currentPassword: string; newPassword: string },
): Promise<{ revokedSessions: number }> {
  const store = await ensureAccountsReady();
  const fresh = await store.findUserById(user.id);
  if (!fresh) throw new AccountError("Your account no longer exists.", 404);
  if (!(await verifyPassword(input.currentPassword, fresh.passwordHash))) throw new AccountError("The current password is incorrect.", 400);
  const problem = passwordError(input.newPassword, fresh.username);
  if (problem) throw new AccountError(problem, 400);
  if (await verifyPassword(input.newPassword, fresh.passwordHash)) throw new AccountError("Choose a password different from the current one.", 400);
  const now = new Date();
  await store.updateUser(fresh.id, { passwordHash: await hashPassword(input.newPassword), weakPassword: false, passwordChangedAt: now, failedAttempts: 0, lockedUntil: null });
  const token = requestSessionToken(embeddedToken);
  const revokedSessions = await store.deleteUserSessions(fresh.id, token ? hashSessionToken(token) : undefined);
  invalidateSessionCache(fresh.id);
  console.info(`[accounts] ${fresh.username} changed their password; ${revokedSessions} other session(s) signed out`);
  return { revokedSessions };
}

// ---------------------------------------------------------------------------
// Administration
// ---------------------------------------------------------------------------

export type AdminAccountRow = PublicAccount & { activeSessions: number };

export async function listAccounts(): Promise<AdminAccountRow[]> {
  const store = await ensureAccountsReady();
  const users = await store.listUsers();
  const now = new Date();
  return Promise.all(users.map(async (u) => ({ ...toPublicAccount(u), activeSessions: await store.countActiveSessions(u.id, now) })));
}

export async function createAccount(
  by: string,
  input: { username: string; displayName?: string; email?: string | null; role: AccountRole; password: string },
): Promise<PublicAccount> {
  const username = normalizeUsername(input.username);
  const badName = usernameError(username);
  if (badName) throw new AccountError(`Username: ${badName}`);
  const badPassword = passwordError(input.password, username);
  if (badPassword) throw new AccountError(`Password: ${badPassword}`);
  const store = await ensureAccountsReady();
  const now = new Date();
  const record: UserRecord = {
    id: newAccountId(),
    username,
    displayName: input.displayName?.trim() || username,
    email: input.email?.trim().toLowerCase() || null,
    role: input.role,
    passwordHash: await hashPassword(input.password),
    bootstrapHash: null,
    weakPassword: false,
    disabled: false,
    failedAttempts: 0,
    lockedUntil: null,
    createdAt: now,
    updatedAt: now,
    lastLoginAt: null,
    passwordChangedAt: now,
    createdBy: by,
  };
  try {
    await store.insertUser(record);
  } catch (err) {
    if (err instanceof DuplicateUsernameError) throw new AccountError(err.message, 409);
    throw err;
  }
  console.info(`[accounts] ${by} created ${record.role} "${username}"`);
  return toPublicAccount(record);
}

async function otherEnabledAdmins(store: AccountsStore, exceptId: string): Promise<number> {
  return (await store.listUsers()).filter((u) => u.id !== exceptId && u.role === "admin" && !u.disabled).length;
}

export async function updateAccount(
  actor: { id: string; username: string },
  id: string,
  input: { displayName?: string; email?: string | null; role?: AccountRole; disabled?: boolean; unlock?: boolean; password?: string },
): Promise<PublicAccount> {
  const store = await ensureAccountsReady();
  const user = await store.findUserById(id);
  if (!user) throw new AccountError("That account no longer exists.", 404);
  const self = user.id === actor.id;
  if (self && (input.role === "analyst" || input.disabled === true)) throw new AccountError("You cannot demote or disable your own account.", 400);
  const losesAdmin = user.role === "admin" && !user.disabled && (input.role === "analyst" || input.disabled === true);
  if (losesAdmin && (await otherEnabledAdmins(store, user.id)) === 0) throw new AccountError("Keep at least one enabled administrator.", 400);

  const patch: UserPatch = {};
  if (input.displayName !== undefined) patch.displayName = input.displayName.trim() || user.username;
  if (input.email !== undefined) patch.email = input.email?.trim().toLowerCase() || null;
  if (input.role !== undefined) patch.role = input.role;
  if (input.disabled !== undefined) patch.disabled = input.disabled;
  if (input.unlock) {
    patch.failedAttempts = 0;
    patch.lockedUntil = null;
  }
  let revoke = input.disabled === true;
  if (input.password !== undefined) {
    const problem = passwordError(input.password, user.username);
    if (problem) throw new AccountError(`Password: ${problem}`);
    patch.passwordHash = await hashPassword(input.password);
    patch.weakPassword = false;
    patch.passwordChangedAt = new Date();
    patch.failedAttempts = 0;
    patch.lockedUntil = null;
    revoke = revoke || !self;
  }
  await store.updateUser(user.id, patch);
  if (revoke) await store.deleteUserSessions(user.id);
  invalidateSessionCache(user.id);
  console.info(`[accounts] ${actor.username} updated "${user.username}" (${Object.keys(patch).filter((k) => k !== "passwordHash").join(", ") || "password"})`);
  const updated = await store.findUserById(user.id);
  return toPublicAccount(updated ?? { ...user, ...patch });
}

export async function deleteAccount(actor: { id: string; username: string }, id: string): Promise<void> {
  const store = await ensureAccountsReady();
  const user = await store.findUserById(id);
  if (!user) return;
  if (user.id === actor.id) throw new AccountError("You cannot delete your own account.", 400);
  if (user.role === "admin" && !user.disabled && (await otherEnabledAdmins(store, user.id)) === 0) throw new AccountError("Keep at least one enabled administrator.", 400);
  await store.deleteUser(user.id);
  invalidateSessionCache(user.id);
  console.info(`[accounts] ${actor.username} deleted "${user.username}"`);
}

/** A plain-language message for errors thrown to the browser. */
export function accountErrorMessage(err: unknown): string {
  if (err instanceof AccountError) return err.message;
  return storeError(err);
}
