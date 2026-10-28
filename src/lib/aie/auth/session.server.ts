/**
 * The signed-in user of the current request, from the session cookie (./env-auth).
 * Server-only: reads the request through @tanstack/react-start/server.
 */
import { randomBytes } from "node:crypto";
import { getCookie, getRequestIP } from "@tanstack/react-start/server";
import { SESSION_COOKIE, passwordFingerprint, signSession, verifySession } from "./env-auth";
import type { RequestIdentity } from "../accounts/types";

export class UnauthorizedError extends Error {
  readonly status = 401;
  constructor() {
    super("Unauthorized");
    this.name = "UnauthorizedError";
  }
}

export type AuthUser = {
  /** Stable id that keys per-user data (AI chat history). */
  id: string;
  username: string;
  displayName: string;
  role: "admin";
};

const g = globalThis as typeof globalThis & { __aieSessionSecret__?: string; __aieUserIds__?: Map<string, string> };

function env(key: string): string | undefined {
  const v = process.env[key]?.trim();
  return v ? v : undefined;
}

export type AuthConfig = { username: string; password: string; secret: string; maxAgeSeconds: number };

/** The configured credentials, or null when AIE_ADMIN_USERNAME / AIE_ADMIN_PASSWORD are not set. */
export function authConfig(): AuthConfig | null {
  const username = env("AIE_ADMIN_USERNAME");
  // The password is used exactly as written (no trimming): spaces may be part of it.
  const password = process.env.AIE_ADMIN_PASSWORD ?? "";
  if (!username || !password) return null;
  let secret = env("AIE_SESSION_SECRET");
  if (!secret || secret.length < 32) {
    if (!g.__aieSessionSecret__) {
      g.__aieSessionSecret__ = randomBytes(48).toString("base64url");
      console.warn("[auth] AIE_SESSION_SECRET is not set (or shorter than 32 characters): using a random secret, so sign-ins end when the server restarts.");
    }
    secret = g.__aieSessionSecret__;
  }
  const days = Number(env("AIE_SESSION_DAYS") ?? 7);
  const maxAgeSeconds = Math.round((Number.isFinite(days) && days > 0 ? Math.min(days, 90) : 7) * 86_400);
  return { username, password, secret, maxAgeSeconds };
}

/**
 * The id that keys this user's data. Reuses the id of an existing account with the same username
 * (from the earlier account system), so AI chat history stays visible; otherwise a stable id.
 */
async function userIdFor(username: string): Promise<string> {
  const key = username.toLowerCase();
  const ids = (g.__aieUserIds__ ??= new Map());
  const known = ids.get(key);
  if (known) return known;
  const fallback = `user:${key}`;
  const TIMED_OUT = Symbol("timeout");
  try {
    const { isMongoConfigured, getMongoDb } = await import("../../mongodb/client.server");
    if (!isMongoConfigured()) {
      ids.set(key, fallback);
      return fallback;
    }
    const lookup = getMongoDb()
      .then((db) => db.collection("aie_users").findOne({ username: key }, { projection: { _id: 0, id: 1 } }))
      .then((doc) => (typeof doc?.id === "string" ? doc.id : fallback));
    const id = await Promise.race([lookup, new Promise<typeof TIMED_OUT>((r) => setTimeout(() => r(TIMED_OUT), 3000))]);
    // A slow database is asked again next time; a definite answer is remembered.
    if (id === TIMED_OUT) return fallback;
    ids.set(key, id);
    return id;
  } catch {
    return fallback;
  }
}

/** The signed-in user of this request, or null. No database or network access in the common case. */
export async function currentUser(): Promise<AuthUser | null> {
  const cfg = authConfig();
  if (!cfg) return null;
  const claims = verifySession(getCookie(SESSION_COOKIE), cfg.secret, { username: cfg.username, fingerprint: passwordFingerprint(cfg.secret, cfg.password) }, Math.floor(Date.now() / 1000));
  if (!claims) return null;
  return userFor(cfg);
}

/** The configured user. */
export async function userFor(cfg: AuthConfig): Promise<AuthUser> {
  return { id: await userIdFor(cfg.username), username: cfg.username, displayName: cfg.username, role: "admin" };
}

export function identityOf(user: AuthUser): RequestIdentity {
  return { method: "password", username: user.username, displayName: user.displayName, role: user.role };
}

/** A Set-Cookie header value for a new session (for server routes that answer with a Response). */
export function sessionCookieHeader(cfg: AuthConfig, secure: boolean): string {
  const now = Math.floor(Date.now() / 1000);
  const token = signSession({ u: cfg.username, iat: now, exp: now + cfg.maxAgeSeconds, pv: passwordFingerprint(cfg.secret, cfg.password) }, cfg.secret);
  return `${SESSION_COOKIE}=${token}; Path=/; Max-Age=${cfg.maxAgeSeconds}; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`;
}

/** A Set-Cookie header value that ends the session. */
export function clearedCookieHeader(secure: boolean): string {
  return `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`;
}

/** HTTPS as the browser sees it, for a given request (directly, or through a reverse proxy that says so). */
export function requestIsHttps(request: Request): boolean {
  const proto = request.headers.get("x-forwarded-proto")?.split(",")[0]?.trim().toLowerCase();
  if (proto) return proto === "https";
  try {
    return new URL(request.url).protocol === "https:";
  } catch {
    return false;
  }
}

const LOOPBACK = /^(?:127\.\d+\.\d+\.\d+|::1|::ffff:127\.\d+\.\d+\.\d+)$/;

/**
 * The client address, for sign-in rate limiting. X-Forwarded-For is only believed when the
 * connection comes from this machine (a reverse proxy on the same host) or AIE_TRUST_PROXY=1;
 * otherwise a client could change it at will and dodge the limit.
 */
export function clientAddress(request: Request): string {
  const peer = (() => {
    try {
      return getRequestIP() ?? "";
    } catch {
      return "";
    }
  })();
  const trustProxy = process.env.AIE_TRUST_PROXY?.trim() === "1" || LOOPBACK.test(peer);
  if (trustProxy) {
    const forwarded = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || request.headers.get("x-real-ip")?.trim();
    if (forwarded) return forwarded;
  }
  return peer || "unknown";
}
