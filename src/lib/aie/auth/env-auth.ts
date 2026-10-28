/**
 * Sign-in with one username and password set in the server environment, and the signed cookie
 * that keeps the browser signed in.
 *
 *   AIE_ADMIN_USERNAME, AIE_ADMIN_PASSWORD   the credentials (required; sign-in is refused without)
 *   AIE_SESSION_SECRET                       signs the cookie (32+ characters). Without it a random
 *                                            secret is made at start, so sessions end on restart.
 *   AIE_SESSION_DAYS                         how long a sign-in lasts (default 7)
 *
 * The cookie holds the username, issue and expiry times and a fingerprint of the password, signed
 * with HMAC-SHA256. Nothing is stored server-side, so checking it needs no database and no network.
 * Changing the password or the secret signs every browser out. The fingerprint is keyed by the
 * secret, so a stolen cookie reveals nothing about the password.
 *
 * Pure: Node crypto only, no request or environment access. Unit-tested in env-auth.test.ts.
 */
import { createHmac, timingSafeEqual } from "node:crypto";

export const SESSION_COOKIE = "aie_session";
const VERSION = 1;

export type SessionClaims = { v: number; u: string; iat: number; exp: number; pv: string };

function b64url(buf: Buffer | string): string {
  return Buffer.from(buf).toString("base64url");
}

function hmac(secret: string, data: string): Buffer {
  return createHmac("sha256", secret).update(data).digest();
}

/** Equal-time comparison of two strings of any length (lengths are hidden behind an HMAC). */
export function safeEqual(a: string, b: string): boolean {
  const key = "aie-compare";
  return timingSafeEqual(hmac(key, a), hmac(key, b));
}

/** Fingerprint of the configured password; changes when the password changes. */
export function passwordFingerprint(secret: string, password: string): string {
  return b64url(hmac(secret, `pw:${password}`)).slice(0, 22);
}

export type Credentials = { username: string; password: string };

/** True when both match the configured credentials. Usernames compare case-insensitively. */
export function checkCredentials(given: Credentials, expected: Credentials): boolean {
  const userOk = safeEqual(given.username.trim().toLowerCase(), expected.username.trim().toLowerCase());
  const passOk = safeEqual(given.password, expected.password);
  return userOk && passOk;
}

export function signSession(claims: Omit<SessionClaims, "v">, secret: string): string {
  const body = b64url(JSON.stringify({ v: VERSION, ...claims }));
  return `${body}.${b64url(hmac(secret, body))}`;
}

/**
 * The claims of a valid, unexpired token for the expected user and password, otherwise null.
 * `now` is in seconds.
 */
export function verifySession(token: string | undefined | null, secret: string, expected: { username: string; fingerprint: string }, now: number): SessionClaims | null {
  if (!token || token.length > 2048) return null;
  const dot = token.indexOf(".");
  if (dot <= 0) return null;
  const body = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  if (!safeEqual(sig, b64url(hmac(secret, body)))) return null;
  let claims: SessionClaims;
  try {
    claims = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch {
    return null;
  }
  if (claims?.v !== VERSION || typeof claims.u !== "string" || typeof claims.exp !== "number") return null;
  if (claims.exp <= now) return null;
  if (claims.u.toLowerCase() !== expected.username.trim().toLowerCase()) return null;
  if (!safeEqual(String(claims.pv ?? ""), expected.fingerprint)) return null;
  return claims;
}

/**
 * Failed sign-ins per client: after `max` failures within `windowMs`, further attempts are refused
 * until the window passes. In memory (one server process).
 */
export class SignInLimiter {
  private readonly failures = new Map<string, number[]>();
  private readonly max: number;
  private readonly windowMs: number;
  constructor(max = 8, windowMs = 15 * 60_000) {
    this.max = max;
    this.windowMs = windowMs;
  }

  private recent(key: string, now: number): number[] {
    const list = (this.failures.get(key) ?? []).filter((t) => now - t < this.windowMs);
    if (list.length) this.failures.set(key, list);
    else this.failures.delete(key);
    return list;
  }

  /** Milliseconds until the client may try again, or 0. */
  retryAfter(key: string, now = Date.now()): number {
    const list = this.recent(key, now);
    return list.length >= this.max ? this.windowMs - (now - list[0]) : 0;
  }

  fail(key: string, now = Date.now()): void {
    const list = this.recent(key, now);
    list.push(now);
    this.failures.set(key, list);
    // Bound memory under a flood of distinct clients.
    if (this.failures.size > 10_000) this.failures.delete(this.failures.keys().next().value as string);
  }

  succeed(key: string): void {
    this.failures.delete(key);
  }
}
