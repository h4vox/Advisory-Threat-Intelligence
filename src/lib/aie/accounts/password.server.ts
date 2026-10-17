/**
 * Password hashing and session tokens (server-only).
 *
 * Hashes are scrypt (N=2^14, r=8, p=1, 64-byte key, 16-byte salt) in the self-describing form
 * `scrypt$N$r$p$salt$key` (base64url), compared in constant time. Session tokens are 32 random
 * bytes; only their SHA-256 is stored, so a database leak does not leak usable sessions.
 */
import { createHash, randomBytes, scrypt, timingSafeEqual, type ScryptOptions } from "node:crypto";

const N = 16384;
const R = 8;
const P = 1;
const KEY_LENGTH = 64;

function derive(password: string, salt: Buffer, keyLength: number, options: ScryptOptions): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password.normalize("NFKC"), salt, keyLength, options, (err, key) => (err ? reject(err) : resolve(key)));
  });
}

/** Memory scrypt needs for these parameters, with headroom (Node refuses above `maxmem`). */
function maxmem(n: number, r: number, p: number): number {
  return 128 * n * r * 2 + 128 * r * p + 1024 * 1024;
}

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const key = await derive(password, salt, KEY_LENGTH, { N, r: R, p: P, maxmem: maxmem(N, R, P) });
  return `scrypt$${N}$${R}$${P}$${salt.toString("base64url")}$${key.toString("base64url")}`;
}

/** False for a wrong password and for anything that is not a well-formed hash this code would produce. */
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;
  const n = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  // Bounded so a tampered record cannot make verification allocate gigabytes.
  if (!Number.isInteger(n) || n < 1024 || n > 131072 || (n & (n - 1)) !== 0) return false;
  if (!Number.isInteger(r) || r < 1 || r > 16 || !Number.isInteger(p) || p < 1 || p > 4) return false;
  const salt = Buffer.from(parts[4], "base64url");
  const expected = Buffer.from(parts[5], "base64url");
  if (salt.length < 8 || expected.length < 16 || expected.length > 128) return false;
  const key = await derive(password, salt, expected.length, { N: n, r, p, maxmem: maxmem(n, r, p) });
  return timingSafeEqual(key, expected);
}

const g = globalThis as typeof globalThis & { __aieDummyHash__?: Promise<string> };

/** A real hash of a random secret: verified against for unknown usernames so response time does not reveal which usernames exist. */
export function dummyPasswordHash(): Promise<string> {
  g.__aieDummyHash__ ??= hashPassword(randomBytes(18).toString("base64url"));
  return g.__aieDummyHash__;
}

export function newSessionToken(): string {
  return randomBytes(32).toString("base64url");
}

export function hashSessionToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/** Session tokens are 43 base64url characters; anything else is not worth a database lookup. */
export function looksLikeSessionToken(token: unknown): token is string {
  return typeof token === "string" && /^[A-Za-z0-9_-]{43}$/.test(token);
}

export function newAccountId(): string {
  return `usr_${randomBytes(12).toString("hex")}`;
}
