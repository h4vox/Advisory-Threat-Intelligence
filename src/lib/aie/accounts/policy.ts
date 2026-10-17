/**
 * Account rules shared by the server and the forms: usernames, password policy, lockout and session
 * lifetime. Pure; safe to import from components and unit tests.
 */

/** 3–64 characters: lowercase letters, digits, dot, dash, underscore; starts and ends alphanumeric. */
const USERNAME_PATTERN = /^[a-z0-9](?:[a-z0-9._-]{1,62})[a-z0-9]$/;

export const DEFAULT_ADMIN_USERNAME = "havox";
export const PASSWORD_MIN_LENGTH = 8;
export const PASSWORD_MAX_LENGTH = 256;

/** Failed sign-ins before an account is locked, and for how long. */
export const LOCKOUT_MAX_FAILURES = 5;
export const LOCKOUT_MS = 15 * 60_000;

/** Failed sign-ins from one address before it is refused for the rest of the window. */
export const IP_MAX_FAILURES = 30;
export const IP_WINDOW_MS = 15 * 60_000;

export const SESSION_TTL_MS = 7 * 24 * 60 * 60_000;

export function normalizeUsername(raw: string): string {
  return raw.trim().toLowerCase();
}

export function usernameError(username: string): string | null {
  if (username.length < 3) return "Use at least 3 characters.";
  if (username.length > 64) return "Use at most 64 characters.";
  if (!USERNAME_PATTERN.test(username)) return "Use lowercase letters, digits, dots, dashes or underscores, starting and ending with a letter or digit.";
  return null;
}

/** Policy for passwords set in the app. The bootstrap administrator password comes from the environment and is only flagged when weak. */
export function passwordError(password: string, username?: string): string | null {
  if (password.length < PASSWORD_MIN_LENGTH) return `Use at least ${PASSWORD_MIN_LENGTH} characters.`;
  if (password.length > PASSWORD_MAX_LENGTH) return `Use at most ${PASSWORD_MAX_LENGTH} characters.`;
  if (!password.trim()) return "The password cannot be only spaces.";
  if (username && password.trim().toLowerCase() === username.toLowerCase()) return "The password cannot be the username.";
  return null;
}

export function isWeakPassword(password: string): boolean {
  return password.length < PASSWORD_MIN_LENGTH;
}

export function isLocked(lockedUntil: Date | string | null | undefined, now: Date): boolean {
  if (!lockedUntil) return false;
  const t = typeof lockedUntil === "string" ? Date.parse(lockedUntil) : lockedUntil.getTime();
  return Number.isFinite(t) && t > now.getTime();
}

/** The lock to apply once an account's failed sign-ins reach the limit (the counter then restarts), else null. */
export function lockoutAfter(failedAttempts: number, now: Date): Date | null {
  return failedAttempts >= LOCKOUT_MAX_FAILURES ? new Date(now.getTime() + LOCKOUT_MS) : null;
}

export type AttemptWindow = { count: number; resetAt: number };

/**
 * Reserves one sign-in attempt in a fixed window, synchronously (call it before any await, so a
 * burst of parallel requests cannot all pass the check). Returns false when the window is full.
 */
export function reserveAttempt(windows: Map<string, AttemptWindow>, key: string, max: number, windowMs: number, now: number): boolean {
  const w = windows.get(key);
  if (!w || w.resetAt <= now) {
    windows.set(key, { count: 1, resetAt: now + windowMs });
    if (windows.size > 5000) for (const [k, v] of windows) if (v.resetAt <= now) windows.delete(k);
    return true;
  }
  if (w.count >= max) return false;
  w.count += 1;
  return true;
}

/** Gives back a reserved attempt (it succeeded, so it is not a failure). */
export function releaseAttempt(windows: Map<string, AttemptWindow>, key: string): void {
  const w = windows.get(key);
  if (w && w.count > 0) w.count -= 1;
}

export function minutesUntil(when: Date | string, now: Date): number {
  const t = typeof when === "string" ? Date.parse(when) : when.getTime();
  return Math.max(1, Math.ceil((t - now.getTime()) / 60_000));
}
