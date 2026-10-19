import { test } from "node:test";
import assert from "node:assert/strict";
import {
  LOCKOUT_MAX_FAILURES,
  LOCKOUT_MS,
  isLocked,
  isWeakPassword,
  lockoutAfter,
  normalizeUsername,
  passwordError,
  releaseAttempt,
  reserveAttempt,
  usernameError,
  type AttemptWindow,
} from "./policy.ts";
import {
  dummyPasswordHash,
  hashPassword,
  hashSessionToken,
  looksLikeSessionToken,
  newAccountId,
  newSessionToken,
  verifyPassword,
} from "./password.server.ts";

test("usernames: normalised to lowercase, 3–64 safe characters", () => {
  assert.equal(normalizeUsername("  HaVox "), "havox");
  assert.equal(usernameError("havox"), null);
  assert.equal(usernameError("j.doe-2_x"), null);
  assert.match(usernameError("ab") ?? "", /at least 3/);
  assert.match(usernameError("a".repeat(65)) ?? "", /at most 64/);
  for (const bad of [".havox", "havox.", "ha vox", "havox@corp", "Havox", "-x-"]) assert.ok(usernameError(bad), bad);
});

test("password policy for passwords set in the app", () => {
  assert.equal(passwordError("correct horse"), null);
  assert.match(passwordError("1234") ?? "", /at least 8/);
  assert.match(passwordError("        ") ?? "", /only spaces/);
  assert.match(passwordError("Analyst01", "analyst01") ?? "", /username/);
  assert.match(passwordError("x".repeat(257)) ?? "", /at most 256/);
  assert.equal(isWeakPassword("1234"), true);
  assert.equal(isWeakPassword("12345678"), false);
});

test("lockout: the fifth failure locks for 15 minutes", () => {
  const now = new Date("2026-10-17T10:00:00Z");
  for (let i = 1; i < LOCKOUT_MAX_FAILURES; i++) assert.equal(lockoutAfter(i, now), null);
  const until = lockoutAfter(LOCKOUT_MAX_FAILURES, now);
  assert.equal(until?.getTime(), now.getTime() + LOCKOUT_MS);
  // Concurrent failures can push the atomic counter past the limit; they still lock.
  assert.ok(lockoutAfter(LOCKOUT_MAX_FAILURES + 3, now));
  assert.equal(isLocked(until, now), true);
  assert.equal(isLocked(until, new Date(now.getTime() + LOCKOUT_MS + 1)), false);
  assert.equal(isLocked(null, now), false);
  assert.equal(isLocked(until!.toISOString(), now), true);
});

test("attempt windows: a parallel burst is cut off at the limit; successes give their attempt back", () => {
  const windows = new Map<string, AttemptWindow>();
  const now = 1_000_000;
  // Ten guesses reserved in the same tick (before any of them is checked): only five get through.
  const admitted = Array.from({ length: 10 }, () => reserveAttempt(windows, "havox", 5, LOCKOUT_MS, now)).filter(Boolean).length;
  assert.equal(admitted, 5);
  releaseAttempt(windows, "havox");
  assert.equal(reserveAttempt(windows, "havox", 5, LOCKOUT_MS, now + 1), true);
  assert.equal(reserveAttempt(windows, "havox", 5, LOCKOUT_MS, now + 2), false);
  // The window resets after it expires.
  assert.equal(reserveAttempt(windows, "havox", 5, LOCKOUT_MS, now + LOCKOUT_MS + 1), true);
  assert.equal(windows.get("havox")?.count, 1);
  // Keys are independent.
  assert.equal(reserveAttempt(windows, "other", 5, LOCKOUT_MS, now), true);
});

test("scrypt hashes verify the right password only, with a fresh salt each time", async () => {
  const a = await hashPassword("1234");
  const b = await hashPassword("1234");
  assert.match(a, /^scrypt\$16384\$8\$1\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$/);
  assert.notEqual(a, b);
  assert.equal(await verifyPassword("1234", a), true);
  assert.equal(await verifyPassword("1235", a), false);
  assert.equal(await verifyPassword("", a), false);
  // Unicode passwords are normalised (NFKC) before hashing.
  const u = await hashPassword("páss");
  assert.equal(await verifyPassword("páss", u), true);
});

test("malformed or out-of-bounds hashes never verify (and never allocate huge scrypt memory)", async () => {
  const good = await hashPassword("secret-pass");
  const [, , , , salt, key] = good.split("$");
  for (const bad of [
    "",
    "plain",
    "bcrypt$10$abc",
    `scrypt$16384$8$1$${salt}`,
    `scrypt$1048576$8$1$${salt}$${key}`, // N too large
    `scrypt$16383$8$1$${salt}$${key}`, // not a power of two
    `scrypt$16384$64$1$${salt}$${key}`, // r too large
    `scrypt$16384$8$1$${salt}$AAAA`, // key too short
  ]) {
    assert.equal(await verifyPassword("secret-pass", bad), false, bad);
  }
});

test("dummy hash is a real, reusable scrypt hash", async () => {
  const d = await dummyPasswordHash();
  assert.equal(d, await dummyPasswordHash());
  assert.equal(await verifyPassword("anything", d), false);
});

test("session tokens: 32 random bytes, stored only as SHA-256", () => {
  const t = newSessionToken();
  assert.equal(looksLikeSessionToken(t), true);
  assert.notEqual(t, newSessionToken());
  assert.match(hashSessionToken(t), /^[0-9a-f]{64}$/);
  assert.equal(hashSessionToken(t), hashSessionToken(t));
  assert.equal(looksLikeSessionToken("short"), false);
  assert.equal(looksLikeSessionToken(`${t}x`), false);
  assert.equal(looksLikeSessionToken(null), false);
  assert.match(newAccountId(), /^usr_[0-9a-f]{24}$/);
});

test("email detection, normalization and username derivation for dev credentials", async () => {
  const { looksLikeEmail, normalizeEmail, usernameFromEmail } = await import("./policy.ts");
  assert.equal(looksLikeEmail("Dev.User@Example.com"), true);
  assert.equal(looksLikeEmail("havox"), false);
  assert.equal(looksLikeEmail("a@b"), false);
  assert.equal(looksLikeEmail("a @b.com"), false);
  assert.equal(normalizeEmail("  Dev.User@Example.COM "), "dev.user@example.com");
  assert.equal(usernameFromEmail("Jane.Doe@corp.io"), "jane.doe");
  assert.equal(usernameFromEmail("a@corp.io"), "devuser"); // local part too short for a username
  assert.equal(usernameFromEmail("_weird_@corp.io"), "weird");
});
