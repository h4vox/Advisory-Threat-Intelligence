import { test } from "node:test";
import assert from "node:assert/strict";
import { SignInLimiter, checkCredentials, passwordFingerprint, safeEqual, signSession, verifySession } from "./env-auth.ts";

const secret = "s".repeat(40);
const expected = { username: "havox", fingerprint: passwordFingerprint(secret, "correct horse") };
const now = 1_800_000_000;
const token = () => signSession({ u: "havox", iat: now, exp: now + 3600, pv: expected.fingerprint }, secret);

test("credentials: exact password, case-insensitive username", () => {
  const exp = { username: "Havox", password: "correct horse" };
  assert.equal(checkCredentials({ username: "havox", password: "correct horse" }, exp), true);
  assert.equal(checkCredentials({ username: " HAVOX ", password: "correct horse" }, exp), true);
  assert.equal(checkCredentials({ username: "havox", password: "Correct horse" }, exp), false);
  assert.equal(checkCredentials({ username: "other", password: "correct horse" }, exp), false);
  assert.equal(checkCredentials({ username: "havox", password: "" }, exp), false);
});

test("safeEqual compares any lengths", () => {
  assert.equal(safeEqual("a", "a"), true);
  assert.equal(safeEqual("a", "ab"), false);
  assert.equal(safeEqual("", ""), true);
});

test("a signed session verifies until it expires", () => {
  assert.equal(verifySession(token(), secret, expected, now)?.u, "havox");
  assert.equal(verifySession(token(), secret, expected, now + 3600), null);
});

test("tampered, wrongly signed or malformed tokens are refused", () => {
  const t = token();
  const [body, sig] = t.split(".");
  const forged = Buffer.from(JSON.stringify({ v: 1, u: "havox", iat: now, exp: now + 99999999, pv: expected.fingerprint })).toString("base64url");
  assert.equal(verifySession(`${forged}.${sig}`, secret, expected, now), null);
  assert.equal(verifySession(t, "x".repeat(40), expected, now), null);
  assert.equal(verifySession(`${body}.`, secret, expected, now), null);
  assert.equal(verifySession("nonsense", secret, expected, now), null);
  assert.equal(verifySession("", secret, expected, now), null);
  assert.equal(verifySession(undefined, secret, expected, now), null);
  assert.equal(verifySession("a".repeat(5000), secret, expected, now), null);
});

test("changing the password or the username signs browsers out", () => {
  const t = token();
  assert.equal(verifySession(t, secret, { username: "havox", fingerprint: passwordFingerprint(secret, "new password") }, now), null);
  assert.equal(verifySession(t, secret, { username: "someone", fingerprint: expected.fingerprint }, now), null);
});

test("the password fingerprint depends on the secret", () => {
  assert.notEqual(passwordFingerprint(secret, "p"), passwordFingerprint("y".repeat(40), "p"));
});

test("limiter: refuses after repeated failures, resets on success and after the window", () => {
  const l = new SignInLimiter(3, 1000);
  assert.equal(l.retryAfter("ip", 0), 0);
  l.fail("ip", 0);
  l.fail("ip", 10);
  l.fail("ip", 20);
  assert.ok(l.retryAfter("ip", 30) > 0);
  assert.equal(l.retryAfter("ip", 1001), 0, "window passed for the first failure");
  l.fail("ip2", 0);
  l.succeed("ip2");
  assert.equal(l.retryAfter("ip2", 1), 0);
});
