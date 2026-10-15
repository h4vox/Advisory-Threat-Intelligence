import { test } from "node:test";
import assert from "node:assert/strict";
import { isEmailAllowed } from "./access-policy.ts";

test("no allowlist: allowed in development, refused in production", () => {
  assert.equal(isEmailAllowed("a@b.com", { production: false }), true);
  assert.equal(isEmailAllowed("a@b.com", { production: true }), false);
});

test("explicit email match is case-insensitive", () => {
  const env = { emails: " Analyst@Scybers.com ,x@y.io", production: true };
  assert.equal(isEmailAllowed("analyst@scybers.com", env), true);
  assert.equal(isEmailAllowed("other@scybers.com", env), false);
});

test("domain match requires the exact domain, not a suffix", () => {
  const env = { domains: "@scybers.com", production: true };
  assert.equal(isEmailAllowed("anyone@scybers.com", env), true);
  assert.equal(isEmailAllowed("evil@notscybers.com", env), false);
  assert.equal(isEmailAllowed("evil@scybers.com.attacker.io", env), false);
});

test("missing or malformed email is refused when a list exists", () => {
  const env = { domains: "scybers.com", production: false };
  assert.equal(isEmailAllowed(null, env), false);
  assert.equal(isEmailAllowed("scybers.com", env), false);
});
