import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  AgyLoginSession,
  extractAuthUrl,
  findErrorLine,
  isGoogleAuthUrl,
  normalizeAuthCode,
  parseLoginMenu,
  ptyChildTerminal,
  stripTerminal,
  type AgyLoginSnapshot,
  type AgyLoginState,
} from "./agy-login.ts";

const GOOD_URL =
  "https://accounts.google.com/o/oauth2/auth?access_type=offline&client_id=1071006060591-x.apps.googleusercontent.com" +
  "&code_challenge=abc&code_challenge_method=S256&redirect_uri=https%3A%2F%2Fantigravity.google%2Foauth-callback&response_type=code&scope=openid&state=s";

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

test("stripTerminal removes colour, cursor, OSC sequences and turns redraws into lines", () => {
  const raw = "\x1b[2J\x1b[H\x1b[38;5;39mHello\x1b[0m\r\nA\rB\x1b]0;title\x07\x1b]8;;https://x\x1b\\link\x1b]8;;\x1b\\\x00";
  assert.equal(stripTerminal(raw), "Hello\nA\nBlink");
});

test("isGoogleAuthUrl accepts only genuine Google OAuth authorization URLs", () => {
  assert.equal(isGoogleAuthUrl(GOOD_URL), true);
  for (const bad of [
    GOOD_URL.replace("accounts.google.com", "accounts.google.com.evil.example"),
    GOOD_URL.replace("https://", "http://"),
    GOOD_URL.replace("https://accounts", "https://user@accounts"),
    GOOD_URL.replace("/o/oauth2/auth", "/signin"),
    GOOD_URL.replace(/client_id=[^&]+&/, ""),
    GOOD_URL.replace("response_type=code", "response_type=token"),
    "not a url",
  ]) {
    assert.equal(isGoogleAuthUrl(bad), false, bad);
  }
});

test("extractAuthUrl prefers the OSC 8 link target and re-joins a wrapped URL", () => {
  const osc8 = `junk \x1b]8;;${GOOD_URL}\x1b\\Click here\x1b]8;;\x1b\\`;
  assert.equal(extractAuthUrl(osc8), GOOD_URL);
  const wrapped = ` Your browser should open automatically. If not:\r\n\r\n ${GOOD_URL.slice(0, 90)}\r\n ${GOOD_URL.slice(90, 180)}\r\n ${GOOD_URL.slice(180)}\r\n\r\n Copy and paste the URL`;
  assert.equal(extractAuthUrl(wrapped), GOOD_URL);
  assert.equal(extractAuthUrl(wrapped.replace("accounts.google.com", "accounts.google.com.evil.example")), null);
  assert.equal(extractAuthUrl("nothing here"), null);
});

test("parseLoginMenu reads the last-drawn menu and finds Google OAuth", () => {
  const text = " Select login method:\n > 1. Google OAuth\n   2. Use a Google Cloud project\n\n   ↑/↓ Navigate · enter Select";
  assert.deepEqual(parseLoginMenu(text), { options: ["Google OAuth", "Use a Google Cloud project"], selected: 0, googleIndex: 0 });
  const second = " Select login method:\n ❯ 1. Use a Google Cloud project\n   2. Google OAuth\n";
  assert.deepEqual(parseLoginMenu(second), { options: ["Use a Google Cloud project", "Google OAuth"], selected: 0, googleIndex: 1 });
  assert.equal(parseLoginMenu("no menu"), null);
});

test("normalizeAuthCode accepts a code or a redirect URL and refuses anything that could inject keys", () => {
  assert.deepEqual(normalizeAuthCode("  4/0AVG-good-code_123  "), { ok: true, code: "4/0AVG-good-code_123" });
  assert.deepEqual(normalizeAuthCode("https://antigravity.google/oauth-callback?state=s&code=4%2F0AVG-abcDEF123&scope=x"), { ok: true, code: "4/0AVG-abcDEF123" });
  assert.deepEqual(normalizeAuthCode("4%2F0AVG-abcDEF123"), { ok: true, code: "4/0AVG-abcDEF123" });
  for (const bad of ["4/0AVG-abc\r\x1b[Bevil", "4/0AVG-abc\nrm -rf", "short", "4/0AVG abc def", "4/0AVG-\x03abcdefg", "x".repeat(600)]) {
    assert.equal(normalizeAuthCode(bad).ok, false, JSON.stringify(bad));
  }
});

test("findErrorLine reports CLI errors but not the paste prompt", () => {
  assert.equal(findErrorLine(" If you aren't automatically redirected, paste the authorization code below:"), null);
  assert.match(findErrorLine("⡿ Signing in...\nError: invalid_grant (Bad Request). Please try again.") ?? "", /invalid_grant/);
});

// ---------------------------------------------------------------------------
// End to end in a real pseudo-terminal, against a simulator of the CLI
// ---------------------------------------------------------------------------

const FAKE = fileURLToPath(new URL("./__fixtures__/fake-agy.mjs", import.meta.url));
const HAS_UTIL_LINUX_SCRIPT = (() => {
  const r = spawnSync("script", ["--version"], { encoding: "utf8" });
  return r.status === 0 && /util-linux/.test(r.stdout + r.stderr);
})();
const TIMINGS = { settleMs: 60, keyDelayMs: 30, alreadySignedInMs: 1500, signInSettleMs: 600, signInPollMs: 100, signInTimeoutMs: 8000, codeWaitMs: 20_000 };
const GOOD_CODE = "4/0AVG-good-code_123";

function session(mode: string, opts: { noOsc8?: boolean; verifyDelayMs?: number; signInMs?: number } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "agy-login-"));
  const stateFile = join(dir, "signed-in");
  if (mode === "signed_in") spawnSync("touch", [stateFile]);
  const env = { ...process.env, FAKE_AGY_MODE: mode, FAKE_AGY_STATE: stateFile, ...(opts.noOsc8 ? { FAKE_AGY_NO_OSC8: "1" } : {}), ...(opts.signInMs ? { FAKE_AGY_SIGNIN_MS: String(opts.signInMs) } : {}) };
  let child: ReturnType<typeof spawn> | null = null;
  const changes: AgyLoginState[] = [];
  const s = new AgyLoginSession({
    timings: TIMINGS,
    onChange: (snap) => changes.push(snap.state),
    spawn: () => {
      child = spawn("script", ["-qfec", `stty cols 1000 rows 50 2>/dev/null; exec node ${JSON.stringify(FAKE)}`, "/dev/null"], { env, stdio: ["pipe", "pipe", "pipe"] });
      return ptyChildTerminal(child as never);
    },
    // Stands in for "run a real prompt through the agent": passes once the CLI saved a sign-in.
    verify: async () => {
      await new Promise((r) => setTimeout(r, opts.verifyDelayMs ?? 50));
      return existsSync(stateFile) ? { ok: true, detail: "agent answered" } : { ok: false, detail: "not authenticated" };
    },
  });
  const cleanup = () => {
    s.cancel();
    (child as { kill?: (sig: string) => void } | null)?.kill?.("SIGKILL");
    rmSync(dir, { recursive: true, force: true });
  };
  return { s, cleanup, changes };
}

async function waitFor(s: AgyLoginSession, states: AgyLoginState[], ms = 8000): Promise<AgyLoginSnapshot> {
  const end = Date.now() + ms;
  for (;;) {
    const snap = s.snapshot();
    if (states.includes(snap.state)) return snap;
    if (Date.now() > end) throw new Error(`timed out in state "${snap.state}" waiting for ${states.join("/")}: ${snap.message}\n${snap.transcript.slice(-600)}`);
    await new Promise((r) => setTimeout(r, 40));
  }
}

const pty = { skip: HAS_UTIL_LINUX_SCRIPT ? false : "needs util-linux script(1) for a pseudo-terminal", timeout: 30_000 };

test("PTY: chooses Google OAuth, relays the CLI's own URL and code, verifies, never leaks the code", pty, async () => {
  const { s, cleanup } = session("login");
  try {
    s.start();
    const awaiting = await waitFor(s, ["awaiting_code", "failed"]);
    assert.equal(awaiting.state, "awaiting_code", awaiting.message);
    assert.ok(awaiting.authUrl && isGoogleAuthUrl(awaiting.authUrl));
    assert.match(awaiting.authUrl!, /client_id=1071006060591-/, "the CLI's client_id, not an app-built URL");
    assert.deepEqual(s.submitCode(GOOD_CODE), { ok: true });
    const done = await waitFor(s, ["signed_in", "failed"]);
    assert.equal(done.state, "signed_in", done.message);
    assert.equal(done.alreadySignedIn, false);
    assert.ok(!done.transcript.includes(GOOD_CODE), "authorization code is redacted from the transcript");
  } finally {
    cleanup();
  }
});

test("PTY: every state change is reported once, in order, ending in signed_in", pty, async () => {
  const { s, cleanup, changes } = session("login");
  try {
    s.start();
    await waitFor(s, ["awaiting_code", "failed"]);
    s.submitCode(GOOD_CODE);
    await waitFor(s, ["signed_in", "failed"]);
    const collapsed = changes.filter((st, i) => st !== changes[i - 1]);
    assert.deepEqual(collapsed.slice(0, 2), ["choosing_method", "awaiting_code"]);
    assert.equal(changes.at(-1), "signed_in");
    assert.ok(changes.includes("signing_in") && changes.includes("verifying"), changes.join(" > "));
  } finally {
    cleanup();
  }
});

test("PTY: navigates to Google OAuth when it is not the first option", pty, async () => {
  const { s, cleanup } = session("google_second");
  try {
    s.start();
    const snap = await waitFor(s, ["awaiting_code", "failed"]);
    assert.equal(snap.state, "awaiting_code", snap.message);
  } finally {
    cleanup();
  }
});

test("PTY: re-joins the URL the terminal wrapped when there is no hyperlink", pty, async () => {
  const { s, cleanup } = session("login", { noOsc8: true });
  try {
    s.start();
    const snap = await waitFor(s, ["awaiting_code", "failed"]);
    assert.equal(snap.state, "awaiting_code", snap.message);
    assert.ok(snap.authUrl && isGoogleAuthUrl(snap.authUrl), snap.authUrl ?? "no url");
  } finally {
    cleanup();
  }
});

test("PTY: a rejected code fails with the CLI's own error", pty, async () => {
  const { s, cleanup } = session("login");
  try {
    s.start();
    await waitFor(s, ["awaiting_code"]);
    assert.deepEqual(s.submitCode("4/0AVG-wrong-code_999"), { ok: true });
    const snap = await waitFor(s, ["failed", "signed_in"]);
    assert.equal(snap.state, "failed");
    assert.match(snap.message, /invalid_grant/);
  } finally {
    cleanup();
  }
});

test("PTY: an already signed-in CLI is detected and verified", pty, async () => {
  const { s, cleanup } = session("signed_in");
  try {
    s.start();
    const snap = await waitFor(s, ["signed_in", "failed"]);
    assert.equal(snap.state, "signed_in", snap.message);
    assert.equal(snap.alreadySignedIn, true);
  } finally {
    cleanup();
  }
});

test("PTY: a login menu that appears late abandons the 'already signed in' check", pty, async () => {
  // The menu shows at 2.5 s, after the 1.5 s startup check began; verification is slower than that.
  const { s, cleanup } = session("slow_menu", { verifyDelayMs: 3000 });
  try {
    s.start();
    const snap = await waitFor(s, ["awaiting_code", "failed", "signed_in"]);
    assert.equal(snap.state, "awaiting_code", snap.message);
    assert.deepEqual(s.submitCode(GOOD_CODE), { ok: true });
    assert.equal((await waitFor(s, ["signed_in", "failed"])).state, "signed_in");
  } finally {
    cleanup();
  }
});

test("PTY: a CLI that exits right after signing in still verifies", pty, async () => {
  const { s, cleanup } = session("exit_after_signin");
  try {
    s.start();
    await waitFor(s, ["awaiting_code"]);
    s.submitCode(GOOD_CODE);
    const snap = await waitFor(s, ["signed_in", "failed"]);
    assert.equal(snap.state, "signed_in", snap.message);
  } finally {
    cleanup();
  }
});

test("PTY: a non-Google (phishing) URL printed by the terminal is never offered", pty, async () => {
  const { s, cleanup } = session("phishing_url");
  try {
    s.start();
    await new Promise((r) => setTimeout(r, 1200));
    const snap = s.snapshot();
    assert.equal(snap.authUrl, null);
    assert.notEqual(snap.state, "awaiting_code");
  } finally {
    cleanup();
  }
});

test("PTY: key-injection attempts are refused before anything is typed", pty, async () => {
  const { s, cleanup } = session("login");
  try {
    s.start();
    await waitFor(s, ["awaiting_code"]);
    const r = s.submitCode("4/0AVG-abc\r\x1b[Bevil");
    assert.equal(r.ok, false);
    assert.equal(s.snapshot().state, "awaiting_code", "still waiting for a valid code");
  } finally {
    cleanup();
  }
});

test("PTY: cancel stops the CLI", pty, async () => {
  const { s, cleanup } = session("login");
  try {
    s.start();
    await waitFor(s, ["awaiting_code"]);
    assert.equal(s.cancel().state, "cancelled");
    assert.deepEqual(s.submitCode(GOOD_CODE).ok, false);
  } finally {
    cleanup();
  }
});

test("PTY: a slow sign-in (spinner far longer than the settle window) is waited out, not failed", pty, async () => {
  const { s, cleanup } = session("login", { signInMs: 3500 });
  try {
    s.start();
    await waitFor(s, ["awaiting_code"]);
    s.submitCode(GOOD_CODE);
    const snap = await waitFor(s, ["signed_in", "failed"], 12_000);
    assert.equal(snap.state, "signed_in", snap.message);
  } finally {
    cleanup();
  }
});
