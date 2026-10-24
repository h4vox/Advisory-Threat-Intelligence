#!/usr/bin/env node
// @ts-nocheck -- standalone test double run in a pseudo-terminal, not app code
// Test double for the Antigravity CLI's interactive sign-in, modeled on a real capture of `agy`
// (logo, "Select login method" menu, wrapped Google URL plus an OSC 8 "Click here" link, the
// authorization-code prompt and the "⡿ Signing in..." spinner). Runs in a real pseudo-terminal.
//
// FAKE_AGY_MODE: login (default) | signed_in | google_second | slow_menu | exit_after_signin | phishing_url
// FAKE_AGY_NO_OSC8=1   print the URL only as wrapped text
// FAKE_AGY_SIGNIN_MS   how long "Signing in..." spins (default 1500)
// FAKE_AGY_STATE=path  file written on a successful sign-in (what the CLI would persist). When it exists,
//                      the CLI starts signed in and `--print` answers prompts; otherwise `--print` fails
//                      the way the real CLI does ("Print mode: not authenticated").
// FAKE_AGY_ONBOARDING=0  skip the first-run setup screens (colour scheme, folder trust) that the real
//                      CLI shows after its first sign-in; they are on by default.
// Also: `--version`, and stream-json print mode (`--input-format stream-json --output-format
// stream-json` with `--print=` or no `--print`). Like the real CLI, `--print` takes the prompt as its
// value: a bare `--print` followed by a flag is a usage error (exit 2).
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { createInterface } from "node:readline";

const STATE = process.env.FAKE_AGY_STATE || "";
// FAKE_AGY_HOME_CHECK=1: like the real CLI, create ~/.gemini at start-up and refuse to start without it.
if (process.env.FAKE_AGY_HOME_CHECK === "1" && !process.argv.includes("--version")) {
  try {
    mkdirSync(`${process.env.HOME}/.gemini`, { recursive: true });
  } catch (err) {
    process.stderr.write(`E1023 main.go:877] CLI failed to start - mkdir ${process.env.HOME}/.gemini: permission denied\nFailed to start: mkdir ${process.env.HOME}/.gemini: permission denied\n`);
    process.exit(1);
  }
}
const signedIn = () => Boolean(STATE) && existsSync(STATE);
const argv = process.argv.slice(2);
if (argv.includes("--version")) {
  process.stdout.write("1.4.6-fake\n");
  process.exit(0);
}
const printAt = argv.findIndex((a) => a === "--print" || a === "-p");
if (printAt >= 0 && /^-/.test(argv[printAt + 1] ?? "")) {
  process.stderr.write(
    `Error: --print took "${argv[printAt + 1]}" as its prompt, so the intended prompt was left as an argument and ignored.\n` +
      "Attach the prompt to the flag (--print='your prompt') and move " + argv[printAt + 1] + " elsewhere on the command line.\n",
  );
  process.exit(2);
}
const streamJson = argv.includes("stream-json") && (printAt < 0 || argv.some((a) => a === "--print=" || a === "-p="));
if (streamJson || printAt >= 0 || argv.some((a) => a.startsWith("--print="))) {
  if (!signedIn()) {
    process.stderr.write("Print mode: not authenticated. Run `agy` to sign in.\n");
    process.exit(1);
  }
  const emit = (o) => process.stdout.write(`${JSON.stringify(o)}\n`);
  let turns = 0;
  let pending = Promise.resolve();
  emit({ event: "init", init: { conversation_id: "fake-conv-1" } });
  const rl = createInterface({ input: process.stdin });
  rl.on("line", (line) => {
    let turn;
    try {
      turn = JSON.parse(line);
    } catch {
      return;
    }
    const prompt = String(turn?.message?.content ?? "");
    // Test hooks: [[fake-delay-ms:N]] answers after N ms (one turn at a time, like the real CLI);
    // [[fake-argv]] answers with this worker's flags and turn number.
    const delay = Number(prompt.match(/\[\[fake-delay-ms:(\d+)\]\]/)?.[1] ?? skillDelay(prompt));
    turns += 1;
    const reply = /\[\[fake-argv\]\]/.test(prompt)
      ? JSON.stringify({ argv: argv.filter((a) => a.startsWith("--")), turn: turns, pid: process.pid })
      : /READY/.test(prompt)
        ? "READY"
        : fakeTranslation(prompt) ?? fakeAnalyst(prompt) ?? `echo: ${prompt.slice(0, 80)}`;
    pending = pending.then(
      () =>
        new Promise((done) =>
          setTimeout(() => {
            emit({ event: "step_update", step_update: { text_delta: reply } });
            emit({ event: "result", result: { status: "SUCCESS", response: reply, usage: { input_tokens: 5, output_tokens: 1, total_tokens: 6 } } });
            done();
          }, delay),
        ),
    );
  });
  rl.on("close", () => void pending.then(() => process.exit(0)));
} else {
  interactive();
}

function interactive() {
const MODE = process.env.FAKE_AGY_MODE || (signedIn() ? "signed_in" : "login");
const GOOD_CODE = "4/0AVG-good-code_123";
const ESC = "\x1b";
const out = (s) => process.stdout.write(s);
const clear = () => out(`${ESC}[2J${ESC}[H`);
const LOGO = ["    ▄▀▀▄", "   ▀▀▀▀▀▀", "  ▀▀▀▀▀▀▀▀", " ▄▀▀    ▀▀▄", "▄▀▀      ▀▀▄"].map((l) => ` ${ESC}[38;5;39m${l}${ESC}[0m`).join("\r\n");

const host = MODE === "phishing_url" ? "accounts.google.com.evil.example" : "accounts.google.com";
const AUTH_URL =
  `https://${host}/o/oauth2/auth?access_type=offline&client_id=1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com` +
  "&code_challenge=qgATp30Q1L58ooXP4FXOEqYfAYHo8HOpVXJTYCZX9WU&code_challenge_method=S256&prompt=consent" +
  "&redirect_uri=https%3A%2F%2Fantigravity.google%2Foauth-callback&response_type=code" +
  "&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform+openid&state=2IZUxE1jWfNItMZalgi5XA";

const options = MODE === "google_second" ? ["Use a Google Cloud project", "Google OAuth"] : ["Google OAuth", "Use a Google Cloud project"];
let selected = 0;
let screen = "boot";
let code = "";

function drawMenu() {
  clear();
  out(`${LOGO}\r\n\r\n Welcome to the Antigravity CLI. You are currently not signed in.\r\n\r\n Select login method:\r\n`);
  options.forEach((o, i) => out(`${i === selected ? ` ${ESC}[36m>${ESC}[0m` : "  "} ${i + 1}. ${o}\r\n`));
  out(`\r\n   ↑/↓ Navigate · enter Select\r\n`);
}

function drawUrl() {
  clear();
  out(`${LOGO}\r\n\r\n Your browser should open automatically. If not:\r\n\r\n`);
  for (let i = 0; i < AUTH_URL.length; i += 180) out(` ${AUTH_URL.slice(i, i + 180)}\r\n`); // hard-wrapped like the capture
  out(`\r\n Copy and paste the URL or click on the link below:\r\n`);
  const link = process.env.FAKE_AGY_NO_OSC8 ? "Click here to authenticate" : `${ESC}]8;;${AUTH_URL}${ESC}\\Click here to authenticate${ESC}]8;;${ESC}\\`;
  out(` ─────────────\r\n → ${link}\r\n ─────────────\r\n\r\n If you aren't automatically redirected, paste the authorization code below:\r\n\r\n ${code || `${ESC}[2mauthorization code...${ESC}[0m`}`);
}

const ONBOARDING = process.env.FAKE_AGY_ONBOARDING !== "0";
const onboarded = () => !ONBOARDING || (Boolean(STATE) && existsSync(`${STATE}.onboarded`));
const themes = ["terminal", "light", "solarized light", "dark", "tokyo night"];
let theme = 0;

/** The real CLI's first-run colour-scheme step (captured), sample preview box included. */
function drawTheme() {
  clear();
  out(`\r\n${ESC}[1mWelcome to Antigravity CLI!${ESC}[0m\r\n\r\nChoose your color scheme:        ╭──────────────────────────────╮\r\n`);
  themes.forEach((t, i) => out(`${i === theme ? "  >" : "   "} ${t}\r\n`));
  out(`│   ✗ error: compilation failed │\r\n│   ⚠ warning: deprecation warning │\r\n╰──────────────────────────────╯\r\n\r\n[Next]\r\n\r\n  ↑/↓ Navigate · enter Confirm`);
}

function drawTrust() {
  clear();
  out(`\r\nDo you trust the files in this folder?\r\n\r\n  > 1. Yes, proceed\r\n    2. No, exit\r\n\r\n  ↑/↓ Navigate · enter Confirm`);
}

function finishOnboarding() {
  if (STATE) writeFileSync(`${STATE}.onboarded`, "yes");
  screen = "chat";
  drawChat();
}

function drawChat(note = "") {
  clear();
  out(`${LOGO}\r\n\r\n ${note}${note ? "\r\n" : ""} ${ESC}[1m>${ESC}[0m Type your message or @path/to/file\r\n`);
}

function signIn() {
  screen = "signing";
  const frames = ["⡿", "⣟", "⣯", "⣷", "⣾", "⣽", "⣻", "⢿"];
  let f = 0;
  const spin = setInterval(() => {
    clear();
    out(`${LOGO}\r\n\r\n ${frames[f++ % frames.length]}  Signing in...\r\n`);
  }, 80);
  setTimeout(() => {
    clearInterval(spin);
    if (code !== GOOD_CODE) {
      clear();
      out(`${LOGO}\r\n\r\n ${ESC}[31mError: invalid_grant (Bad Request). Please try again.${ESC}[0m\r\n`);
      screen = "error";
      return;
    }
    if (STATE) {
      mkdirSync(dirname(STATE), { recursive: true });
      writeFileSync(STATE, "signed-in");
    }
    if (MODE === "exit_after_signin") process.exit(0);
    if (!onboarded()) {
      screen = "theme";
      drawTheme();
      return;
    }
    screen = "chat";
    drawChat("Signed in as analyst@example.com");
  }, Number(process.env.FAKE_AGY_SIGNIN_MS || 1500));
}

process.stdin.setRawMode?.(true);
process.stdin.setEncoding("utf8");
process.stdin.on("data", (key) => {
  if (key.includes("\x03")) process.exit(130);
  if (screen === "menu") {
    if (key === `${ESC}[A`) selected = Math.max(0, selected - 1);
    else if (key === `${ESC}[B`) selected = Math.min(options.length - 1, selected + 1);
    else if (key === "\r") {
      if (options[selected] !== "Google OAuth") {
        clear();
        out(" Enter your Google Cloud project ID: ");
        screen = "project";
        return;
      }
      screen = "url";
      drawUrl();
      return;
    }
    drawMenu();
  } else if (screen === "theme") {
    if (key === `${ESC}[A`) theme = Math.max(0, theme - 1);
    else if (key === `${ESC}[B`) theme = Math.min(themes.length - 1, theme + 1);
    else if (key.includes("\r")) {
      screen = "trust";
      drawTrust();
      return;
    }
    drawTheme();
  } else if (screen === "trust") {
    if (key.includes("\r")) finishOnboarding();
  } else if (screen === "url") {
    for (const ch of key) {
      if (ch === "\r") return signIn();
      if (ch === "\x7f") code = code.slice(0, -1);
      else if (ch >= " ") code += ch;
    }
    drawUrl();
  }
});

if (MODE === "signed_in") {
  if (!onboarded()) {
    screen = "theme";
    drawTheme();
  } else {
    screen = "chat";
    drawChat();
  }
} else {
  setTimeout(() => {
    screen = "menu";
    drawMenu();
  }, MODE === "slow_menu" ? 2500 : 150);
}
}

// A mechanical stand-in for a translation request (tests only, no model): runs of non-ASCII text
// become English filler and everything ASCII (indicators, commands, identifiers) is kept as is, so
// AIE's translation checks and the crawler path can be exercised end to end.
function fakeTranslation(prompt) {
  if (!/text below into English/.test(prompt)) return null;
  const m = prompt.match(/<untrusted_source_content>\n([\s\S]*)\n<\/untrusted_source_content>/);
  return m ? m[1].replace(/[^\x00-\x7F]+/g, " the text ").replace(/[ \t]{2,}/g, " ") : null;
}

// Test hook: per-skill delays from ~/.gemini/fake-agy-delays.json ({"REPORT_QUALIFIER": 60000}), to
// stand in for a slow model in crawler tests.
function skillDelay(prompt) {
  try {
    const delays = JSON.parse(readFileSync(`${process.env.HOME}/.gemini/fake-agy-delays.json`, "utf8"));
    const skill = prompt.match(/\[SKILL: ([A-Z_]+)\]/)?.[1];
    return Number((skill && delays[skill]) ?? delays.default ?? 0);
  } catch {
    return 0;
  }
}

// A scripted stand-in for the AIE Analyst model (tests only): asks for list_reports on "latest" /
// "this week" questions, proposes start_crawl on crawl requests, otherwise answers citing [S1].
function fakeAnalyst(prompt) {
  const q = prompt.match(/\nANALYST: ([^\n]*)/)?.[1];
  if (!q) return null;
  const today = prompt.match(/Today is (\d{4}-\d{2}-\d{2})/)?.[1] ?? "2026-01-01";
  const done = (tool) => prompt.includes(`→ ${tool}(`);
  if (/\bcrawl\b/i.test(q) && !done("start_crawl")) {
    return JSON.stringify({ tool_calls: [{ name: "start_crawl", arguments: { query: "ransomware" } }] });
  }
  if (/latest|this week|recent/i.test(q) && !done("list_reports")) {
    const since = new Date(Date.parse(today) - 30 * 86400000).toISOString().slice(0, 10);
    return JSON.stringify({ tool_calls: [{ name: "list_reports", arguments: { since, limit: 3 } }] });
  }
  if (done("start_crawl")) return "A crawl focused on ransomware is ready: confirm it with the button below.";
  const ev = [...prompt.matchAll(/\n\[(S\d+)\] ([^\n]*?) —/g)];
  if (!ev.length) return "Hello, I am the AIE Analyst. Ask me about reports, actors, techniques or the crawler.";
  return ev.slice(0, 3).map(([, id, title]) => `- ${title} [${id}]`).join("\n");
}
