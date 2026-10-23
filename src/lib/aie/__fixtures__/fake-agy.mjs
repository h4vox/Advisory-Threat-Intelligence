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
// Also: `--version`, and `--print --input-format stream-json --output-format stream-json` (NDJSON turns).
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { createInterface } from "node:readline";

const STATE = process.env.FAKE_AGY_STATE || "";
const signedIn = () => Boolean(STATE) && existsSync(STATE);
const argv = process.argv.slice(2);
if (argv.includes("--version")) {
  process.stdout.write("1.4.6-fake\n");
  process.exit(0);
}
if (argv.includes("--print") || argv.includes("-p")) {
  if (!signedIn()) {
    process.stderr.write("Print mode: not authenticated. Run `agy` to sign in.\n");
    process.exit(1);
  }
  const emit = (o) => process.stdout.write(`${JSON.stringify(o)}\n`);
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
    const reply = /READY/.test(prompt) ? "READY" : `echo: ${prompt.slice(0, 80)}`;
    emit({ event: "step_update", step_update: { text_delta: reply } });
    emit({ event: "result", result: { status: "SUCCESS", response: reply, usage: { input_tokens: 5, output_tokens: 1, total_tokens: 6 } } });
  });
  rl.on("close", () => process.exit(0));
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
    screen = "chat";
    drawChat("Signed in as analyst@example.com");
  }, Number(process.env.FAKE_AGY_SIGNIN_MS || 1500));
}

process.stdin.setRawMode?.(true);
process.stdin.setEncoding("utf8");
process.stdin.on("data", (key) => {
  if (key === "\x03") process.exit(130);
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
  screen = "chat";
  drawChat();
} else {
  setTimeout(() => {
    screen = "menu";
    drawMenu();
  }, MODE === "slow_menu" ? 2500 : 150);
}
}
