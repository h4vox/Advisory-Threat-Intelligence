import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { DEFAULT_AGY_CLI_FLAVOR, agyStreamJsonArgs, nextAgyCliFlavor } from "./agy-cli-flags.ts";

const FAKE = fileURLToPath(new URL("./__fixtures__/fake-agy.mjs", import.meta.url));
const TURN = `${JSON.stringify({ event: "user", message: { content: "Reply with exactly the word READY and nothing else." } })}\n`;

/** Runs the CLI double with these flags and one stream-json turn, signed in. */
function runFake(args: string[]) {
  const dir = mkdtempSync(join(tmpdir(), "agy-flags-"));
  const state = join(dir, "signed-in");
  writeFileSync(state, "signed-in");
  try {
    return spawnSync(process.execPath, [FAKE, ...args], { input: TURN, encoding: "utf8", env: { ...process.env, FAKE_AGY_STATE: state } });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("the default flags keep --print last with its value attached, extra flags before it", () => {
  assert.deepEqual(agyStreamJsonArgs(DEFAULT_AGY_CLI_FLAVOR, "gemini-3.8-flash-low"), [
    "--disable-slash-commands",
    "--input-format",
    "stream-json",
    "--output-format",
    "stream-json",
    "--model",
    "gemini-3.8-flash-low",
    "--print=",
  ]);
  const withConversation = agyStreamJsonArgs(DEFAULT_AGY_CLI_FLAVOR, "m", ["--conversation", "abc123"]);
  assert.deepEqual(withConversation.slice(-3), ["--conversation", "abc123", "--print="]);
});

test("the reported failure: a bare --print before another flag is a usage error; the new flags answer", () => {
  const old = runFake(["--print", "--disable-slash-commands", "--input-format", "stream-json", "--output-format", "stream-json", "--model", "m"]);
  assert.equal(old.status, 2);
  assert.match(old.stderr, /--print took "--disable-slash-commands" as its prompt/);

  const fixed = runFake(agyStreamJsonArgs(DEFAULT_AGY_CLI_FLAVOR, "m"));
  assert.equal(fixed.status, 0, fixed.stderr);
  assert.match(fixed.stdout, /"response":"READY"/);
});

test("usage errors step the flags once each, and unrelated errors change nothing", () => {
  const printRefused = nextAgyCliFlavor(DEFAULT_AGY_CLI_FLAVOR, 'Error: --print took "--x" as its prompt');
  assert.deepEqual(printRefused, { print: "omit", slashCommandsFlag: true });
  // The headless form without --print also answers.
  const headless = runFake(agyStreamJsonArgs(printRefused!, "m"));
  assert.equal(headless.status, 0, headless.stderr);
  assert.match(headless.stdout, /"response":"READY"/);

  const slashRefused = nextAgyCliFlavor(printRefused!, "Error: unknown flag: --disable-slash-commands");
  assert.deepEqual(slashRefused, { print: "omit", slashCommandsFlag: false });
  assert.ok(!agyStreamJsonArgs(slashRefused!, "m").includes("--disable-slash-commands"));

  assert.equal(nextAgyCliFlavor(slashRefused!, "Error: unknown flag: --disable-slash-commands"), null, "no loop");
  assert.equal(nextAgyCliFlavor(DEFAULT_AGY_CLI_FLAVOR, "Print mode: not authenticated"), null);
  assert.equal(nextAgyCliFlavor(DEFAULT_AGY_CLI_FLAVOR, "quota exceeded"), null);
});
