#!/usr/bin/env node
/**
 * Installs dependencies when they are missing or older than package-lock.json (e.g. right after
 * a pull that added a package), so `npm run dev`, `build` and `start:prod` never start against
 * missing modules. Runs as the npm pre-script of those commands; fast when nothing changed.
 */
import { execFileSync } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const lock = join(root, "package-lock.json");
const installed = join(root, "node_modules", ".package-lock.json");

const stale = !existsSync(installed) || (existsSync(lock) && statSync(lock).mtimeMs > statSync(installed).mtimeMs + 1000);
if (stale && process.env.AIE_SKIP_DEPS_CHECK !== "1") {
  console.log("[deps] package-lock.json changed since the last install: running npm install…");
  try {
    execFileSync(process.platform === "win32" ? "npm.cmd" : "npm", ["install", "--no-audit", "--no-fund"], { cwd: root, stdio: "inherit" });
  } catch {
    console.error("[deps] npm install failed; run it by hand to see why. Starting anyway.");
  }
}
