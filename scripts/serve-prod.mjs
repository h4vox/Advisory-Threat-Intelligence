#!/usr/bin/env node
/**
 * Runs the production build (`npm run build` → .output/) as a Node server.
 *
 *   npm run start:prod
 *
 * Environment (.env is read by scripts/with-app-env.mjs):
 *   AIE_HOST  interface to listen on (default 127.0.0.1: put a reverse proxy with TLS in front)
 *   PORT      port (default 8080)
 *
 * Production is several times faster to load than `npm run dev`: the app arrives as a few
 * compressed bundles instead of hundreds of separately compiled modules.
 */
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const entry = join(root, ".output", "server", "index.mjs");
if (!existsSync(entry)) {
  console.error("[serve-prod] No production build found (.output/server/index.mjs). Run `npm run build` first.");
  process.exit(1);
}
process.env.NODE_ENV = "production";
process.env.HOST = process.env.AIE_HOST?.trim() || process.env.HOST?.trim() || "127.0.0.1";
process.env.PORT = process.env.PORT?.trim() || "8080";
console.log(`[serve-prod] AIE production server on http://${process.env.HOST}:${process.env.PORT}`);
await import(pathToFileURL(entry).href);
