#!/usr/bin/env node
/**
 * Ship PGLite's runtime files with the server build.
 *
 * The production server bundles @electric-sql/pglite into a single module that loads
 * `pglite.wasm`, `pglite.data` and `initdb.wasm` from its own directory at runtime. The bundler
 * does not copy those files, so without DATABASE_URL the local-database fallback could not start
 * (ENOENT on pglite.data) and the rejection took the whole server down right after its first
 * response — browsers were left on "Checking session…" with nothing answering.
 *
 * Run after `vite build` (see the `build` script). Copies the files next to every built module
 * that references them; already-present files are left alone. Exit code 1 if PGLite is bundled
 * but its files cannot be found.
 */
import { copyFileSync, existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";

const root = process.cwd();
const outputs = [".vercel/output/functions", ".output/server"].map((d) => join(root, d)).filter((d) => existsSync(d));
const assets = ["pglite.wasm", "pglite.data", "initdb.wasm"];
const dist = join(root, "node_modules/@electric-sql/pglite/dist");

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) yield* walk(path);
    else if (/\.(mjs|js|cjs)$/.test(name)) yield path;
  }
}

const targets = new Set();
for (const out of outputs) {
  for (const file of walk(out)) {
    const text = readFileSync(file, "utf8");
    if (text.includes("pglite.data") && text.includes("import.meta.url")) targets.add(dirname(file));
  }
}

if (targets.size === 0) {
  console.log("[pglite-assets] no bundled PGLite module in the build output; nothing to copy");
  process.exit(0);
}
const missing = assets.filter((a) => !existsSync(join(dist, a)));
if (missing.length) {
  console.error(`[pglite-assets] missing in ${relative(root, dist)}: ${missing.join(", ")}`);
  process.exit(1);
}
let copied = 0;
for (const dir of targets) {
  for (const asset of assets) {
    const dest = join(dir, asset);
    if (existsSync(dest)) continue;
    copyFileSync(join(dist, asset), dest);
    copied += 1;
  }
  console.log(`[pglite-assets] ${relative(root, dir)}: ${assets.join(", ")}`);
}
console.log(`[pglite-assets] copied ${copied} file(s)`);
