// ESM resolve hook for the eval harness (runs under --experimental-strip-types).
//  - Resolves the app's extensionless relative imports ("./types") to .ts files.
//  - Redirects modules that reach LLM providers / the agent sandbox / logging to inert
//    stubs, so attack-chain.ts can be imported and only its heuristic path runs.
//  - Refuses database imports outright: the eval must never touch Mongo/Postgres.
import { existsSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";

const STUBS = {
  "./ai-manager": "ai-manager.mjs",
  "./providers": "providers.mjs",
  "./agent-sandbox": "agent-sandbox.mjs",
  "./warm-agent-service": "warm-agent-service.mjs",
  "./logger": "logger.mjs",
};
const SRC_ROOT = new URL("../../src/", import.meta.url);

export async function resolve(specifier, context, next) {
  const parent = context.parentURL ?? "";
  if (/(^|\/)mongodb(\/|$)|^@\/lib\/db$|\/lib\/db(\.ts)?$/.test(specifier)) {
    throw new Error(`eval harness refuses DB import: ${specifier} (from ${parent})`);
  }
  if (STUBS[specifier] && parent.includes("/src/lib/aie/")) {
    return { url: new URL(`./stubs/${STUBS[specifier]}`, import.meta.url).href, shortCircuit: true };
  }
  let spec = specifier;
  if (spec.startsWith("@/")) spec = new URL(spec.slice(2), SRC_ROOT).href;
  const isRelative = spec.startsWith("./") || spec.startsWith("../") || spec.startsWith("file:");
  if (isRelative && parent.startsWith("file:") && !/\.[cm]?[jt]sx?$/.test(spec)) {
    const base = new URL(spec, parent);
    for (const candidate of [`${base.href}.ts`, `${base.href}/index.ts`]) {
      if (existsSync(fileURLToPath(candidate))) {
        return { url: pathToFileURL(fileURLToPath(candidate)).href, shortCircuit: true };
      }
    }
  }
  return next(spec, context);
}
