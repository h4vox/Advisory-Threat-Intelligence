/**
 * Keep the server running when a background promise fails.
 *
 * Node exits on an unhandled promise rejection. A single background task failing — the local
 * database bootstrap when its files are missing, for example — then took the whole server down
 * right after it sent the first page, leaving browsers on "Checking session…" with nothing
 * answering. Log it instead; the request that needs the failed resource reports its own error.
 * Called at module scope in `src/router.tsx`, which the server loads before any route. No-op in
 * the browser; safe to call more than once.
 */
const g = globalThis as typeof globalThis & { __aieProcessGuards__?: boolean };

export function installProcessGuards(): void {
  if (typeof window !== "undefined" || typeof process === "undefined" || typeof process.on !== "function" || g.__aieProcessGuards__) return;
  g.__aieProcessGuards__ = true;
  process.on("unhandledRejection", (reason) => {
    console.error("[server] unhandled promise rejection; the server keeps running:", reason);
  });
}
