import { createMiddleware } from "@tanstack/react-start";
import { getEmbeddedSessionToken } from "./client-token";

/**
 * Forwards the embedded-preview session token (if any) to account server functions. The cookie,
 * when present, is read server-side and wins. See `./client-token`.
 */
export const accountTokenMiddleware = createMiddleware({ type: "function" }).client(async ({ next }) => {
  return next({ sendContext: { aieToken: getEmbeddedSessionToken() ?? undefined } });
});
