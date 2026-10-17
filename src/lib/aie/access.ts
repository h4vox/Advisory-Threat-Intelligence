import { createMiddleware } from "@tanstack/react-start";
import { getBearerToken } from "@/lib/auth/client";
import { isEmailAllowed } from "./access-policy";
import { getEmbeddedSessionToken } from "./accounts/client-token";
import type { RequestIdentity } from "./accounts/types";

/**
 * Analyst access gate for every AIE server function.
 *
 * Two ways in, checked in this order:
 * 1. A password session (local account, see `./accounts`). Accounts are provisioned by an
 *    administrator, so they are on the access list by definition.
 * 2. Single sign-on (Better Auth, federated through the Grok broker). Sign-in alone is not enough:
 *    any Google/X account can sign in, and this app holds provider API keys and spends AI budget,
 *    so the caller's email must also match `AIE_ALLOWED_EMAILS` or `AIE_ALLOWED_DOMAINS`
 *    (comma-separated). With neither set, single sign-on is allowed in development only; a
 *    production server refuses it until the allowlist is configured (fail closed).
 *
 * The SSO session lookup is bounded: a database that never answers fails the call with a clear
 * message instead of hanging it.
 */

export class ForbiddenError extends Error {
  readonly status = 403;
  constructor(message = "Forbidden") {
    super(message);
    this.name = "ForbiddenError";
  }
}

const SSO_TIMEOUT_MS = 8000;

function bounded<T>(promise: Promise<T>, ms: number, message: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  return Promise.race([
    promise,
    new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(message)), ms);
    }),
  ]).finally(() => clearTimeout(timer));
}

export const analystMiddleware = createMiddleware({ type: "function" })
  .client(async ({ next }) => {
    // Embedded previews cannot use cookies: forward the SSO bearer token and the password session token (both null otherwise).
    // Static imports on purpose: both modules are browser-safe, and dynamic imports here upset the server bundle's chunk order.
    return next({ sendContext: { bearerToken: getBearerToken() ?? undefined, aieToken: getEmbeddedSessionToken() ?? undefined } });
  })
  .server(async ({ next, context }) => {
    // Only `*.server` modules here: this file also runs in the browser (the client hook above).
    const { assertSameSiteRequest } = await import("@/lib/auth/isolation.server");
    assertSameSiteRequest();

    const { resolveRequestAccount, accountErrorMessage } = await import("./accounts/session.server");
    let account: Awaited<ReturnType<typeof resolveRequestAccount>> = null;
    try {
      account = await resolveRequestAccount(context.aieToken);
    } catch (err) {
      throw new Error(`Password sessions are unavailable: ${accountErrorMessage(err)}`);
    }
    if (account) {
      const identity: RequestIdentity = { method: "password", username: account.username, displayName: account.displayName, role: account.role };
      return next({ context: { userId: account.id, userEmail: account.email, identity } });
    }

    const { getSessionUser, requireUserId, DEV_USER_ID, UnauthorizedError, authConfigured } = await import("@/lib/auth/verify.server");
    const production = process.env.NODE_ENV === "production";
    const timeoutMessage = "Single sign-on did not respond (its session database is not answering). Sign in with a username and password instead.";
    let userId: string;
    try {
      userId = await bounded(requireUserId(context.bearerToken), SSO_TIMEOUT_MS, timeoutMessage);
    } catch (err) {
      // Sign-in off with a real database configured: there is no shared user, so password sign-in is the way in.
      if (!(err instanceof UnauthorizedError) && !authConfigured && !(err instanceof Error && err.message === timeoutMessage)) throw new UnauthorizedError();
      throw err;
    }
    if (userId === DEV_USER_ID) {
      // Sign-in is off: the shared local workspace user, never in production (sign in with a password there).
      if (production) throw new UnauthorizedError();
      const identity: RequestIdentity = { method: "dev", username: null, displayName: "Local workspace user", role: "analyst" };
      return next({ context: { userId, userEmail: null as string | null, identity } });
    }
    const user = await bounded(getSessionUser(context.bearerToken), SSO_TIMEOUT_MS, timeoutMessage);
    const email = user?.email ?? null;
    const allowed = isEmailAllowed(email, {
      emails: process.env.AIE_ALLOWED_EMAILS,
      domains: process.env.AIE_ALLOWED_DOMAINS,
      production,
    });
    if (!allowed) {
      throw new ForbiddenError(
        production && !process.env.AIE_ALLOWED_EMAILS && !process.env.AIE_ALLOWED_DOMAINS
          ? "Single sign-on is not configured for this workspace (set AIE_ALLOWED_EMAILS or AIE_ALLOWED_DOMAINS). Sign in with a username and password instead."
          : "Your account is not on this workspace's access list.",
      );
    }
    const identity: RequestIdentity = { method: "sso", username: null, displayName: null, role: "analyst" };
    return next({ context: { userId, userEmail: email, identity } });
  });
