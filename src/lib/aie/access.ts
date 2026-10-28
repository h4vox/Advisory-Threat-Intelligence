import { createMiddleware } from "@tanstack/react-start";

/**
 * Access gate for every AIE server function: the request must carry a valid sign-in cookie
 * (./auth/env-auth: the username and password set in the server environment). Scripted
 * cross-site requests are refused before the cookie is even read.
 *
 * Checking the cookie needs no database and no network, so it never slows a page down.
 * `adminMiddleware` additionally requires the administrator role, for privileged operations.
 */

export class ForbiddenError extends Error {
  readonly status = 403;
  constructor(message = "Forbidden") {
    super(message);
    this.name = "ForbiddenError";
  }
}

export const analystMiddleware = createMiddleware({ type: "function" }).server(async ({ next }) => {
  // Only `*.server` modules here: this file is also bundled for the browser.
  const { assertSameSiteRequest } = await import("@/lib/auth/isolation.server");
  assertSameSiteRequest();
  const { currentUser, identityOf, UnauthorizedError } = await import("./auth/session.server");
  const user = await currentUser();
  if (!user) throw new UnauthorizedError();
  return next({ context: { userId: user.id, userEmail: null as string | null, identity: identityOf(user) } });
});

/** For privileged operations (agent installation, sign-in to the agent, maintenance). */
export const adminMiddleware = createMiddleware({ type: "function" })
  .middleware([analystMiddleware])
  .server(async ({ next, context }) => {
    if (context.identity.role !== "admin") throw new ForbiddenError("This needs an administrator.");
    return next();
  });
