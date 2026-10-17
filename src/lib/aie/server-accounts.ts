/**
 * Account server functions: password sign-in next to single sign-on, the session check the sign-in
 * gate uses, password changes, and user administration for administrators.
 *
 *   getAccountSession   public: this browser's password session plus what the sign-in page needs
 *   passwordSignIn      public: username + password → session cookie (and the token, for embedded previews)
 *   passwordSignOut     public: ends the password session
 *   changePassword      signed-in password account
 *   listUserAccounts / createUserAccount / updateUserAccount / deleteUserAccount   administrators
 *
 * Logic lives in ./accounts/session.server (store: ../mongodb/accounts-repo.server).
 */
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { assertSameSiteRequest } from "@/lib/auth/isolation.server";
import { ForbiddenError, analystMiddleware } from "./access";
import { accountTokenMiddleware } from "./accounts/middleware";
import {
  AccountError,
  accountErrorMessage,
  changeOwnPassword,
  createAccount,
  deleteAccount,
  describeAccountSession,
  listAccounts,
  resolveRequestAccount,
  signInWithPassword,
  signOutPassword,
  updateAccount,
} from "./accounts/session.server";
import type { RequestIdentity } from "./accounts/types";

/** Re-throw with a message that is safe and useful to show in the browser. */
async function friendly<T>(work: () => Promise<T>): Promise<T> {
  try {
    return await work();
  } catch (err) {
    throw new Error(accountErrorMessage(err));
  }
}

export const getAccountSession = createServerFn({ method: "POST" })
  .middleware([accountTokenMiddleware])
  .handler(async ({ context }) => {
    assertSameSiteRequest();
    return describeAccountSession(context.aieToken);
  });

export const passwordSignIn = createServerFn({ method: "POST" })
  .validator(
    z.object({
      username: z.string().trim().min(1, "Enter your username.").max(100),
      password: z.string().min(1, "Enter your password.").max(1024),
    }),
  )
  .handler(async ({ data }) => {
    assertSameSiteRequest();
    return friendly(() => signInWithPassword(data));
  });

export const passwordSignOut = createServerFn({ method: "POST" })
  .middleware([accountTokenMiddleware])
  .handler(async ({ context }) => {
    assertSameSiteRequest();
    await signOutPassword(context.aieToken);
    return { ok: true as const };
  });

export const changePassword = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(z.object({ currentPassword: z.string().min(1).max(1024), newPassword: z.string().min(1).max(1024) }))
  .handler(async ({ data, context }) => {
    if (context.identity.method !== "password") throw new ForbiddenError("Only username and password accounts have a password to change.");
    return friendly(async () => {
      const account = await resolveRequestAccount(context.aieToken);
      if (!account) throw new AccountError("Your session has ended. Sign in again.", 401);
      return changeOwnPassword(account, context.aieToken, data);
    });
  });

function requireAdmin(identity: RequestIdentity, userId: string): { id: string; username: string } {
  if (identity.method !== "password" || identity.role !== "admin" || !identity.username) {
    throw new ForbiddenError("Only administrators can manage users.");
  }
  return { id: userId, username: identity.username };
}

const roleSchema = z.enum(["admin", "analyst"]);
const emailSchema = z.string().trim().max(200).email("Enter a valid email address.").or(z.literal("")).nullable().optional();

export const listUserAccounts = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .handler(async ({ context }) => {
    requireAdmin(context.identity, context.userId);
    return friendly(() => listAccounts());
  });

export const createUserAccount = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(
    z.object({
      username: z.string().trim().min(1).max(100),
      displayName: z.string().trim().max(120).optional(),
      email: emailSchema,
      role: roleSchema,
      password: z.string().min(1).max(1024),
    }),
  )
  .handler(async ({ data, context }) => {
    const actor = requireAdmin(context.identity, context.userId);
    return friendly(() => createAccount(actor.username, data));
  });

export const updateUserAccount = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(
    z.object({
      id: z.string().min(1).max(100),
      displayName: z.string().trim().max(120).optional(),
      email: emailSchema,
      role: roleSchema.optional(),
      disabled: z.boolean().optional(),
      unlock: z.boolean().optional(),
      password: z.string().min(1).max(1024).optional(),
    }),
  )
  .handler(async ({ data, context }) => {
    const actor = requireAdmin(context.identity, context.userId);
    const { id, ...patch } = data;
    return friendly(() => updateAccount(actor, id, patch));
  });

export const deleteUserAccount = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(z.object({ id: z.string().min(1).max(100) }))
  .handler(async ({ data, context }) => {
    const actor = requireAdmin(context.identity, context.userId);
    await friendly(() => deleteAccount(actor, data.id));
    return { ok: true as const };
  });
