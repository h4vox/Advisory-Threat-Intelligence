/**
 * Sign-in state for the page guard (routes/__root.tsx). Signing in and out are plain form posts
 * to /api/login and /api/logout (routes/api), so they work before the page's scripts load.
 * Credentials: AIE_ADMIN_USERNAME / AIE_ADMIN_PASSWORD in the server environment (./auth/env-auth).
 */
import { createServerFn } from "@tanstack/react-start";

export type AuthStateUser = { id: string; username: string; displayName: string; role: "admin" };
export type AuthState = { user: AuthStateUser | null; configured: boolean };

export const getAuthState = createServerFn({ method: "GET" }).handler(async (): Promise<AuthState> => {
  const { authConfig, currentUser } = await import("./auth/session.server");
  return { user: await currentUser(), configured: authConfig() !== null };
});
