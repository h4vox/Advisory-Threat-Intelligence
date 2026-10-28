import { useRouteContext } from "@tanstack/react-router";
import { useCallback } from "react";
import type { AccountRole, AuthMethod } from "@/lib/aie/accounts/types";

/**
 * The signed-in user, as resolved by the page guard in routes/__root.tsx before the page rendered.
 * There is no loading state: a page only renders once the user is known.
 */

export type SessionUser = {
  id: string;
  displayName: string;
  primaryEmail: string | null;
  profileImageUrl: string | null;
  method: AuthMethod;
  username: string | null;
  role: AccountRole;
  weakPassword: boolean;
};

export type AppSessionState = { user: SessionUser | null; isPending: false; hasSsoSession: false };

export function useAppSession(): AppSessionState {
  const ctx = useRouteContext({ from: "__root__" }) as { user?: { id: string; username: string; displayName: string; role: AccountRole } | null };
  const u = ctx?.user ?? null;
  const user: SessionUser | null = u
    ? { id: u.id, displayName: u.displayName, primaryEmail: null, profileImageUrl: null, method: "password", username: u.username, role: u.role, weakPassword: false }
    : null;
  return { user, isPending: false, hasSsoSession: false };
}

/** Signs out with a plain form post to /api/logout (clears the cookie, returns to sign-in). */
export function useSignOut() {
  return useCallback(async (_opts?: { hasSsoSession?: boolean }) => {
    const form = document.createElement("form");
    form.method = "post";
    form.action = "/api/logout";
    document.body.appendChild(form);
    form.submit();
  }, []);
}
