import { useQuery, useQueryClient, type QueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useState } from "react";
import { authClient, authEnabled, signOut as ssoSignOut } from "@/lib/auth/client";
import { DEV_USER, type AppUser } from "@/lib/auth/use-current-user";
import { getAccountSession, passwordSignOut } from "@/lib/aie/server-accounts";
import { setEmbeddedSessionToken } from "@/lib/aie/accounts/client-token";
import type { AccountRole, AccountSessionInfo, AuthMethod, PublicAccount } from "@/lib/aie/accounts/types";

/**
 * The signed-in visitor, whichever way they signed in: a password session (checked first), single
 * sign-on, or the local workspace user when sign-in is off outside production.
 *
 * Nothing here can hold the app on "Checking session…": the password check is bounded, and a
 * single sign-on session request that has not answered within a few seconds (its database not
 * responding, for instance) is treated as "not signed in with SSO" so the sign-in page appears.
 */

export const ACCOUNT_SESSION_KEY = ["account-session"] as const;

const ACCOUNT_TIMEOUT_MS = 12_000;
const SSO_TIMEOUT_MS = 5_000;
const SESSION_TIMEOUT_MESSAGE = "The server did not answer the session check.";

export type SessionUser = AppUser & {
  method: AuthMethod;
  username: string | null;
  role: AccountRole;
  weakPassword: boolean;
};

export type AppSessionState = {
  user: SessionUser | null;
  /** Still resolving: don't treat `user: null` as signed out yet. */
  isPending: boolean;
  /** Sign-in page details (store reachable, accounts exist, admin configured). */
  info: AccountSessionInfo | undefined;
  /** The password session check failed outright (network or server error). */
  accountError: string | null;
  /** Single sign-on is configured but its session check failed or timed out. */
  ssoUnavailable: boolean;
  /** Also signed in with single sign-on (for a complete sign-out). */
  hasSsoSession: boolean;
};

function withTimeout<T>(promise: Promise<T>, ms: number, message: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  return Promise.race([
    promise,
    new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(message)), ms);
    }),
  ]).finally(() => clearTimeout(timer));
}

export function fromAccount(a: PublicAccount): SessionUser {
  return {
    id: a.id,
    displayName: a.displayName || a.username,
    primaryEmail: a.email,
    profileImageUrl: null,
    isDevFallback: false,
    method: "password",
    username: a.username,
    role: a.role,
    weakPassword: a.weakPassword,
  };
}

type SsoState = { user: AppUser | null; isPending: boolean; failed: boolean };

/** Better Auth session, or a settled "none" when sign-in is off. `authEnabled` is constant, so the hook order is stable. */
function useSsoSession(): SsoState {
  if (!authEnabled) return { user: null, isPending: false, failed: false };
  // `authEnabled` is constant for the app's lifetime, so this conditional hook call keeps a stable order.
  const { data, isPending, error } = authClient.useSession();
  const u = data?.user;
  return {
    user: u ? { id: u.id, displayName: u.name ?? null, primaryEmail: u.email ?? null, profileImageUrl: u.image ?? null, isDevFallback: false } : null,
    isPending,
    failed: Boolean(error),
  };
}

export function accountSessionQuery() {
  return {
    queryKey: ACCOUNT_SESSION_KEY,
    queryFn: () => withTimeout(getAccountSession(), ACCOUNT_TIMEOUT_MS, SESSION_TIMEOUT_MESSAGE),
    staleTime: 5 * 60_000,
    // One quick retry for a network blip; a timeout is not retried (that would double the wait).
    retry: (failures: number, error: Error) => failures < 1 && error.message !== SESSION_TIMEOUT_MESSAGE,
    retryDelay: 400,
    // The sign-in page reuses a failed check instead of starting another wait.
    retryOnMount: false,
    refetchOnWindowFocus: false,
  } as const;
}

/**
 * What this page load learned about single sign-on, shared by every useAppSession() so the sign-in
 * page does not start its own wait after the gate already gave up. Only effects write it, and
 * effects never run on the server, so it stays false there (and for hydration).
 */
const ssoProbe = { settled: false, timedOut: false };

export function useAppSession(): AppSessionState {
  const account = useQuery(accountSessionQuery());
  const sso = useSsoSession();

  // Settle single sign-on once: later background refetches (window focus) must not send the app back to "Checking session…".
  const [ssoSettled, setSsoSettled] = useState(() => ssoProbe.settled);
  const [ssoTimedOut, setSsoTimedOut] = useState(() => ssoProbe.timedOut);
  useEffect(() => {
    if (sso.isPending) return;
    ssoProbe.settled = true;
    setSsoSettled(true);
  }, [sso.isPending]);
  useEffect(() => {
    if (!authEnabled || ssoSettled || ssoTimedOut) return;
    const timer = window.setTimeout(() => {
      ssoProbe.timedOut = true;
      setSsoTimedOut(true);
    }, SSO_TIMEOUT_MS);
    return () => window.clearTimeout(timer);
  }, [ssoSettled, ssoTimedOut]);

  const info = account.data;
  const accountError = account.isError ? (account.error instanceof Error ? account.error.message : "The session check failed.") : null;
  const ssoPending = authEnabled && sso.isPending && !ssoSettled && !ssoTimedOut;
  const ssoUnavailable = authEnabled && !sso.user && (sso.failed || (ssoTimedOut && !ssoSettled));
  const common = { info, accountError, ssoUnavailable, hasSsoSession: Boolean(sso.user) };

  if (info?.user) return { ...common, user: fromAccount(info.user), isPending: false };
  if (sso.user) return { ...common, user: { ...sso.user, method: "sso", username: null, role: "analyst", weakPassword: false }, isPending: false };
  if (account.isPending || ssoPending) return { ...common, user: null, isPending: true };
  // Sign-in off: the local workspace user, unless the server says this is production (then sign in with a password).
  const devAccess = info ? info.devAccess : Boolean(import.meta.env.DEV);
  if (!authEnabled && devAccess) return { ...common, user: { ...DEV_USER, method: "dev", username: null, role: "analyst", weakPassword: false }, isPending: false };
  return { ...common, user: null, isPending: false };
}

/** After a password sign-in: show the user at once, then confirm with the server (cookie or forwarded token). */
export async function adoptPasswordSession(queryClient: QueryClient, user: PublicAccount, token: string, embedded: boolean): Promise<boolean> {
  if (embedded) setEmbeddedSessionToken(token);
  const prev = queryClient.getQueryData<AccountSessionInfo>(ACCOUNT_SESSION_KEY);
  queryClient.setQueryData<AccountSessionInfo>(ACCOUNT_SESSION_KEY, {
    storage: prev?.storage ?? "local",
    available: true,
    hasAccounts: true,
    adminConfigured: prev?.adminConfigured ?? false,
    devAccess: prev?.devAccess ?? false,
    user,
  });
  if (embedded) return true;
  // The browser may have refused the cookie (blocked cookies, unusual proxies): fall back to the token for this tab.
  try {
    const confirmed = await getAccountSession();
    if (confirmed.user) return true;
    setEmbeddedSessionToken(token);
    const retried = await getAccountSession();
    if (retried.user) {
      queryClient.setQueryData(ACCOUNT_SESSION_KEY, retried);
      return true;
    }
  } catch {
    /* keep the optimistic session; server calls will report a real problem */
    return true;
  }
  setEmbeddedSessionToken(null);
  return false;
}

/** Signs out of the password session and, when present, single sign-on; then shows the sign-in page. */
export function useSignOut() {
  const queryClient = useQueryClient();
  return useCallback(
    async (opts: { hasSsoSession: boolean }) => {
      try {
        await withTimeout(passwordSignOut(), 6000, "Sign-out timed out.");
      } catch {
        /* the cookie is cleared server-side when the call lands; the local token is cleared below */
      }
      setEmbeddedSessionToken(null);
      queryClient.clear();
      if (authEnabled && opts.hasSsoSession) {
        try {
          await ssoSignOut("/login");
          return;
        } catch {
          /* fall through to the sign-in page */
        }
      }
      window.location.href = "/login";
    },
    [queryClient],
  );
}
