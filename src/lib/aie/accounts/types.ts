/**
 * Local accounts: username + password sign-in that works next to single sign-on.
 *
 * Accounts live in MongoDB (collections aie_users / aie_sessions) when MONGODB_URI is set, otherwise
 * in the app's SQL database. Passwords are stored as scrypt hashes; sessions as SHA-256 hashes of a
 * random token that the browser holds in an HttpOnly cookie. Pure types; safe to import anywhere.
 */

export type AccountRole = "admin" | "analyst";

/** How the current visitor signed in. "dev" is the local workspace user (sign-in off, not production). */
export type AuthMethod = "password" | "sso" | "dev";

export const ACCOUNT_ROLES: ReadonlyArray<{ value: AccountRole; label: string; hint: string }> = [
  { value: "admin", label: "Administrator", hint: "Full access, manages users" },
  { value: "analyst", label: "Analyst", hint: "Full access to intelligence and simulation" },
];

/** What the browser may see about a password account (never the hash). */
export type PublicAccount = {
  id: string;
  username: string;
  displayName: string;
  email: string | null;
  role: AccountRole;
  disabled: boolean;
  createdAt: string;
  createdBy: string | null;
  lastLoginAt: string | null;
  passwordChangedAt: string | null;
  /** The password is shorter than the policy minimum (e.g. a bootstrap password). */
  weakPassword: boolean;
  /** Locked after repeated failed sign-ins, until this time. */
  lockedUntil: string | null;
  /** Managed by AIE_ADMIN_USERNAME / AIE_ADMIN_PASSWORD. */
  bootstrap: boolean;
};

export type AccountStorage = "mongodb" | "local";

/** Session state for the sign-in gate; public (no session required). */
export type AccountSessionInfo = {
  /** The password session of this browser, or null. */
  user: PublicAccount | null;
  storage: AccountStorage;
  /** False when the account store could not be reached; `error` says why. */
  available: boolean;
  error?: string;
  /** At least one account exists (or the administrator is configured and will be created). */
  hasAccounts: boolean;
  /** AIE_ADMIN_PASSWORD is set on the server. */
  adminConfigured: boolean;
  /** Non-production server with sign-in off: the shared local workspace user may continue. */
  devAccess: boolean;
};

/** Identity attached to every analyst server function's context. */
export type RequestIdentity = {
  method: AuthMethod;
  username: string | null;
  displayName: string | null;
  role: AccountRole;
};
