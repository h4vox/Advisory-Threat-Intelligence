/**
 * Fallback carrier for the password session token (browser-side).
 *
 * The session normally rides an HttpOnly cookie. Inside an embedded preview (a cross-site iframe)
 * the browser does not send that cookie, and some browsers drop it altogether; then the token the
 * sign-in call returned is kept in sessionStorage for this tab and forwarded with each server call
 * (see `accountTokenMiddleware` / `analystMiddleware`). The server checks it exactly like the cookie.
 */
const KEY = "aie.session-token";

export function isEmbedded(): boolean {
  if (typeof window === "undefined") return false;
  try {
    return window.self !== window.top;
  } catch {
    return true; // cross-origin parent
  }
}

export function getEmbeddedSessionToken(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return window.sessionStorage.getItem(KEY);
  } catch {
    return null;
  }
}

export function setEmbeddedSessionToken(token: string | null): void {
  if (typeof window === "undefined") return;
  try {
    if (token) window.sessionStorage.setItem(KEY, token);
    else window.sessionStorage.removeItem(KEY);
  } catch {
    /* storage unavailable */
  }
}
