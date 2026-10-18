# AIE sign-in and access

AIE has two ways to sign in. Both appear on the sign-in page. The first field accepts **an email or a username**. Every server function checks access, not just the pages.

| Method | Who can use it | Where it lives |
|---|---|---|
| **Email / username and password** | Accounts an administrator created, the environment administrator, and the dev credential | MongoDB collections `aie_users` and `aie_sessions` (local database without `MONGODB_URI`) |
| **Single sign-on** (Google, X through the Grok auth broker) | Emails in `AIE_ALLOWED_EMAILS` or domains in `AIE_ALLOWED_DOMAINS` | Better Auth (`DATABASE_URL` Postgres, or the embedded PGLite) |

## Quick start: a temporary email + password login

Before you set up the full administrator, you can sign in with a dev credential set in the environment:

```
DEV_USER_CRED_EMAIL=you@example.com
DEV_USER_CRED_PASS=your-temp-password
```

Restart and sign in with that email and password. The account is created on start, has the administrator role, and is flagged as a dev credential. Changing the password and restarting resets it; removing both variables deletes it on the next start. Store it in a local, untracked `.env` — never commit it. It is stored as an scrypt hash, like every password.

## Set up the administrator

Set these in the server environment (deployment settings or a local, untracked `.env`), then restart:

```
MONGODB_URI=mongodb+srv://…
AIE_ADMIN_USERNAME=havox        # optional, defaults to havox
AIE_ADMIN_PASSWORD=…            # required to create the administrator
```

AIE creates the administrator in MongoDB on the first sign-in page load after start-up. Only scrypt hashes are stored; the password is never written to the database or to git.

- **Change the password in the app.** Use Profile → Change password. That change survives restarts as long as `AIE_ADMIN_PASSWORD` stays the same.
- **Recover a lost password.** Set a new `AIE_ADMIN_PASSWORD`, restart, and open the sign-in page. AIE notices that the value changed, resets the password, unlocks and re-enables the account, and signs out its old sessions.
- **Short passwords.** A short password such as `1234` is accepted from the environment. The administrator then sees a "Your password is short" warning until they change it. Passwords set in the app need at least 8 characters.

## Manage users

Administrators open **Settings → Users & access**. From there they can:

- add users (analyst or administrator) with a generated or typed password;
- reset passwords;
- unlock locked accounts;
- change roles;
- disable or delete accounts.

Disabling an account or resetting someone else's password signs out their sessions. AIE always keeps at least one enabled administrator. Administrators cannot demote, disable or delete themselves.

## Sessions and security

- **Session tokens.** A session is a random 32-byte token. The browser keeps it in an HttpOnly, SameSite=Lax cookie (`__Host-aie.session` with Secure over HTTPS, `aie.session` over plain HTTP). The server stores only the token's SHA-256.
- **Session lifetime.** Sessions last 7 days. In MongoDB, expired sessions are removed by a TTL index.
- **Rate limits.**
  - After 5 failed sign-ins, an account is locked for 15 minutes. The failure counter in the store is atomic, so parallel guesses each count.
  - Each server also reserves attempts before checking a password, so a burst of parallel guesses is cut off at the limit.
  - After 30 failures in 15 minutes, one network address is refused until the window ends.
  - Unknown usernames take the same hashing time as real ones, get the same error, and lock the same way, so the responses don't reveal which usernames exist.
- **Same-site checks.** Sign-in, sign-out and every server function reject scripted cross-site requests (`Sec-Fetch-Site`).
- **Embedded previews.** Cookies cannot be used inside a cross-site iframe. There, the token is kept in `sessionStorage` for the tab and sent with each server call, where it is checked exactly like the cookie.

## Why "Checking session…" no longer hangs

There were two causes.

1. **The built server crashed after its first page.** Without `DATABASE_URL`, the app falls back to an embedded database (PGLite). The production build did not ship PGLite's data files, so that database failed to start, and the unhandled error stopped the whole Node process. The browser had already received the first page, which shows "Checking session…", but nothing answered after that. Two fixes:
   - `npm run build` now copies PGLite's files into the server output (`scripts/copy-pglite-assets.mjs`).
   - A background failure is now logged instead of stopping the process (`src/lib/process-guards.ts`).
2. **The gate waited on the account store even when nobody was signed in.** The session check (`describeAccountSession`) provisioned the admin and counted users on every page load, so a slow or unreachable MongoDB held a fresh browser on "Checking session…" for many seconds before showing the sign-in page. Now, when the request carries **no session token** (a fresh browser, a signed-out visitor), the gate answers "not signed in" immediately with no store round trip — the admin and dev accounts are provisioned in the background. A dead MongoDB now reaches the sign-in page in about two seconds instead of eight-plus.
3. **The gate could wait forever on single sign-on.** It waited for the SSO session request without a limit. Now every wait is bounded:

| Wait | Limit | What happens next |
|---|---|---|
| Session check with no session token | none — answered immediately | Straight to the sign-in page |
| Resolving a present session token | Store timeout of 8 s | A clear error, then the sign-in page |
| Single sign-on session request | 5 s in the browser | Treated as "not signed in with SSO"; password sign-in still works |
| SSO checks inside server functions | 8 s | The call fails with a clear message instead of hanging |
| The loading screen itself | Link appears after a few seconds | A plain "Go to sign in" link, which works even before scripts load |

## Environment reference

| Variable | Purpose |
|---|---|
| `AIE_ADMIN_USERNAME` | Administrator username (default `havox`) |
| `AIE_ADMIN_PASSWORD` | Administrator password; creates the account, and resets it when the value changes |
| `DEV_USER_CRED_EMAIL` / `DEV_USER_CRED_PASS` | Temporary email + password login (admin role), created on start; reset on password change, removed when unset |
| `AIE_ADMIN_EMAIL` | Optional email on the administrator's profile |
| `AIE_ALLOWED_EMAILS` / `AIE_ALLOWED_DOMAINS` | Single sign-on allowlist (required for SSO in production) |
| `MONGODB_URI` | Where accounts are stored (local database without it, which resets on restart when it is PGLite) |
| `VITE_AUTH_ENABLED=false` | Turns single sign-on off. Outside production, the app then runs as the local workspace user; in production, password sign-in is required |

Code: `src/lib/aie/accounts/` (policy, hashing, sessions), `src/lib/mongodb/accounts-repo.server.ts` (store), `src/lib/aie/server-accounts.ts` (server functions), `src/lib/aie/access.ts` (the access check), `src/components/auth/` and `src/routes/login.tsx` (UI).
