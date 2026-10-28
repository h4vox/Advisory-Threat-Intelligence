# AIE sign-in and access

AIE has one sign-in: a username and password set in the server environment.

```
AIE_ADMIN_USERNAME=<username>
AIE_ADMIN_PASSWORD=<password>
AIE_SESSION_SECRET=<32+ random characters, e.g. `openssl rand -base64 48`>
AIE_SESSION_DAYS=7        # optional
```

Put them in `.env` next to `package.json` (untracked) or in the server's environment, then restart.
Sign-in is refused until the username and password are both set.

## How it works

- **Sign-in page:** the form posts to `/api/login`. It works as soon as the page arrives, before the
  page's scripts load.
- **The cookie:** a correct username and password sets `aie_session`, an HttpOnly, SameSite=Lax cookie.
  It is also Secure over HTTPS (behind a reverse proxy, the proxy must send `X-Forwarded-Proto`).
  The cookie is signed with HMAC-SHA256 using `AIE_SESSION_SECRET`.
- **Checking a request:** pages and every server function check that cookie. The check needs no
  database and no network, so it never slows a page down and never leaves a page waiting on
  "Checking session…".
- **Signing everyone out:** change `AIE_ADMIN_PASSWORD` or `AIE_SESSION_SECRET` and restart. Without
  `AIE_SESSION_SECRET` a random secret is made at start, so everyone is signed out on every restart.
- **Repeated failures:** after 8 failed sign-ins from one address within 15 minutes, that address must wait.
- **Cross-site requests:** sign-in, sign-out and server functions refuse scripted cross-site requests (CSRF).

Accounts created earlier (MongoDB collections `aie_users`, `aie_sessions`) are kept untouched. If one
has the same username, its id is reused, so your AI chat history stays visible. Multiple users,
roles and single sign-on will be planned separately.
