import { useEffect, useRef, useState, type ReactNode } from "react";
import { createFileRoute, redirect } from "@tanstack/react-router";
import { AlertTriangle, Apple, Eye, EyeOff, Github, Loader2, LockKeyhole, ShieldCheck } from "lucide-react";
import { getAuthState } from "@/lib/aie/server-auth";
import { cn } from "@/lib/cn";

type LoginSearch = { redirect?: string; error?: "invalid" | "limited" | "unconfigured" };

/** Same-origin paths only (no "//host" or absolute URLs): never an open redirect. */
function safeRedirect(r: unknown): string | undefined {
  return typeof r === "string" && r.startsWith("/") && !r.startsWith("//") && !r.startsWith("/\\") && !r.startsWith("/login") && !r.startsWith("/api/")
    ? r
    : undefined;
}

export const Route = createFileRoute("/login")({
  validateSearch: (search: Record<string, unknown>): LoginSearch => {
    const error = search.error === "invalid" || search.error === "limited" || search.error === "unconfigured" ? search.error : undefined;
    const r = safeRedirect(search.redirect);
    return { ...(r ? { redirect: r } : {}), ...(error ? { error } : {}) };
  },
  // Already signed in: straight to the page asked for. Also tells the page whether sign-in is set up.
  beforeLoad: async ({ search }) => {
    const state = await getAuthState();
    if (state.user) throw redirect({ href: search.redirect ?? "/" });
    return { configured: state.configured };
  },
  component: Login,
});

const field =
  "h-11 w-full rounded-lg border border-border bg-bg-elevated px-3 text-sm text-fg placeholder:text-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/60";

const providerButton =
  "inline-flex h-11 items-center justify-center gap-2 rounded-lg border border-border bg-bg-elevated px-3 text-sm font-medium text-fg disabled:cursor-not-allowed disabled:opacity-55";

const ERRORS: Record<NonNullable<LoginSearch["error"]>, string> = {
  invalid: "Incorrect username or password.",
  limited: "Too many failed sign-ins. Wait a few minutes and try again.",
  unconfigured: "Sign-in is not set up on the server.",
};

/** The username kept on this device when "Save username on this device" is ticked. */
const SAVED_USERNAME_KEY = "aie.login.username";

function readSavedUsername(): string | null {
  try {
    return window.localStorage.getItem(SAVED_USERNAME_KEY);
  } catch {
    return null;
  }
}

function writeSavedUsername(username: string | null) {
  try {
    if (username) window.localStorage.setItem(SAVED_USERNAME_KEY, username);
    else window.localStorage.removeItem(SAVED_USERNAME_KEY);
  } catch {
    // Storage blocked (private window): nothing is remembered.
  }
}

/**
 * A plain HTML form posted to /api/login: it works as soon as the page arrives, before (and
 * without) the page's scripts. Only username/email and password sign-in is enabled; the Google,
 * Apple, GitHub and SSO buttons are shown disabled until those sign-in methods are set up.
 */
function Login() {
  const { redirect: to, error } = Route.useSearch();
  const { configured } = Route.useRouteContext();
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [remember, setRemember] = useState(true);
  const usernameRef = useRef<HTMLInputElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const saved = readSavedUsername();
    if (saved && usernameRef.current && !usernameRef.current.value) {
      usernameRef.current.value = saved;
      passwordRef.current?.focus();
    }
  }, []);

  return (
    <div className="flex min-h-dvh flex-col bg-bg text-fg">
      <header className="flex items-center px-4 py-4">
        <div className="flex items-center gap-2.5">
          <span
            aria-hidden
            className="inline-flex size-8 items-center justify-center rounded-lg"
            style={{ color: "var(--color-primary)", backgroundColor: "color-mix(in oklab, var(--color-primary) 14%, transparent)" }}
          >
            <ShieldCheck className="size-4" strokeWidth={1.75} />
          </span>
          <span className="text-sm font-semibold">AIE</span>
        </div>
      </header>

      <main className="flex flex-1 justify-center px-4 pb-12 pt-8">
        <div className="flex w-full max-w-[360px] flex-col gap-6">
          <div className="text-center">
            <h1 className="text-2xl font-semibold tracking-tight">Sign in to AIE</h1>
            <p className="mt-1.5 text-sm text-muted">Adversary Intelligence Engine</p>
          </div>

          <div>
            <div className="grid grid-cols-3 gap-2">
              <button type="button" disabled title="Not enabled yet" className={providerButton}>
                <GoogleMark className="size-4" />
                Google
              </button>
              <button type="button" disabled title="Not enabled yet" className={providerButton}>
                <Apple className="size-4" />
                Apple
              </button>
              <button type="button" disabled title="Not enabled yet" className={providerButton}>
                <Github className="size-4" />
                GitHub
              </button>
            </div>
            <button type="button" disabled title="Not enabled yet" className={cn(providerButton, "mt-2 w-full")}>
              <LockKeyhole className="size-4" />
              Continue with SSO
            </button>
            <p className="mt-2 text-center text-xs text-subtle">Google, Apple, GitHub and SSO sign-in are not enabled yet.</p>
          </div>

          <div className="flex items-center gap-3 text-xs font-medium uppercase tracking-wider text-subtle" aria-hidden>
            <span className="h-px flex-1 bg-border" />
            or
            <span className="h-px flex-1 bg-border" />
          </div>

          {!configured && (
            <Notice tone="warning">
              Sign-in is not set up on the server. Set <code className="font-mono text-[12px]">AIE_ADMIN_USERNAME</code> and{" "}
              <code className="font-mono text-[12px]">AIE_ADMIN_PASSWORD</code> in its environment (<code className="font-mono text-[12px]">.env</code>) and
              restart.
            </Notice>
          )}

          <form
            className="space-y-4"
            method="post"
            action="/api/login"
            onSubmit={() => {
              writeSavedUsername(remember ? usernameRef.current?.value.trim() || null : null);
              setSubmitting(true);
            }}
          >
            {to && <input type="hidden" name="redirect" value={to} />}
            <div className="space-y-1.5">
              <label htmlFor="login-username" className="text-sm font-medium">
                Username or email
              </label>
              <input
                ref={usernameRef}
                id="login-username"
                name="username"
                required
                autoComplete="username"
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                autoFocus
                className={field}
              />
            </div>
            <div className="space-y-1.5">
              <label htmlFor="login-password" className="text-sm font-medium">
                Password
              </label>
              <div className="relative">
                <input
                  ref={passwordRef}
                  id="login-password"
                  name="password"
                  required
                  type={showPassword ? "text" : "password"}
                  autoComplete="current-password"
                  className={cn(field, "pr-11")}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((v) => !v)}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                  aria-pressed={showPassword}
                  className="absolute inset-y-0 right-0 inline-flex w-11 items-center justify-center rounded-r-lg text-muted hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/60"
                >
                  {showPassword ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                </button>
              </div>
            </div>

            <label className="flex cursor-pointer items-center gap-2.5 pt-1 text-sm">
              <input
                type="checkbox"
                checked={remember}
                onChange={(e) => setRemember(e.target.checked)}
                className="size-4 cursor-pointer rounded border-border accent-[var(--color-primary)]"
              />
              Save username on this device
            </label>

            <div aria-live="polite">
              {error && (
                <p className="flex items-start gap-2 text-sm text-danger">
                  <AlertTriangle className="mt-0.5 size-4 shrink-0" />
                  <span>{ERRORS[error]}</span>
                </p>
              )}
            </div>

            <button
              type="submit"
              className="btn-primary inline-flex h-11 w-full items-center justify-center gap-2 rounded-lg px-4 text-sm font-semibold aria-busy:opacity-80"
              aria-busy={submitting}
            >
              {submitting && <Loader2 className="size-4 motion-safe:animate-spin" />}
              {submitting ? "Signing in…" : "Sign in"}
            </button>
          </form>

          <div className="space-y-1.5 text-center text-sm text-muted">
            <p>Don't have access? Ask your administrator.</p>
            <p>Forgot your password? Your administrator can reset it.</p>
          </div>

          <p className="mt-4 text-center text-xs text-subtle">
            Access is limited to approved analysts. You stay signed in on this browser until you sign out or the session expires.
          </p>
        </div>
      </main>
    </div>
  );
}

/** Google's "G" mark, in its brand colours. */
function GoogleMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 48 48" aria-hidden className={className}>
      <path
        fill="#EA4335"
        d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"
      />
      <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z" />
      <path
        fill="#FBBC05"
        d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"
      />
      <path
        fill="#34A853"
        d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"
      />
    </svg>
  );
}

function Notice({ tone, children }: { tone: "warning" | "danger"; children: ReactNode }) {
  const color = tone === "danger" ? "var(--color-danger)" : "var(--color-warn)";
  return (
    <div
      role="alert"
      className="flex items-start gap-2 rounded-lg border px-3 py-2.5 text-sm"
      style={{ borderColor: `color-mix(in oklab, ${color} 30%, transparent)`, backgroundColor: `color-mix(in oklab, ${color} 8%, transparent)` }}
    >
      <AlertTriangle className="mt-0.5 size-4 shrink-0" style={{ color }} />
      <div className="min-w-0 text-fg">{children}</div>
    </div>
  );
}
