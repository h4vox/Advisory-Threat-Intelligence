import { useState, type ReactNode } from "react";
import { createFileRoute, redirect } from "@tanstack/react-router";
import { AlertTriangle, Eye, EyeOff, KeyRound, Loader2, LogIn, ShieldCheck } from "lucide-react";
import { getAuthState } from "@/lib/aie/server-auth";
import { cn } from "@/lib/cn";

type LoginSearch = { redirect?: string; error?: "invalid" | "limited" | "unconfigured" };

/** Same-origin paths only (no "//host" or absolute URLs): never an open redirect. */
function safeRedirect(r: unknown): string | undefined {
  return typeof r === "string" && r.startsWith("/") && !r.startsWith("//") && !r.startsWith("/\\") && !r.startsWith("/login") && !r.startsWith("/api/") ? r : undefined;
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

const ERRORS: Record<NonNullable<LoginSearch["error"]>, string> = {
  invalid: "Incorrect username or password.",
  limited: "Too many failed sign-ins. Wait a few minutes and try again.",
  unconfigured: "Sign-in is not set up on the server.",
};

/**
 * A plain HTML form posted to /api/login: it works as soon as the page arrives, before (and
 * without) the page's scripts.
 */
function Login() {
  const { redirect: to, error } = Route.useSearch();
  const { configured } = Route.useRouteContext();
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  return (
    <main className="grid min-h-dvh place-items-center bg-bg px-4 py-10 text-fg">
      <div className="w-full max-w-[400px] space-y-6">
        <div className="flex items-center gap-3">
          <span
            aria-hidden
            className="inline-flex size-10 items-center justify-center rounded-xl"
            style={{ color: "var(--color-primary)", backgroundColor: "color-mix(in oklab, var(--color-primary) 14%, transparent)" }}
          >
            <ShieldCheck className="size-5" strokeWidth={1.75} />
          </span>
          <div>
            <div className="text-sm font-semibold">AIE</div>
            <div className="text-xs text-muted">Adversary Intelligence Engine</div>
          </div>
        </div>

        <div className="rounded-xl border border-border bg-bg-card p-6 shadow-[var(--shadow-card)]">
          <h1 className="text-xl font-semibold">Sign in</h1>
          <p className="mt-1 text-sm text-muted">Access is limited to approved analysts.</p>

          {!configured && (
            <Notice tone="warning">
              Sign-in is not set up on the server. Set <code className="font-mono text-[12px]">AIE_ADMIN_USERNAME</code> and{" "}
              <code className="font-mono text-[12px]">AIE_ADMIN_PASSWORD</code> in its environment (<code className="font-mono text-[12px]">.env</code>) and
              restart.
            </Notice>
          )}

          <form className="mt-5 space-y-4" method="post" action="/api/login" onSubmit={() => setSubmitting(true)}>
            {to && <input type="hidden" name="redirect" value={to} />}
            <div className="space-y-1.5">
              <label htmlFor="login-username" className="text-sm font-medium">
                Username
              </label>
              <input
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
              className="btn-primary inline-flex h-11 w-full items-center justify-center gap-2 rounded-lg px-4 text-sm font-medium aria-busy:opacity-80"
              aria-busy={submitting}
            >
              {submitting ? <Loader2 className="size-4 motion-safe:animate-spin" /> : <LogIn className="size-4" />}
              {submitting ? "Signing in…" : "Sign in"}
            </button>
          </form>
        </div>

        <p className="flex items-center justify-center gap-1.5 text-xs text-subtle">
          <KeyRound className="size-3.5" />
          You stay signed in on this browser for 7 days.
        </p>
      </div>
    </main>
  );
}

function Notice({ tone, children }: { tone: "warning" | "danger"; children: ReactNode }) {
  const color = tone === "danger" ? "var(--color-danger)" : "var(--color-warn)";
  return (
    <div
      role="alert"
      className="mt-4 flex items-start gap-2 rounded-lg border px-3 py-2.5 text-sm"
      style={{ borderColor: `color-mix(in oklab, ${color} 30%, transparent)`, backgroundColor: `color-mix(in oklab, ${color} 8%, transparent)` }}
    >
      <AlertTriangle className="mt-0.5 size-4 shrink-0" style={{ color }} />
      <div className="min-w-0 text-fg">{children}</div>
    </div>
  );
}
