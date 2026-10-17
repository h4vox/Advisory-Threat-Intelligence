import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { createFileRoute, useRouter } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Eye, EyeOff, KeyRound, Loader2, LogIn, ShieldCheck } from "lucide-react";
import { GROK_PROVIDERS, authEnabled, signIn } from "@/lib/auth/client";
import { adoptPasswordSession, useAppSession } from "@/components/auth/use-app-session";
import { isEmbedded } from "@/lib/aie/accounts/client-token";
import { passwordSignIn } from "@/lib/aie/server-accounts";
import { cn } from "@/lib/cn";

type LoginSearch = { redirect?: string };

export const Route = createFileRoute("/login")({
  validateSearch: (search: Record<string, unknown>): LoginSearch => {
    const r = search.redirect;
    // Same-origin paths only (no "//host" or absolute URLs): never an open redirect.
    return typeof r === "string" && r.startsWith("/") && !r.startsWith("//") && !r.startsWith("/\\") && !r.startsWith("/login") ? { redirect: r } : {};
  },
  component: Login,
});

const field =
  "h-11 w-full rounded-lg border border-border bg-bg-elevated px-3 text-sm text-fg placeholder:text-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/60 disabled:opacity-60";

function Login() {
  const session = useAppSession();
  const { redirect } = Route.useSearch();
  const router = useRouter();
  const queryClient = useQueryClient();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [ssoBusy, setSsoBusy] = useState<string | null>(null);
  // The server-rendered form stays inert until scripts take over, so an early submit is never lost to a page reload.
  const [ready, setReady] = useState(false);
  useEffect(() => setReady(true), []);

  if (!session.isPending && session.user) return <GoTo href={redirect ?? "/"} />;

  const info = session.info;
  const storeDown = info ? !info.available : Boolean(session.accountError);
  const noAccounts = info?.available && !info.hasAccounts;

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (submitting) return;
    setError(null);
    if (!username.trim() || !password) {
      setError("Enter your username and password.");
      return;
    }
    setSubmitting(true);
    try {
      const res = await passwordSignIn({ data: { username, password } });
      const kept = await adoptPasswordSession(queryClient, res.user, res.token, isEmbedded());
      if (!kept) {
        setError("You signed in, but this browser did not keep the session. Allow cookies for this site and try again.");
        return;
      }
      router.history.replace(redirect ?? "/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign-in failed.");
      setPassword("");
    } finally {
      setSubmitting(false);
    }
  }

  async function onSso(providerId: string) {
    setError(null);
    setSsoBusy(providerId);
    try {
      await signIn(providerId, { callbackURL: redirect ?? "/" });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Single sign-on failed.");
    } finally {
      setSsoBusy(null);
    }
  }

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

          {storeDown && (
            <Notice tone="danger">
              Password sign-in is unavailable right now. {info?.error ?? session.accountError}
            </Notice>
          )}
          {noAccounts && (
            <Notice tone="warning">
              No accounts exist yet. Set <code className="font-mono text-[12px]">AIE_ADMIN_PASSWORD</code> (and optionally{" "}
              <code className="font-mono text-[12px]">AIE_ADMIN_USERNAME</code>) in the server environment and restart to create the
              administrator.
            </Notice>
          )}

          <form className="mt-5 space-y-4" onSubmit={onSubmit} method="post" noValidate>
            <div className="space-y-1.5">
              <label htmlFor="login-username" className="text-sm font-medium">
                Username
              </label>
              <input
                id="login-username"
                name="username"
                autoComplete="username"
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                autoFocus
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                disabled={submitting}
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
                  type={showPassword ? "text" : "password"}
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={submitting}
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
                  <span>{error}</span>
                </p>
              )}
            </div>

            <button
              type="submit"
              disabled={submitting || !ready}
              className="btn-primary inline-flex h-11 w-full items-center justify-center gap-2 rounded-lg px-4 text-sm font-medium disabled:cursor-wait disabled:opacity-70"
            >
              {submitting ? <Loader2 className="size-4 motion-safe:animate-spin" /> : <LogIn className="size-4" />}
              {submitting ? "Signing in…" : "Sign in"}
            </button>
          </form>

          {authEnabled && (
            <>
              <div className="my-5 flex items-center gap-3 text-xs text-subtle">
                <span className="h-px flex-1 bg-border" />
                or continue with
                <span className="h-px flex-1 bg-border" />
              </div>
              <div className="space-y-2">
                {GROK_PROVIDERS.map((p) => (
                  <button
                    key={p.providerId}
                    type="button"
                    disabled={Boolean(ssoBusy) || submitting || !ready}
                    onClick={() => void onSso(p.providerId)}
                    className="inline-flex h-10 w-full items-center justify-center gap-2 rounded-lg border border-border bg-bg-elevated px-4 text-sm font-medium transition-colors hover:bg-bg-subtle disabled:opacity-60"
                  >
                    {ssoBusy === p.providerId && <Loader2 className="size-4 motion-safe:animate-spin" />}
                    {p.label}
                  </button>
                ))}
              </div>
              {session.ssoUnavailable && (
                <p className="mt-3 text-xs text-muted">
                  Single sign-on did not respond just now. Username and password sign-in still works.
                </p>
              )}
            </>
          )}
        </div>

        <p className="flex items-center justify-center gap-1.5 text-xs text-subtle">
          <KeyRound className="size-3.5" />
          Sessions last 7 days on this browser. Ask an administrator for an account.
        </p>
      </div>
    </main>
  );
}

/** Client-side redirect to a same-origin path that may carry a query string (validated in validateSearch). */
function GoTo({ href }: { href: string }) {
  const router = useRouter();
  useEffect(() => {
    router.history.replace(href);
  }, [router, href]);
  return null;
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
