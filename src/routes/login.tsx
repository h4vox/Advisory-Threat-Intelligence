import { createFileRoute, Navigate } from "@tanstack/react-router";
import { GROK_PROVIDERS, authEnabled, signIn } from "@/lib/auth/client";
import { useCurrentUserState } from "@/lib/auth/use-current-user";

export const Route = createFileRoute("/login")({ component: Login });

function Login() {
  const { user, isPending } = useCurrentUserState();
  if (!isPending && user) return <Navigate to="/" />;

  return (
    <main className="grid min-h-dvh place-items-center bg-bg px-4 text-fg">
      <div className="w-full max-w-sm space-y-5 rounded-lg border border-border bg-bg-elevated p-6">
        <div className="space-y-1">
          <div className="font-mono text-[11px] uppercase tracking-widest text-subtle">
            Adversary Intelligence Engine
          </div>
          <h1 className="text-xl font-semibold tracking-tight">Sign in</h1>
          <p className="text-sm text-muted">
            Access is limited to approved analysts.
          </p>
        </div>
        {authEnabled ? (
          <div className="space-y-2">
            {GROK_PROVIDERS.map((p) => (
              <button
                key={p.providerId}
                type="button"
                disabled={isPending}
                onClick={() => signIn(p.providerId, { callbackURL: "/" })}
                className="h-11 w-full cursor-pointer rounded-md border border-border px-4 text-sm font-medium transition-colors hover:bg-bg-subtle disabled:opacity-60"
              >
                Continue with {p.label}
              </button>
            ))}
          </div>
        ) : (
          <p className="text-sm text-muted">Sign-in is disabled in this environment.</p>
        )}
      </div>
    </main>
  );
}
