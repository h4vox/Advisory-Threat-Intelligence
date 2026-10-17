import { MutationCache, QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createRootRoute, HeadContent, Navigate, Outlet, Scripts, useRouterState } from "@tanstack/react-router";
import { useState, type ReactNode } from "react";
import { Toaster } from "sonner";
import { PreviewHostBridge } from "@/components/preview-host-bridge";
import { ACCOUNT_SESSION_KEY, useAppSession } from "@/components/auth/use-app-session";
import { AuthProvider } from "@/lib/auth/provider";
import { authClient, authEnabled } from "@/lib/auth/client";
import appCss from "../styles.css?url";

const APP_NAME = "AIE";

export const Route = createRootRoute({
  head: () => ({
    meta: [
      { charSet: "utf-8" },
      { name: "viewport", content: "width=device-width, initial-scale=1" },
      { title: APP_NAME },
      {
        name: "description",
        content: "Adversary Intelligence Engine — Phase 1 retrieval console for public threat reports.",
      },
      { name: "theme-color", content: "#0a0a0c" },
    ],
    links: [
      { rel: "icon", type: "image/svg+xml", href: "/favicon.svg" },
      { rel: "stylesheet", href: appCss },
      { rel: "manifest", href: "/__grok/manifest.webmanifest" },
      { rel: "apple-touch-icon", href: "/__grok/icon-180.png" },
      { rel: "preconnect", href: "https://fonts.googleapis.com" },
      {
        rel: "preconnect",
        href: "https://fonts.gstatic.com",
        crossOrigin: "anonymous",
      },
      {
        rel: "stylesheet",
        href: "https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&display=swap",
      },
    ],
  }),
  component: RootDocument,
});

const PUBLIC_PATHS = ["/login"];

/**
 * Every page except sign-in requires a session (password or single sign-on); server functions
 * enforce access. The session check is bounded (see useAppSession), and the loading screen offers
 * a plain link to the sign-in page after a few seconds, which works even before scripts load.
 */
function AuthGate({ children }: { children: ReactNode }) {
  const location = useRouterState({ select: (s) => s.location });
  const session = useAppSession();
  if (PUBLIC_PATHS.includes(location.pathname)) return <>{children}</>;
  if (session.isPending) return <SessionCheckScreen />;
  if (!session.user) {
    return <Navigate to="/login" search={location.pathname === "/" ? {} : { redirect: location.href }} replace />;
  }
  return <>{children}</>;
}

function SessionCheckScreen() {
  return (
    <div className="grid h-dvh place-items-center bg-bg px-4 text-center">
      <div className="space-y-3">
        <span aria-hidden className="mx-auto block size-5 rounded-full border-2 border-border border-t-primary motion-safe:animate-spin" />
        <p role="status" className="text-sm text-muted">
          Checking session…
        </p>
        <p className="session-slow-hint text-xs text-subtle">
          Taking longer than usual.{" "}
          <a href="/login" className="text-accent underline-offset-4 hover:underline">
            Go to sign in
          </a>{" "}
          or reload the page.
        </p>
      </div>
    </div>
  );
}

/** A server call answered "Unauthorized" (session ended or revoked): re-check, so the gate shows sign-in. */
function isUnauthorized(error: unknown): boolean {
  return error instanceof Error && error.message === "Unauthorized";
}

function RootDocument() {
  const [queryClient] = useState(() => {
    const onError = (error: unknown) => {
      if (!isUnauthorized(error)) return;
      void client.invalidateQueries({ queryKey: ACCOUNT_SESSION_KEY });
      if (authEnabled) authClient.$store.notify("$sessionSignal");
    };
    const client: QueryClient = new QueryClient({
      queryCache: new QueryCache({ onError }),
      mutationCache: new MutationCache({ onError }),
      defaultOptions: {
        queries: {
          staleTime: 60_000,
          gcTime: 10 * 60_000,
          refetchOnWindowFocus: false,
          refetchOnReconnect: false,
          retry: 1,
        },
      },
    });
    return client;
  });

  return (
    <html lang="en" className="antialiased" suppressHydrationWarning>
      <head>
        <HeadContent />
        <script
          dangerouslySetInnerHTML={{
            __html: `(function(){
              try {
                var t = localStorage.getItem('aie_theme');
                if (t === 'light') {
                  document.documentElement.setAttribute('data-theme', 'light');
                  document.documentElement.classList.add('light');
                } else {
                  document.documentElement.setAttribute('data-theme', 'dark');
                  document.documentElement.classList.remove('light');
                }
                var s = localStorage.getItem('aie_ui_style');
                if (s === 'liquid-glass') {
                  document.documentElement.setAttribute('data-style', 'liquid-glass');
                  document.documentElement.classList.add('theme-liquid-glass');
                } else {
                  document.documentElement.setAttribute('data-style', 'default');
                  document.documentElement.classList.remove('theme-liquid-glass');
                }
                var gr = localStorage.getItem('aie_glass_blur_ratio');
                var val = gr ? parseInt(gr, 10) : 70;
                if (!isNaN(val) && val >= 5 && val <= 110) {
                  var blurPx = Math.round(6 + (val / 100) * 36.0);
                  var opDark = (0.05 + (val / 100) * 0.16).toFixed(3);
                  var opLight = (0.50 + (val / 100) * 0.28).toFixed(3);
                  var spec = (0.22 + (val / 100) * 0.38).toFixed(3);
                  document.documentElement.style.setProperty('--glass-blur-ratio', val + '%');
                  document.documentElement.style.setProperty('--glass-blur', blurPx + 'px');
                  document.documentElement.style.setProperty('--glass-opacity-dark', opDark);
                  document.documentElement.style.setProperty('--glass-opacity-light', opLight);
                  document.documentElement.style.setProperty('--glass-specular-opacity', spec);
                }
              } catch(e) {}
            })()`,
          }}
        />
      </head>
      <body>
        <PreviewHostBridge />
        <AuthProvider>
          <QueryClientProvider client={queryClient}>
            <AuthGate>
              <Outlet />
            </AuthGate>
            <Toaster
              position="bottom-right"
              richColors
              closeButton
            />
          </QueryClientProvider>
        </AuthProvider>
        <Scripts />
      </body>
    </html>
  );
}
