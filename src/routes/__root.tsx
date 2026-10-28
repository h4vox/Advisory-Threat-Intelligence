import { MutationCache, QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createRootRoute, HeadContent, Outlet, redirect, Scripts } from "@tanstack/react-router";
import { useState } from "react";
import { Toaster } from "sonner";
import { PreviewHostBridge } from "@/components/preview-host-bridge";
import { getAuthState, type AuthStateUser } from "@/lib/aie/server-auth";
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
  // Sign-in check before any page renders: on the server for the first load (part of the page
  // request, no extra round trip), then once per browser tab. No "Checking session…" screen.
  beforeLoad: async ({ location }): Promise<{ user: AuthStateUser | null }> => {
    if (PUBLIC_PATHS.includes(location.pathname)) return { user: null };
    const user = await signedInUser();
    if (!user) {
      throw redirect({ to: "/login", search: location.pathname === "/" ? {} : { redirect: location.href } });
    }
    return { user };
  },
  component: RootDocument,
});

const PUBLIC_PATHS = ["/login"];

// Browser only: the signed-in user, so moving between pages does not ask the server again.
// Never cached on the server, where one process serves every visitor.
let browserUser: AuthStateUser | null = null;

async function signedInUser(): Promise<AuthStateUser | null> {
  if (typeof window !== "undefined" && browserUser) return browserUser;
  const { user } = await getAuthState();
  if (typeof window !== "undefined") browserUser = user;
  return user;
}

/** Forget the cached user (after sign-out, or when the server says the session ended). */
export function forgetSignedInUser(): void {
  browserUser = null;
}

/** A server call answered "Unauthorized" (session ended or revoked): re-check, so the gate shows sign-in. */
function isUnauthorized(error: unknown): boolean {
  return error instanceof Error && error.message === "Unauthorized";
}

function RootDocument() {
  const [queryClient] = useState(() => {
    const onError = (error: unknown) => {
      if (!isUnauthorized(error) || typeof window === "undefined") return;
      // The session ended (expired, or the password changed): back to sign-in, then here again.
      forgetSignedInUser();
      if (!window.location.pathname.startsWith("/login")) {
        const back = window.location.pathname + window.location.search;
        window.location.assign(back === "/" ? "/login" : `/login?redirect=${encodeURIComponent(back)}`);
      }
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
        <QueryClientProvider client={queryClient}>
          <Outlet />
          <Toaster position="bottom-right" richColors closeButton />
        </QueryClientProvider>
        <Scripts />
      </body>
    </html>
  );
}
