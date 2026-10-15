import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createRootRoute, HeadContent, Outlet, Scripts } from "@tanstack/react-router";
import { useState } from "react";
import { Toaster } from "sonner";
import { PreviewHostBridge } from "@/components/preview-host-bridge";
import { AuthProvider } from "@/lib/auth/provider";
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
      { name: "theme-color", content: "#0b0c0e" },
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

function RootDocument() {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            staleTime: 60_000,
            gcTime: 10 * 60_000,
            refetchOnWindowFocus: false,
            refetchOnReconnect: false,
            retry: 1,
          },
        },
      }),
  );

  return (
    <html lang="en" className="antialiased" suppressHydrationWarning>
      <head>
        <HeadContent />
        <script
          dangerouslySetInnerHTML={{
            __html: `(function(){
              try {
                var t = localStorage.getItem('aie_theme');
                if (t === 'light' || (!t && window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches)) {
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
            <Outlet />
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
