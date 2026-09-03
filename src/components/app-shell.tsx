import { useEffect, useState, type ReactNode } from "react";
import { Link, useRouterState } from "@tanstack/react-router";
import { Database, Globe2, Layers, Library, Moon, Radar, Sun, Upload } from "lucide-react";
import { cn } from "@/lib/cn";

const NAV = [
  { to: "/", label: "Overview", icon: Radar },
  { to: "/matrix", label: "ATT&CK Matrix", icon: Layers },
  { to: "/sources", label: "Sources", icon: Globe2 },
  { to: "/ingest", label: "Ingest", icon: Upload },
  { to: "/library", label: "Library", icon: Library },
] as const;

function AieMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden>
      <rect x="1" y="1" width="30" height="30" rx="3" fill="none" stroke="currentColor" strokeWidth="1.5" />
      <path d="M8 24 L16 8 L24 24" fill="none" stroke="currentColor" strokeWidth="1.6" />
      <path d="M11.5 18h9" stroke="currentColor" strokeWidth="1.6" />
    </svg>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = useRouterState({ select: (s) => s?.location?.pathname ?? "" }) ?? "";
  const [theme, setTheme] = useState<"dark" | "light">("dark");

  useEffect(() => {
    const saved = localStorage.getItem("aie_theme") as "dark" | "light" | null;
    const initialTheme = saved || (window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
    setTheme(initialTheme);
    document.documentElement.setAttribute("data-theme", initialTheme);
    if (initialTheme === "light") {
      document.documentElement.classList.add("light");
    } else {
      document.documentElement.classList.remove("light");
    }
  }, []);

  const toggleTheme = () => {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    localStorage.setItem("aie_theme", next);
    document.documentElement.setAttribute("data-theme", next);
    if (next === "light") {
      document.documentElement.classList.add("light");
    } else {
      document.documentElement.classList.remove("light");
    }
  };

  return (
    <div className="min-h-dvh bg-bg text-fg">
      <div className="flex min-h-dvh w-full max-w-[1920px] mx-auto">
        <aside className="sticky top-0 hidden h-dvh w-56 shrink-0 flex-col border-r border-border bg-bg px-4 py-6 md:flex">
          <div className="mb-8 flex items-center gap-2.5 px-1">
            <AieMark className="size-8 text-accent" />
            <div>
              <div className="text-sm font-medium tracking-tight">AIE</div>
              <div className="font-mono text-[10px] uppercase tracking-widest text-subtle">
                Phase 1 · Retrieval
              </div>
            </div>
          </div>
          <nav className="flex flex-1 flex-col gap-1">
            {NAV.map((item) => {
              const active = item.to === "/" ? pathname === "/" : Boolean(pathname && pathname.startsWith(item.to));
              return (
                <Link
                  key={item.to}
                  to={item.to}
                  className={cn(
                    "flex h-11 items-center gap-2.5 rounded-md px-3 text-sm transition-colors duration-150",
                    active ? "bg-bg-subtle text-fg font-medium" : "text-muted hover:bg-bg-elevated hover:text-fg",
                  )}
                >
                  <item.icon className="size-4" strokeWidth={1.75} />
                  {item.label}
                </Link>
              );
            })}
          </nav>
          <div className="mt-auto border-t border-border pt-4 text-[11px] leading-relaxed text-subtle">
            Public CTI only. Evidence-preserving ingest. No production malware.
          </div>
        </aside>

        <div className="flex min-w-0 flex-1 flex-col">
          <header className="sticky top-0 z-30 flex items-center justify-between border-b border-border bg-bg/95 backdrop-blur-md px-4 py-3 md:px-8">
            <div className="flex items-center gap-2 md:hidden">
              <AieMark className="size-7 text-accent" />
              <span className="text-sm font-medium">AIE</span>
            </div>
            <div className="hidden font-mono text-[11px] uppercase tracking-widest text-subtle md:block">
              Adversary Intelligence Engine
            </div>
            <div className="flex items-center gap-3 text-subtle">
              <div className="flex items-center gap-2">
                <Database className="size-3.5" />
                <span className="font-mono text-[11px] uppercase tracking-wider hidden sm:inline">Retrieval store</span>
              </div>
              <button
                type="button"
                onClick={toggleTheme}
                className="flex size-8 items-center justify-center rounded-lg border border-border bg-bg-elevated text-muted hover:text-fg hover:bg-bg-subtle transition-colors"
                title={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
              >
                {theme === "dark" ? <Sun className="size-4 text-warn" /> : <Moon className="size-4 text-accent" />}
              </button>
            </div>
          </header>
          <main className="flex-1 px-4 py-6 md:px-8 md:py-8">{children}</main>
        </div>
      </div>

      <nav className="fixed inset-x-0 bottom-0 z-20 border-t border-border bg-bg/95 backdrop-blur md:hidden">
        <div className="grid grid-cols-5">
          {NAV.map((item) => {
            const active = item.to === "/" ? pathname === "/" : Boolean(pathname && pathname.startsWith(item.to));
            return (
              <Link
                key={item.to}
                to={item.to}
                className={cn(
                  "flex h-14 flex-col items-center justify-center gap-0.5 text-[10px] uppercase tracking-wider",
                  active ? "text-fg" : "text-subtle",
                )}
              >
                <item.icon className="size-4" strokeWidth={1.75} />
                {item.label}
              </Link>
            );
          })}
        </div>
      </nav>
      <div className="h-14 md:hidden" />
    </div>
  );
}
