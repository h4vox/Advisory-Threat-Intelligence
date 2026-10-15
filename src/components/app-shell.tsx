import { useEffect, useState, type ReactNode } from "react";
import { Link, useRouterState } from "@tanstack/react-router";
import { Bot, Cpu, Database, Globe2, Layers, Library, Moon, Radar, Settings, Sparkles, Sun, Upload } from "lucide-react";
import { cn } from "@/lib/cn";
import { AieAgentChatDrawer } from "./aie-agent-chat-drawer";
import { UserButton } from "@/lib/auth/gates";

const NAV = [
  { to: "/", label: "Overview", icon: Radar },
  { to: "/matrix", label: "ATT&CK Matrix", icon: Layers },
  { to: "/sources", label: "Sources", icon: Globe2 },
  { to: "/ingest", label: "Ingest", icon: Upload },
  { to: "/library", label: "Library", icon: Library },
  { to: "/marketplace", label: "Marketplace", icon: Cpu },
  { to: "/settings", label: "Settings", icon: Settings },
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

function applyGlassBlurTokens(val: number) {
  if (typeof document === "undefined") return;
  const blurPx = Math.round(6 + (val / 100) * 36.0);
  const opacityDark = (0.05 + (val / 100) * 0.16).toFixed(3);
  const opacityLight = (0.50 + (val / 100) * 0.28).toFixed(3);
  const specular = (0.22 + (val / 100) * 0.38).toFixed(3);
  document.documentElement.style.setProperty("--glass-blur-ratio", `${val}%`);
  document.documentElement.style.setProperty("--glass-blur", `${blurPx}px`);
  document.documentElement.style.setProperty("--glass-opacity-dark", `${opacityDark}`);
  document.documentElement.style.setProperty("--glass-opacity-light", `${opacityLight}`);
  document.documentElement.style.setProperty("--glass-specular-opacity", `${specular}`);
}

export function AppShell({
  children,
  className,
  flush,
}: {
  children: ReactNode;
  className?: string;
  flush?: boolean;
}) {
  const pathname = useRouterState({ select: (s) => s?.location?.pathname ?? "" }) ?? "";
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [uiStyle, setUiStyle] = useState<"default" | "liquid-glass">("default");
  const [agentDrawerOpen, setAgentDrawerOpen] = useState(false);

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

    const savedStyle = (localStorage.getItem("aie_ui_style") as "default" | "liquid-glass" | null) || "default";
    setUiStyle(savedStyle);
    document.documentElement.setAttribute("data-style", savedStyle);
    if (savedStyle === "liquid-glass") {
      document.documentElement.classList.add("theme-liquid-glass");
    } else {
      document.documentElement.classList.remove("theme-liquid-glass");
    }

    // Restore glass blur ratio tokens
    const savedRatio = localStorage.getItem("aie_glass_blur_ratio");
    const ratioVal = savedRatio ? parseInt(savedRatio, 10) : 70;
    if (!isNaN(ratioVal) && ratioVal >= 5 && ratioVal <= 110) {
      applyGlassBlurTokens(ratioVal);
    }

    const handleStyleChange = () => {
      const updatedStyle = (localStorage.getItem("aie_ui_style") as "default" | "liquid-glass" | null) || "default";
      setUiStyle(updatedStyle);
      document.documentElement.setAttribute("data-style", updatedStyle);
      if (updatedStyle === "liquid-glass") {
        document.documentElement.classList.add("theme-liquid-glass");
        const currentRatio = localStorage.getItem("aie_glass_blur_ratio");
        applyGlassBlurTokens(currentRatio ? parseInt(currentRatio, 10) : 70);
      } else {
        document.documentElement.classList.remove("theme-liquid-glass");
      }
    };

    const handleRatioChange = () => {
      const currentRatio = localStorage.getItem("aie_glass_blur_ratio");
      if (currentRatio) {
        const parsed = parseInt(currentRatio, 10);
        if (!isNaN(parsed)) applyGlassBlurTokens(parsed);
      }
    };

    window.addEventListener("aie-style-changed", handleStyleChange);
    window.addEventListener("aie-glass-ratio-changed", handleRatioChange);
    return () => {
      window.removeEventListener("aie-style-changed", handleStyleChange);
      window.removeEventListener("aie-glass-ratio-changed", handleRatioChange);
    };
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
    window.dispatchEvent(new Event("aie-theme-changed"));
  };

  const toggleUiStyle = () => {
    const next = uiStyle === "liquid-glass" ? "default" : "liquid-glass";
    setUiStyle(next);
    localStorage.setItem("aie_ui_style", next);
    document.documentElement.setAttribute("data-style", next);
    if (next === "liquid-glass") {
      document.documentElement.classList.add("theme-liquid-glass");
      const currentRatio = localStorage.getItem("aie_glass_blur_ratio");
      applyGlassBlurTokens(currentRatio ? parseInt(currentRatio, 10) : 75);
    } else {
      document.documentElement.classList.remove("theme-liquid-glass");
    }
    window.dispatchEvent(new Event("aie-style-changed"));
  };

  return (
    <div className={cn("h-dvh w-full overflow-hidden flex text-fg app-shell-root", uiStyle === "liquid-glass" ? "bg-transparent" : "bg-bg")}>
      {/* 100% STATIC DESKTOP SIDEBAR: Never moves or shifts during page scrolling */}
      <aside className={cn("hidden md:flex h-full w-56 shrink-0 flex-col border-r border-border px-4 py-6 overflow-y-auto select-none", uiStyle === "liquid-glass" ? "bg-bg/80 backdrop-blur-xl" : "bg-bg")}>
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
                preload="intent"
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

      {/* Main Content Column: Strictly fills remaining screen with static header and scrollable body */}
      <div className="flex min-w-0 flex-1 flex-col h-full overflow-hidden">
        {/* 100% STATIC TOP HEADER: Fixed in place, never scrolls away or jitters */}
        <header className={cn("shrink-0 z-30 flex items-center justify-between border-b border-border px-4 py-3 md:px-8", uiStyle === "liquid-glass" ? "bg-bg/75 backdrop-blur-xl" : "bg-bg")}>
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

            {/* AI Agent Drawer Trigger Button */}
            <button
              type="button"
              onClick={() => setAgentDrawerOpen(true)}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-accent/30 bg-accent/10 hover:bg-accent/20 text-accent transition-colors cursor-pointer group"
              title="Open AI Agent Cognitive Chat & IPC Console"
            >
              <span className="relative flex size-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full size-2 bg-emerald-500"></span>
              </span>
              <Bot className="size-3.5 text-accent" />
              <span className="font-mono text-[11px] font-medium hidden sm:inline">AI Agent</span>
            </button>

            <button
              type="button"
              onClick={toggleTheme}
              className="flex size-8 items-center justify-center rounded-lg border border-border bg-bg-elevated text-muted hover:text-fg hover:bg-bg-subtle transition-colors"
              title={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
            >
              {theme === "dark" ? <Sun className="size-4 text-warn" /> : <Moon className="size-4 text-accent" />}
            </button>
            <div className="hidden sm:block">
              <UserButton />
            </div>
          </div>
        </header>

        {/* Main Content Container */}
        <main
          className={cn(
            "flex-1 w-full",
            flush
              ? "overflow-hidden p-0 flex flex-col"
              : "overflow-y-auto px-4 py-6 md:px-8 md:py-8 pb-20 md:pb-8",
            className
          )}
        >
          {children}
        </main>
      </div>

      {/* Global AI Agent Slide-Over Chat Drawer (Matches 1/4 Screen Width) */}
      <AieAgentChatDrawer
        isOpen={agentDrawerOpen}
        onClose={() => setAgentDrawerOpen(false)}
      />

      {/* Mobile Bottom Navigation: Fixed to bottom */}
      <nav className="fixed inset-x-0 bottom-0 z-40 border-t border-border bg-bg/95 backdrop-blur md:hidden">
        <div className="grid grid-cols-7">
          {NAV.map((item) => {
            const active = item.to === "/" ? pathname === "/" : Boolean(pathname && pathname.startsWith(item.to));
            return (
              <Link
                key={item.to}
                to={item.to}
                preload="intent"
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
    </div>
  );
}
