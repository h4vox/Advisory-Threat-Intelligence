import { useEffect, useState, type ComponentType, type ReactNode } from "react";
import { Link, useRouterState } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import * as Dialog from "@radix-ui/react-dialog";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import {
  Bot,
  ChevronDown,
  ChevronsUpDown,
  Cpu,
  Globe2,
  Layers,
  LayoutDashboard,
  Library,
  LogOut,
  Menu,
  Moon,
  Search,
  Settings,
  Sparkles,
  Sun,
  Upload,
  X,
} from "lucide-react";
import { cn } from "@/lib/cn";
import { getStorageStats } from "@/lib/aie/server";
import { authEnabled, signOut } from "@/lib/auth/client";
import { useCurrentUser } from "@/lib/auth/use-current-user";
import { AieAgentChatDrawer } from "./aie-agent-chat-drawer";
import { CommandPalette, type PaletteNavItem } from "./layout/command-palette";

type NavIcon = ComponentType<{ className?: string; strokeWidth?: number }>;
type NavItem = { to: string; label: string; icon: NavIcon };
type NavGroup = { id: string; label: string | null; items: NavItem[] };

const NAV_GROUPS: NavGroup[] = [
  { id: "home", label: null, items: [{ to: "/", label: "Overview", icon: LayoutDashboard }] },
  {
    id: "intel",
    label: "Intelligence",
    items: [
      { to: "/library", label: "Library", icon: Library },
      { to: "/matrix", label: "ATT&CK Matrix", icon: Layers },
    ],
  },
  {
    id: "collection",
    label: "Collection",
    items: [
      { to: "/sources", label: "Sources", icon: Globe2 },
      { to: "/ingest", label: "Ingest", icon: Upload },
    ],
  },
  {
    id: "platform",
    label: "Platform",
    items: [
      { to: "/marketplace", label: "Marketplace", icon: Cpu },
      { to: "/settings", label: "Settings", icon: Settings },
    ],
  },
];

const PALETTE_ITEMS: PaletteNavItem[] = NAV_GROUPS.flatMap((g) =>
  g.items.map((i) => ({ ...i, group: g.label ?? "Home" })),
);

function isActive(pathname: string, to: string) {
  return to === "/" ? pathname === "/" : pathname === to || pathname.startsWith(`${to}/`);
}

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
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const user = useCurrentUser();

  const countsQuery = useQuery({
    queryKey: ["nav-counts"],
    queryFn: () => getStorageStats(),
    staleTime: 5 * 60_000,
  });
  // Only show counts the store actually reports (no badge rather than a misleading 0).
  const storeCounts = countsQuery.data?.configured ? countsQuery.data : undefined;
  const counts: Record<string, number | undefined> = {
    "/library": storeCounts?.totalReports,
    "/sources": storeCounts?.totalSources,
  };

  // ⌘K / Ctrl+K opens search from anywhere.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // Close the mobile drawer on navigation.
  useEffect(() => {
    setMobileNavOpen(false);
  }, [pathname]);

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

  const workspaceMenu = (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <button
          type="button"
          className="flex w-full items-center gap-3 rounded-lg px-2 py-2 text-left transition-colors hover:bg-bg-subtle"
        >
          <span className="flex size-9 shrink-0 items-center justify-center rounded-lg border border-border bg-bg-elevated">
            <AieMark className="size-6 text-accent" />
          </span>
          <span className="min-w-0 flex-1">
            <span className="block truncate text-sm font-semibold text-fg">AIE</span>
            <span className="block truncate text-xs text-muted">{user?.primaryEmail ?? "Adversary Intelligence Engine"}</span>
          </span>
          <ChevronsUpDown className="size-4 shrink-0 text-subtle" />
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          align="start"
          sideOffset={6}
          className="z-50 w-60 rounded-lg border border-border bg-bg-elevated p-1 text-sm shadow-xl"
        >
          <div className="px-2 py-1.5">
            <div className="truncate font-medium text-fg">{user?.displayName ?? "Analyst"}</div>
            <div className="truncate text-xs text-muted">{user?.primaryEmail ?? ""}</div>
          </div>
          <DropdownMenu.Separator className="my-1 h-px bg-border" />
          <DropdownMenu.Item
            onSelect={toggleTheme}
            className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-fg outline-none data-[highlighted]:bg-bg-subtle"
          >
            {theme === "dark" ? <Sun className="size-4" /> : <Moon className="size-4" />}
            {theme === "dark" ? "Light theme" : "Dark theme"}
          </DropdownMenu.Item>
          <DropdownMenu.Item
            onSelect={toggleUiStyle}
            className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-fg outline-none data-[highlighted]:bg-bg-subtle"
          >
            <Sparkles className="size-4" />
            {uiStyle === "liquid-glass" ? "Default style" : "Liquid glass style"}
          </DropdownMenu.Item>
          {authEnabled && (
            <>
              <DropdownMenu.Separator className="my-1 h-px bg-border" />
              <DropdownMenu.Item
                onSelect={() => void signOut().catch(() => undefined)}
                className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-fg outline-none data-[highlighted]:bg-bg-subtle"
              >
                <LogOut className="size-4" />
                Sign out
              </DropdownMenu.Item>
            </>
          )}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );

  const sidebarBody = (
    <>
      <div className="border-b border-border px-3 py-3">{workspaceMenu}</div>
      <div className="border-b border-border px-3 py-2">
        <button
          type="button"
          onClick={() => setPaletteOpen(true)}
          className="flex h-10 w-full items-center gap-2.5 rounded-lg px-2.5 text-sm text-muted transition-colors hover:bg-bg-subtle hover:text-fg"
        >
          <Search className="size-4" strokeWidth={1.75} />
          Search
          <kbd className="ml-auto rounded border border-border bg-bg-elevated px-1.5 py-0.5 font-mono text-[10px] text-subtle">⌘K</kbd>
        </button>
      </div>
      <nav aria-label="Main" className="flex-1 overflow-y-auto px-3 py-2">
        {NAV_GROUPS.map((group) => {
          const isCollapsed = group.label ? collapsed[group.id] : false;
          return (
            <div key={group.id} className={cn(group.label && "mt-2 border-t border-border pt-2")}>
              {group.label && (
                <button
                  type="button"
                  aria-expanded={!isCollapsed}
                  onClick={() => setCollapsed((c) => ({ ...c, [group.id]: !c[group.id] }))}
                  className="flex h-9 w-full items-center justify-between rounded-md px-2.5 text-[13px] font-medium text-muted transition-colors hover:text-fg"
                >
                  {group.label}
                  <ChevronDown className={cn("size-4 transition-transform", isCollapsed && "-rotate-90")} />
                </button>
              )}
              {!isCollapsed && (
                <ul className="flex flex-col gap-0.5">
                  {group.items.map((item) => {
                    const active = isActive(pathname, item.to);
                    const count = counts[item.to];
                    return (
                      <li key={item.to}>
                        <Link
                          to={item.to}
                          preload="intent"
                          aria-current={active ? "page" : undefined}
                          className={cn(
                            "relative flex h-10 items-center gap-2.5 rounded-lg px-2.5 text-sm transition-colors",
                            active ? "bg-bg-subtle font-medium text-fg" : "text-muted hover:bg-bg-elevated hover:text-fg",
                          )}
                        >
                          {active && <span aria-hidden className="absolute -left-3 top-1.5 bottom-1.5 w-[3px] rounded-r bg-accent" />}
                          <item.icon className="size-[18px]" strokeWidth={1.75} />
                          {item.label}
                          {typeof count === "number" && (
                            <span className="ml-auto rounded bg-bg-elevated px-1.5 py-px font-mono text-[10px] text-muted tabular-nums">
                              {count}
                            </span>
                          )}
                        </Link>
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>
          );
        })}
      </nav>
      <div className="border-t border-border px-3 py-3">
        <button
          type="button"
          onClick={() => setAgentDrawerOpen(true)}
          className="flex h-10 w-full items-center gap-2.5 rounded-lg px-2.5 text-sm text-muted transition-colors hover:bg-bg-subtle hover:text-fg"
          title="Open the AI agent chat"
        >
          <Bot className="size-[18px]" strokeWidth={1.75} />
          AI Agent
          <span className="relative ml-auto flex size-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-sage opacity-60" />
            <span className="relative inline-flex size-2 rounded-full bg-sage" />
          </span>
        </button>
        <div className="mt-2 px-2.5 text-[11px] leading-relaxed text-subtle">
          Public CTI only. Evidence-preserving ingest.
        </div>
      </div>
    </>
  );

  return (
    <div className={cn("flex h-dvh w-full overflow-hidden text-fg app-shell-root", uiStyle === "liquid-glass" ? "bg-transparent" : "bg-bg")}>
      {/* Desktop sidebar */}
      <aside
        className={cn(
          "hidden h-full w-64 shrink-0 select-none flex-col border-r border-border md:flex",
          uiStyle === "liquid-glass" ? "bg-bg/80 backdrop-blur-xl" : "bg-bg",
        )}
      >
        {sidebarBody}
      </aside>

      {/* Mobile drawer */}
      <Dialog.Root open={mobileNavOpen} onOpenChange={setMobileNavOpen}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-40 bg-black/50 md:hidden" />
          <Dialog.Content className="fixed inset-y-0 left-0 z-50 flex w-[82vw] max-w-xs flex-col border-r border-border bg-bg md:hidden">
            <Dialog.Title className="sr-only">Navigation</Dialog.Title>
            <Dialog.Description className="sr-only">Main navigation</Dialog.Description>
            <Dialog.Close
              aria-label="Close navigation"
              className="absolute right-3 top-4 z-10 rounded-md p-1.5 text-muted hover:bg-bg-subtle hover:text-fg"
            >
              <X className="size-4" />
            </Dialog.Close>
            {sidebarBody}
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      <div className="flex h-full min-w-0 flex-1 flex-col overflow-hidden">
        {/* Mobile top bar (desktop pages carry their own header) */}
        <header className="flex shrink-0 items-center gap-2 border-b border-border bg-bg px-3 py-2 md:hidden">
          <button
            type="button"
            aria-label="Open navigation"
            onClick={() => setMobileNavOpen(true)}
            className="rounded-md p-2 text-muted hover:bg-bg-subtle hover:text-fg"
          >
            <Menu className="size-5" />
          </button>
          <AieMark className="size-6 text-accent" />
          <span className="text-sm font-semibold">AIE</span>
          <div className="ml-auto flex items-center gap-1">
            <button
              type="button"
              aria-label="Search"
              onClick={() => setPaletteOpen(true)}
              className="rounded-md p-2 text-muted hover:bg-bg-subtle hover:text-fg"
            >
              <Search className="size-5" />
            </button>
            <button
              type="button"
              aria-label="Open AI agent"
              onClick={() => setAgentDrawerOpen(true)}
              className="rounded-md p-2 text-muted hover:bg-bg-subtle hover:text-fg"
            >
              <Bot className="size-5" />
            </button>
          </div>
        </header>

        <main
          className={cn(
            "w-full flex-1",
            flush ? "flex flex-col overflow-hidden p-0" : "overflow-y-auto px-4 py-6 md:px-10 md:py-8",
            className,
          )}
        >
          {children}
        </main>
      </div>

      <AieAgentChatDrawer isOpen={agentDrawerOpen} onClose={() => setAgentDrawerOpen(false)} />
      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} navItems={PALETTE_ITEMS} />
    </div>
  );
}
