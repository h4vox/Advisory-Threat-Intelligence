import { useEffect, useState, type ComponentType, type ReactNode } from "react";
import { Link, useRouterState } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import * as Dialog from "@radix-ui/react-dialog";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import * as Popover from "@radix-ui/react-popover";
import {
  Activity,
  Bell,
  Bot,
  ChevronDown,
  ChevronRight,
  Cpu,
  Globe2,
  Keyboard,
  Layers,
  Waypoints,
  LayoutDashboard,
  Library,
  LogOut,
  Menu,
  Moon,
  Search,
  Settings,
  Shapes,
  Sparkles,
  Square,
  Sun,
  Upload,
  UserRound,
  X,
  Route as RouteIcon,
  ScanSearch,
  ScrollText,
  UsersRound,
} from "lucide-react";
import { cn } from "@/lib/cn";
import { getDashboard, getStorageStats } from "@/lib/aie/server";
import { formatDateTime } from "@/lib/aie/format";
import { useAppSession, useSignOut, type SessionUser } from "./auth/use-app-session";
import { AieAgentChatDrawer } from "./aie-agent-chat-drawer";
import { AGENT_ASK_EVENT, ENTITY_CONTEXT_EVENT, askAgentAbout, isEntityDrag, readDroppedEntity } from "./agent-handoff";
import { EntityContextSheet } from "./intel/entity-context-sheet";
import { CommandPalette, type PaletteNavItem } from "./layout/command-palette";
import { actorCrumbName } from "./actors/actor-names";

type NavIcon = ComponentType<{ className?: string; strokeWidth?: number }>;
type NavItem = { to: string; label: string; icon: NavIcon };
type NavGroup = { id: string; label: string | null; items: NavItem[] };
type Theme = "dark" | "light";
type UiStyle = "default" | "liquid-glass";

const NAV_GROUPS: NavGroup[] = [
  { id: "home", label: null, items: [{ to: "/", label: "Overview", icon: LayoutDashboard }] },
  {
    id: "intel",
    label: "Intelligence",
    items: [
      { to: "/library", label: "Library", icon: Library },
      { to: "/search", label: "Search", icon: ScanSearch },
      { to: "/actors", label: "Threat actors", icon: UsersRound },
      { to: "/matrix", label: "ATT&CK Matrix", icon: Layers },
      { to: "/graph", label: "Intel Graph", icon: Waypoints },
    ],
  },
  {
    id: "emulation",
    label: "Emulation",
    items: [
      { to: "/purple", label: "Purple paths", icon: RouteIcon },
      { to: "/advisories", label: "Advisories", icon: ScrollText },
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

const DEV_ITEMS: NavItem[] = [{ to: "/ui-kit", label: "UI kit", icon: Shapes }];

const PALETTE_ITEMS: PaletteNavItem[] = [
  ...NAV_GROUPS.flatMap((g) => g.items.map((i) => ({ ...i, group: g.label ?? "Home" }))),
  // Developer reference, reachable from search only.
  ...DEV_ITEMS.map((i) => ({ ...i, group: "Developer" })),
];

function isActive(pathname: string, to: string) {
  return to === "/" ? pathname === "/" : pathname === to || pathname.startsWith(`${to}/`);
}

/** Breadcrumb trail for the current route, derived from the nav model. */
function breadcrumbFor(pathname: string): string[] {
  const actor = pathname.match(/^\/actors\/([^/]+)/);
  if (actor) {
    let id = actor[1];
    try {
      id = decodeURIComponent(id);
    } catch {
      /* keep raw */
    }
    return ["Intelligence", "Threat actors", actorCrumbName(id) ?? id];
  }
  for (const g of NAV_GROUPS) {
    for (const item of g.items) {
      if (!isActive(pathname, item.to)) continue;
      const trail = g.label ? [g.label, item.label] : [item.label];
      if (item.to !== "/" && pathname !== item.to) trail.push(item.to === "/library" ? "Report" : "Detail");
      return trail;
    }
  }
  const dev = DEV_ITEMS.find((i) => isActive(pathname, i.to));
  if (dev) return ["Developer", dev.label];
  return ["AIE"];
}

function AieMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden>
      <rect x="1" y="1" width="30" height="30" rx="7" fill="currentColor" />
      <path d="M9 23.5 L16 8.5 L23 23.5" fill="none" stroke="var(--color-primary-fg)" strokeWidth="2.2" strokeLinejoin="round" />
      <path d="M12 18h8" stroke="var(--color-primary-fg)" strokeWidth="2.2" />
    </svg>
  );
}

function applyGlassBlurTokens(val: number) {
  if (typeof document === "undefined") return;
  const blurPx = Math.round(6 + (val / 100) * 36.0);
  const opacityDark = (0.05 + (val / 100) * 0.16).toFixed(3);
  const opacityLight = (0.5 + (val / 100) * 0.28).toFixed(3);
  const specular = (0.22 + (val / 100) * 0.38).toFixed(3);
  document.documentElement.style.setProperty("--glass-blur-ratio", `${val}%`);
  document.documentElement.style.setProperty("--glass-blur", `${blurPx}px`);
  document.documentElement.style.setProperty("--glass-opacity-dark", `${opacityDark}`);
  document.documentElement.style.setProperty("--glass-opacity-light", `${opacityLight}`);
  document.documentElement.style.setProperty("--glass-specular-opacity", `${specular}`);
}

function safeGet(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}
function safeSet(key: string, value: string) {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* storage unavailable: preference lasts for this page only */
  }
}

function applyTheme(theme: Theme) {
  document.documentElement.setAttribute("data-theme", theme);
  document.documentElement.classList.toggle("light", theme === "light");
}

function applyStyle(style: UiStyle) {
  document.documentElement.setAttribute("data-style", style);
  document.documentElement.classList.toggle("theme-liquid-glass", style === "liquid-glass");
  if (style === "liquid-glass") {
    const ratio = parseInt(safeGet("aie_glass_blur_ratio") ?? "70", 10);
    applyGlassBlurTokens(!isNaN(ratio) && ratio >= 5 && ratio <= 110 ? ratio : 70);
  }
}


function signInLabel(user: SessionUser | null): string {
  if (!user) return "Not signed in";
  if (user.method === "password") return "Username and password";
  if (user.method === "sso") return "Single sign-on";
  return "Sign-in off: local workspace user";
}

function initials(user: SessionUser | null) {
  const src = (user?.displayName || user?.primaryEmail || "Analyst").trim();
  const parts = src.split(/[\s@._-]+/).filter(Boolean);
  return ((parts[0]?.[0] ?? "A") + (parts[1]?.[0] ?? "")).toUpperCase();
}

function Avatar({ user, size = "md" }: { user: SessionUser | null; size?: "md" | "lg" }) {
  const box = size === "lg" ? "size-12 text-base" : "size-8 text-xs";
  if (user?.profileImageUrl) {
    return <img src={user.profileImageUrl} alt="" className={cn("shrink-0 rounded-full object-cover", box)} />;
  }
  return (
    <span
      aria-hidden
      className={cn("inline-flex shrink-0 items-center justify-center rounded-full font-semibold", box)}
      style={{
        color: "var(--color-primary)",
        backgroundColor: "color-mix(in oklab, var(--color-primary) 18%, transparent)",
      }}
    >
      {initials(user)}
    </span>
  );
}

const iconBtn =
  "inline-flex size-9 shrink-0 items-center justify-center rounded-lg text-muted transition-colors hover:bg-bg-subtle hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";
const menuItem =
  "flex cursor-pointer items-center gap-2.5 rounded-md px-2 py-1.5 text-sm text-fg outline-none data-[highlighted]:bg-bg-subtle data-[disabled]:cursor-not-allowed data-[disabled]:opacity-50";

function StyleSwitch({
  value,
  onChange,
  labels = "xl",
}: {
  value: UiStyle;
  onChange: (s: UiStyle) => void;
  /** "xl": text from the xl breakpoint (top bar); "always": always show text. */
  labels?: "xl" | "always";
}) {
  const items: Array<{ v: UiStyle; label: string; icon: NavIcon }> = [
    { v: "default", label: "Default", icon: Square },
    { v: "liquid-glass", label: "Liquid glass", icon: Sparkles },
  ];
  return (
    <div role="radiogroup" aria-label="UI style" className="inline-flex h-9 items-center rounded-lg border border-border bg-bg-elevated p-0.5">
      {items.map(({ v, label, icon: Icon }) => {
        const active = value === v;
        return (
          <button
            key={v}
            type="button"
            role="radio"
            aria-checked={active}
            title={`${label} style`}
            onClick={() => onChange(v)}
            className={cn(
              "inline-flex h-full items-center gap-1.5 rounded-md px-2.5 text-xs font-medium transition-colors",
              active ? "bg-bg-subtle text-fg shadow-xs" : "text-muted hover:text-fg",
            )}
          >
            <Icon className={cn("size-3.5", active && v === "liquid-glass" && "text-primary")} strokeWidth={1.9} />
            <span className={cn(labels === "xl" && "sr-only xl:not-sr-only")}>{label}</span>
          </button>
        );
      })}
    </div>
  );
}

function ThemeSwitch({ value, onChange }: { value: Theme; onChange: (t: Theme) => void }) {
  return (
    <div role="radiogroup" aria-label="Theme" className="inline-flex h-9 items-center rounded-lg border border-border bg-bg-elevated p-0.5">
      {(["dark", "light"] as const).map((t) => {
        const active = value === t;
        const Icon = t === "dark" ? Moon : Sun;
        return (
          <button
            key={t}
            type="button"
            role="radio"
            aria-checked={active}
            onClick={() => onChange(t)}
            className={cn(
              "inline-flex h-full items-center gap-1.5 rounded-md px-2.5 text-xs font-medium transition-colors",
              active ? "bg-bg-subtle text-fg shadow-xs" : "text-muted hover:text-fg",
            )}
          >
            <Icon className="size-3.5" strokeWidth={1.9} />
            {t === "dark" ? "Dark" : "Light"}
          </button>
        );
      })}
    </div>
  );
}

function outcomeTone(outcome: string) {
  const o = outcome.toLowerCase();
  if (/(fail|error|reject|block)/.test(o)) return "var(--color-danger)";
  if (/(skip|dup|pending|queue)/.test(o)) return "var(--color-warn)";
  if (/(acquir|ingest|stored|success|ok|created)/.test(o)) return "var(--color-sage)";
  return "var(--color-info)";
}

function ActivityPopover() {
  const [open, setOpen] = useState(false);
  // Shares the Overview cache; fetched only once the popover has been opened.
  const [requested, setRequested] = useState(false);
  const q = useQuery({
    queryKey: ["dashboard"],
    queryFn: () => getDashboard(),
    enabled: requested,
    staleTime: 30_000,
  });
  const events = q.data?.events ?? [];
  return (
    <Popover.Root
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        if (o) setRequested(true);
      }}
    >
      <Popover.Trigger asChild>
        <button type="button" aria-label="Activity" title="Recent crawl & ingest activity" className={cn(iconBtn, "relative")}>
          <Bell className="size-[18px]" strokeWidth={1.75} />
          {events.length > 0 && (
            <span aria-hidden className="absolute right-2 top-2 size-1.5 rounded-full bg-primary ring-2 ring-bg" />
          )}
        </button>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content
          align="end"
          sideOffset={8}
          className="dropdown-liquid-glass z-50 w-[min(24rem,calc(100vw-2rem))] overflow-hidden rounded-xl"
        >
          <div className="flex items-center justify-between border-b border-border px-4 py-3">
            <span className="flex items-center gap-2 text-sm font-medium text-fg">
              <Activity className="size-4 text-primary" strokeWidth={1.9} />
              Activity
            </span>
            <span className="text-xs text-subtle">Crawl & ingest events</span>
          </div>
          <div className="max-h-[22rem] overflow-y-auto">
            {q.isLoading && <p className="px-4 py-8 text-center text-sm text-muted">Loading recent events…</p>}
            {q.error && <p className="px-4 py-8 text-center text-sm text-danger">{q.error.message}</p>}
            {q.data && events.length === 0 && (
              <div className="px-4 py-8 text-center">
                <p className="text-sm font-medium text-fg">No activity yet</p>
                <p className="mt-1 text-xs text-muted">Crawl and ingest outcomes appear here as they happen.</p>
              </div>
            )}
            <ul className="divide-y divide-border">
              {events.slice(0, 12).map((e) => (
                <li key={e.id} className="px-4 py-2.5">
                  <div className="flex items-center justify-between gap-3">
                    <span className="flex min-w-0 items-center gap-2 text-xs font-medium" style={{ color: outcomeTone(e.outcome) }}>
                      <span className="size-1.5 shrink-0 rounded-full" style={{ backgroundColor: outcomeTone(e.outcome) }} />
                      <span className="truncate capitalize">{e.outcome.replace(/_/g, " ").toLowerCase()}</span>
                    </span>
                    <span className="shrink-0 text-[11px] text-subtle tabular-nums">{formatDateTime(e.createdAt)}</span>
                  </div>
                  <p className="mt-1 truncate font-mono text-[11px] text-muted" title={e.url}>
                    {e.url}
                  </p>
                </li>
              ))}
            </ul>
          </div>
          <div className="border-t border-border px-4 py-2.5">
            <Link to="/ingest" onClick={() => setOpen(false)} className="text-xs font-medium text-primary hover:underline">
              Open ingest
            </Link>
          </div>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}

const SHORTCUTS: Array<{ keys: string[]; label: string }> = [
  { keys: ["⌘", "K"], label: "Open search (Ctrl+K on Windows / Linux)" },
  { keys: ["?"], label: "Show keyboard shortcuts" },
  { keys: ["↑", "↓"], label: "Move through search results" },
  { keys: ["Enter"], label: "Open the highlighted result" },
  { keys: ["Esc"], label: "Close dialogs, drawers and menus" },
];

function DialogShell({
  open,
  onOpenChange,
  title,
  description,
  children,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  title: string;
  description: string;
  children: ReactNode;
}) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/50 backdrop-blur-[2px]" />
        <Dialog.Content className="dropdown-liquid-glass fixed left-1/2 top-1/2 z-50 w-[min(32rem,calc(100vw-2rem))] -translate-x-1/2 -translate-y-1/2 rounded-xl p-5 focus:outline-none">
          <div className="mb-4 flex items-start justify-between gap-4">
            <div>
              <Dialog.Title className="text-base font-semibold text-fg">{title}</Dialog.Title>
              <Dialog.Description className="mt-0.5 text-sm text-muted">{description}</Dialog.Description>
            </div>
            <Dialog.Close aria-label="Close" className={iconBtn}>
              <X className="size-4" />
            </Dialog.Close>
          </div>
          {children}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
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
  const [theme, setTheme] = useState<Theme>("dark");
  const [uiStyle, setUiStyle] = useState<UiStyle>("default");
  const [agentDrawerOpen, setAgentDrawerOpen] = useState(false);
  // Requests handed to the agent from elsewhere (buttons, drag-and-drop), and the entity context panel.
  const [agentAsk, setAgentAsk] = useState<{ id: number; text: string } | null>(null);
  const [contextRef, setContextRef] = useState<string | null>(null);
  const [agentDropActive, setAgentDropActive] = useState(false);
  useEffect(() => {
    const onAsk = (e: Event) => {
      const text = (e as CustomEvent<{ text?: string }>).detail?.text;
      if (!text) return;
      setAgentAsk({ id: Date.now(), text });
      setAgentDrawerOpen(true);
    };
    const onContext = (e: Event) => {
      const ref = (e as CustomEvent<{ ref?: string }>).detail?.ref;
      if (ref) setContextRef(ref);
    };
    window.addEventListener(AGENT_ASK_EVENT, onAsk);
    window.addEventListener(ENTITY_CONTEXT_EVENT, onContext);
    return () => {
      window.removeEventListener(AGENT_ASK_EVENT, onAsk);
      window.removeEventListener(ENTITY_CONTEXT_EVENT, onContext);
    };
  }, []);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const session = useAppSession();
  const user = session.user;
  const signOutAll = useSignOut();
  const crumbs = breadcrumbFor(pathname);

  const countsQuery = useQuery({
    queryKey: ["nav-counts"],
    queryFn: () => getStorageStats(),
    staleTime: 5 * 60_000,
  });
  // Only show counts the store actually reports (no badge rather than a misleading 0).
  const storeCounts = countsQuery.data?.configured ? countsQuery.data : undefined;
  const counts: Record<string, number | undefined> = {
    "/library": storeCounts?.visibleReports ?? storeCounts?.totalReports,
    "/sources": storeCounts?.totalSources,
  };

  // ⌘K / Ctrl+K opens search; "?" opens the shortcuts sheet (outside text fields).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
        return;
      }
      const t = e.target as HTMLElement | null;
      const typing = t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName));
      if (e.key === "?" && !typing && !e.metaKey && !e.ctrlKey) {
        e.preventDefault();
        setShortcutsOpen(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // Close the mobile drawer on navigation.
  useEffect(() => {
    setMobileNavOpen(false);
  }, [pathname]);

  // Restore preferences and stay in sync with Settings, which writes the same keys.
  useEffect(() => {
    const sync = () => {
      const t: Theme = safeGet("aie_theme") === "light" ? "light" : "dark"; // dark-first
      const s: UiStyle = safeGet("aie_ui_style") === "liquid-glass" ? "liquid-glass" : "default";
      setTheme(t);
      setUiStyle(s);
      applyTheme(t);
      applyStyle(s);
    };
    sync();
    const onRatio = () => {
      const parsed = parseInt(safeGet("aie_glass_blur_ratio") ?? "", 10);
      if (!isNaN(parsed)) applyGlassBlurTokens(parsed);
    };
    window.addEventListener("aie-style-changed", sync);
    window.addEventListener("aie-theme-changed", sync);
    window.addEventListener("aie-glass-ratio-changed", onRatio);
    return () => {
      window.removeEventListener("aie-style-changed", sync);
      window.removeEventListener("aie-theme-changed", sync);
      window.removeEventListener("aie-glass-ratio-changed", onRatio);
    };
  }, []);

  const changeTheme = (next: Theme) => {
    setTheme(next);
    safeSet("aie_theme", next);
    applyTheme(next);
    window.dispatchEvent(new Event("aie-theme-changed"));
  };

  const changeStyle = (next: UiStyle) => {
    setUiStyle(next);
    safeSet("aie_ui_style", next);
    applyStyle(next);
    window.dispatchEvent(new Event("aie-style-changed"));
  };

  const displayName = user?.displayName || user?.username || "Analyst";
  const email = user?.primaryEmail || "";
  const identityLine = email || (user?.username ? `@${user.username}` : "No email on this session");
  const canSignOut = Boolean(user && user.method !== "dev");

  const profileMenu = (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <button
          type="button"
          aria-label="Account menu"
          className="inline-flex h-9 items-center gap-2 rounded-lg pl-0.5 pr-1.5 transition-colors hover:bg-bg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <Avatar user={user} />
          <ChevronDown className="hidden size-3.5 text-subtle md:block" />
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content align="end" sideOffset={8} className="dropdown-liquid-glass z-50 w-64 rounded-xl p-1.5">
          <div className="flex items-center gap-3 px-2 py-2">
            <Avatar user={user} />
            <div className="min-w-0">
              <div className="truncate text-sm font-medium text-fg">{displayName}</div>
              <div className="truncate text-xs text-muted">{identityLine}</div>
            </div>
          </div>
          <DropdownMenu.Separator className="my-1 h-px bg-border" />
          <DropdownMenu.Item onSelect={() => setProfileOpen(true)} className={menuItem}>
            <UserRound className="size-4 text-muted" />
            Profile
          </DropdownMenu.Item>
          <DropdownMenu.Item asChild className={menuItem}>
            <Link to="/settings">
              <Settings className="size-4 text-muted" />
              Settings
            </Link>
          </DropdownMenu.Item>
          <DropdownMenu.Item onSelect={() => setShortcutsOpen(true)} className={menuItem}>
            <Keyboard className="size-4 text-muted" />
            Keyboard shortcuts
            <kbd className="ml-auto rounded border border-border px-1.5 font-mono text-[10px] text-subtle">?</kbd>
          </DropdownMenu.Item>
          {/* Appearance lives in the top bar on desktop; mobile reaches it here. */}
          <div className="md:hidden">
            <DropdownMenu.Separator className="my-1 h-px bg-border" />
            <DropdownMenu.Item onSelect={() => changeTheme(theme === "dark" ? "light" : "dark")} className={menuItem}>
              {theme === "dark" ? <Sun className="size-4 text-muted" /> : <Moon className="size-4 text-muted" />}
              {theme === "dark" ? "Light theme" : "Dark theme"}
            </DropdownMenu.Item>
            <DropdownMenu.Item
              onSelect={() => changeStyle(uiStyle === "liquid-glass" ? "default" : "liquid-glass")}
              className={menuItem}
            >
              <Sparkles className="size-4 text-muted" />
              {uiStyle === "liquid-glass" ? "Default style" : "Liquid glass style"}
            </DropdownMenu.Item>
          </div>
          <DropdownMenu.Separator className="my-1 h-px bg-border" />
          <DropdownMenu.Item
            disabled={!canSignOut}
            onSelect={() => void signOutAll({ hasSsoSession: session.hasSsoSession })}
            className={menuItem}
            title={canSignOut ? undefined : "Sign-in is off for this local workspace"}
          >
            <LogOut className="size-4 text-muted" />
            Sign out
            {!canSignOut && <span className="ml-auto text-[11px] text-subtle">Sign-in off</span>}
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );

  const sidebarBody = (
    <>
      <Link to="/" className="flex h-14 shrink-0 items-center gap-2.5 border-b border-border px-5">
        <AieMark className="size-7 text-primary" />
        <span className="min-w-0 leading-tight">
          <span className="block text-sm font-semibold text-fg">AIE</span>
          <span className="block truncate text-[11px] text-subtle">Adversary Intelligence Engine</span>
        </span>
      </Link>
      <nav aria-label="Main" className="flex-1 overflow-y-auto px-3 py-3">
        {NAV_GROUPS.map((group) => {
          const isCollapsed = group.label ? collapsed[group.id] : false;
          return (
            <div key={group.id} className={cn(group.label && "mt-3")}>
              {group.label && (
                <button
                  type="button"
                  aria-expanded={!isCollapsed}
                  onClick={() => setCollapsed((c) => ({ ...c, [group.id]: !c[group.id] }))}
                  className="flex h-8 w-full items-center justify-between rounded-md px-2.5 text-xs font-medium text-subtle transition-colors hover:text-fg"
                >
                  {group.label}
                  <ChevronDown className={cn("size-3.5 transition-transform", isCollapsed && "-rotate-90")} />
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
                            "relative flex h-9 items-center gap-2.5 rounded-lg px-2.5 text-sm transition-colors",
                            active ? "bg-bg-subtle font-medium text-fg" : "text-muted hover:bg-bg-subtle hover:text-fg",
                          )}
                        >
                          {active && <span aria-hidden className="absolute -left-3 top-1.5 bottom-1.5 w-[3px] rounded-r bg-primary" />}
                          <item.icon className={cn("size-[18px]", active && "text-primary")} strokeWidth={1.75} />
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
      <div className="border-t border-border px-5 py-3 text-[11px] leading-relaxed text-subtle">
        <span className="mb-1 flex items-center gap-1.5 font-medium text-muted">
          <span className="size-1.5 rounded-full bg-sage" />
          Pipeline online
        </span>
        Public CTI only. Evidence-preserving ingest.
      </div>
    </>
  );

  const searchTrigger = (
    <button
      type="button"
      onClick={() => setPaletteOpen(true)}
      className="flex h-9 w-full max-w-md items-center gap-2.5 rounded-lg border border-border bg-bg-elevated px-3 text-sm text-subtle transition-colors hover:border-border-strong hover:text-muted"
    >
      <Search className="size-4 shrink-0" strokeWidth={1.75} />
      <span className="truncate">Search reports, actors, techniques…</span>
      <kbd className="ml-auto shrink-0 rounded border border-border bg-bg-subtle px-1.5 py-0.5 font-mono text-[10px] text-muted">⌘K</kbd>
    </button>
  );

  return (
    <div className={cn("flex h-dvh w-full overflow-hidden text-fg app-shell-root", uiStyle === "liquid-glass" ? "bg-transparent" : "bg-bg")}>
      {/* Desktop sidebar */}
      <aside className="app-sidebar hidden h-full w-60 shrink-0 select-none flex-col border-r border-border bg-bg md:flex">
        {sidebarBody}
      </aside>

      {/* Mobile drawer */}
      <Dialog.Root open={mobileNavOpen} onOpenChange={setMobileNavOpen}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-40 bg-black/50 md:hidden" />
          <Dialog.Content className="app-sidebar fixed inset-y-0 left-0 z-50 flex w-[82vw] max-w-xs flex-col border-r border-border bg-bg md:hidden">
            <Dialog.Title className="sr-only">Navigation</Dialog.Title>
            <Dialog.Description className="sr-only">Main navigation</Dialog.Description>
            <Dialog.Close aria-label="Close navigation" className={cn(iconBtn, "absolute right-2 top-2.5 z-10")}>
              <X className="size-4" />
            </Dialog.Close>
            {sidebarBody}
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      <div className="flex h-full min-w-0 flex-1 flex-col overflow-hidden">
        {/* Global top bar */}
        <header className="app-topbar flex h-14 shrink-0 items-center gap-2 border-b border-border bg-bg px-2 md:gap-4 md:px-6">
          <button type="button" aria-label="Open navigation" onClick={() => setMobileNavOpen(true)} className={cn(iconBtn, "md:hidden")}>
            <Menu className="size-5" />
          </button>

          <nav aria-label="Breadcrumb" className="min-w-0 shrink-0 md:w-auto">
            <ol className="flex min-w-0 items-center gap-1.5 text-sm">
              {crumbs.map((c, i) => {
                const last = i === crumbs.length - 1;
                return (
                  <li key={`${c}-${i}`} className={cn("flex min-w-0 items-center gap-1.5", !last && "hidden md:flex")}>
                    <span className={cn("truncate", last ? "font-medium text-fg" : "text-muted")}>{c}</span>
                    {!last && <ChevronRight className="size-3.5 shrink-0 text-subtle" />}
                  </li>
                );
              })}
            </ol>
          </nav>

          <div className="hidden min-w-0 flex-1 md:flex md:justify-center lg:pl-4">{searchTrigger}</div>

          <div className="ml-auto flex shrink-0 items-center gap-1 md:gap-1.5">
            <button type="button" aria-label="Search" onClick={() => setPaletteOpen(true)} className={cn(iconBtn, "md:hidden")}>
              <Search className="size-5" />
            </button>
            <div className="hidden md:block">
              <StyleSwitch value={uiStyle} onChange={changeStyle} />
            </div>
            <button
              type="button"
              aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
              title={theme === "dark" ? "Light theme" : "Dark theme"}
              onClick={() => changeTheme(theme === "dark" ? "light" : "dark")}
              className={cn(iconBtn, "hidden md:inline-flex")}
            >
              {theme === "dark" ? <Sun className="size-[18px]" strokeWidth={1.75} /> : <Moon className="size-[18px]" strokeWidth={1.75} />}
            </button>
            <div className="hidden md:block">
              <ActivityPopover />
            </div>
            <button
              type="button"
              onClick={() => setAgentDrawerOpen(true)}
              title="Open the AI agent chat (drop an entity here to investigate it)"
              aria-label="Open AI agent"
              onDragOver={(e) => {
                if (!isEntityDrag(e)) return;
                e.preventDefault();
                e.dataTransfer.dropEffect = "copy";
                setAgentDropActive(true);
              }}
              onDragLeave={() => setAgentDropActive(false)}
              onDrop={(e) => {
                setAgentDropActive(false);
                const ent = readDroppedEntity(e);
                if (!ent) return;
                e.preventDefault();
                askAgentAbout(ent);
              }}
              className={cn(
                "inline-flex h-9 items-center gap-2 rounded-lg px-2 text-sm font-medium text-fg transition-colors hover:bg-bg-subtle md:border md:border-border md:bg-bg-elevated md:px-3",
                agentDropActive && "ring-2 ring-primary ring-offset-2 ring-offset-bg",
              )}
            >
              <Bot className="size-[18px] text-primary" strokeWidth={1.75} />
              <span className="hidden lg:inline">AI Agent</span>
            </button>
            <span aria-hidden className="mx-1 hidden h-6 w-px bg-border md:block" />
            {profileMenu}
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

      <DialogShell open={profileOpen} onOpenChange={setProfileOpen} title="Profile" description="Your analyst identity and workspace preferences.">
        <div className="flex items-center gap-4 rounded-lg border border-border bg-bg-subtle p-4">
          <Avatar user={user} size="lg" />
          <div className="min-w-0">
            <div className="truncate text-base font-semibold text-fg">{displayName}</div>
            <div className="truncate text-sm text-muted">{identityLine}</div>
          </div>
          <span className="ml-auto shrink-0 rounded-md px-2 py-0.5 text-xs font-medium text-primary" style={{ backgroundColor: "color-mix(in oklab, var(--color-primary) 14%, transparent)" }}>
            {user?.role === "admin" ? "Administrator" : "Analyst"}
          </span>
        </div>
        <dl className="mt-4 grid grid-cols-[minmax(0,8.5rem)_minmax(0,1fr)] gap-x-4 gap-y-2.5 text-sm">
          {user?.username ? (
            <>
              <dt className="text-muted">Username</dt>
              <dd className="truncate font-mono text-xs leading-5 text-fg">{user.username}</dd>
            </>
          ) : (
            <>
              <dt className="text-muted">User ID</dt>
              <dd className="truncate font-mono text-xs leading-5 text-fg">{user?.id ?? "Unknown"}</dd>
            </>
          )}
          <dt className="text-muted">Sign-in</dt>
          <dd className="text-fg">{signInLabel(user)}</dd>
          <dt className="text-muted">Role</dt>
          <dd className="text-fg">{user?.role === "admin" ? "Administrator" : "Analyst"}</dd>
        </dl>
        <p className="mt-3 text-xs text-subtle">The username and password are set in the server environment (AIE_ADMIN_USERNAME, AIE_ADMIN_PASSWORD).</p>
        <div className="mt-5 border-t border-border pt-4">
          <div className="mb-3 text-sm font-medium text-fg">Preferences</div>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <span className="text-sm text-muted">Theme</span>
            <ThemeSwitch value={theme} onChange={changeTheme} />
          </div>
          <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
            <span className="text-sm text-muted">UI style</span>
            <StyleSwitch value={uiStyle} onChange={changeStyle} labels="always" />
          </div>
        </div>
      </DialogShell>


      <DialogShell open={shortcutsOpen} onOpenChange={setShortcutsOpen} title="Keyboard shortcuts" description="Work faster without leaving the keyboard.">
        <ul className="divide-y divide-border rounded-lg border border-border">
          {SHORTCUTS.map((s) => (
            <li key={s.label} className="flex items-center justify-between gap-4 px-3 py-2.5 text-sm">
              <span className="text-muted">{s.label}</span>
              <span className="flex shrink-0 gap-1">
                {s.keys.map((k) => (
                  <kbd key={k} className="min-w-6 rounded border border-border bg-bg-subtle px-1.5 py-0.5 text-center font-mono text-[11px] text-fg">
                    {k}
                  </kbd>
                ))}
              </span>
            </li>
          ))}
        </ul>
      </DialogShell>

      <AieAgentChatDrawer isOpen={agentDrawerOpen} onClose={() => setAgentDrawerOpen(false)} ask={agentAsk} onAskHandled={() => setAgentAsk(null)} />
      <EntityContextSheet refValue={contextRef} onOpenChange={(open) => !open && setContextRef(null)} onRef={setContextRef} />
      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} navItems={PALETTE_ITEMS} />
    </div>
  );
}
