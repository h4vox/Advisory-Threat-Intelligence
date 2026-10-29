import { useMemo, useState, type ReactNode } from "react";
import * as Popover from "@radix-ui/react-popover";
import * as Dialog from "@radix-ui/react-dialog";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BookOpen, Bookmark, ChevronLeft, ChevronRight, FolderOpen, Info, LogOut, Save, Trash2, X } from "lucide-react";
import { MarkdownView } from "@/components/ui/markdown-view";
import { deleteGraphView, listGraphViews, saveGraphView, type SavedView, type SavedViewState } from "@/lib/aie/server-graph-views";
import { canBack, canForward, type Trail } from "@/lib/aie/graph/trail";
import type { GraphNode } from "@/lib/aie/graph/types";
import { cn } from "@/lib/cn";
import guide from "../../../docs/INTEL_GRAPH_GUIDE.md?raw";
import type { GraphTheme } from "./graph-style";

// ---------------------------------------------------------------------------
// Hint: a small (i) that explains an option
// ---------------------------------------------------------------------------

export function Hint({ children, label = "What is this?" }: { children: ReactNode; label?: string }) {
  return (
    <Popover.Root>
      <Popover.Trigger asChild>
        <button type="button" aria-label={label} className="inline-flex size-5 shrink-0 items-center justify-center rounded-full text-subtle hover:bg-bg-subtle hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
          <Info className="size-3.5" />
        </button>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content side="bottom" align="start" sideOffset={6} className="dropdown-liquid-glass z-50 max-w-[18rem] rounded-lg border border-border px-3 py-2 text-xs leading-relaxed text-fg shadow-xl">
          {children}
          <Popover.Arrow className="fill-[var(--color-border)]" />
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}

// ---------------------------------------------------------------------------
// Saved investigations (server, or this browser without MongoDB)
// ---------------------------------------------------------------------------

const LOCAL_KEY = "aie_graph_saved_views";

function readLocal(): SavedView[] {
  try {
    const v = JSON.parse(localStorage.getItem(LOCAL_KEY) ?? "[]");
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}
function writeLocal(views: SavedView[]) {
  try {
    localStorage.setItem(LOCAL_KEY, JSON.stringify(views.slice(0, 200)));
  } catch {
    /* storage unavailable */
  }
}

export function useSavedViews() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["graph-views"], queryFn: () => listGraphViews(), staleTime: 30_000 });
  const onServer = q.data?.available ?? false;
  const views = onServer ? q.data!.views : q.isSuccess ? readLocal() : [];
  const save = useMutation({
    mutationFn: async (v: { id?: string; name: string; note: string; state: SavedViewState }) => {
      if (onServer) return saveGraphView({ data: v });
      const now = new Date().toISOString();
      const all = readLocal();
      const view: SavedView = { id: v.id ?? `local_${Date.now().toString(36)}`, name: v.name, note: v.note, state: v.state, createdAt: all.find((x) => x.id === v.id)?.createdAt ?? now, updatedAt: now };
      writeLocal([view, ...all.filter((x) => x.id !== view.id)]);
      return view;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["graph-views"] }),
  });
  const remove = useMutation({
    mutationFn: async (id: string) => {
      if (onServer) return deleteGraphView({ data: { id } });
      writeLocal(readLocal().filter((x) => x.id !== id));
      return { ok: true };
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["graph-views"] }),
  });
  return { views, onServer, loading: q.isPending, save, remove };
}

// ---------------------------------------------------------------------------
// Trail bar (under the graph)
// ---------------------------------------------------------------------------

export function TrailBar({
  trail,
  nodeOf,
  theme,
  onJump,
  onBack,
  onForward,
  onExit,
  onSave,
  saved,
}: {
  trail: Trail;
  nodeOf: (id: string) => GraphNode | undefined;
  theme: GraphTheme;
  onJump: (k: number) => void;
  onBack: () => void;
  onForward: () => void;
  onExit: () => void;
  onSave: () => void;
  saved: ReactNode;
}) {
  const focused = trail.pos >= 0;
  const btn = "inline-flex h-7 shrink-0 items-center gap-1.5 rounded-md border border-border bg-bg-elevated px-2 text-xs text-muted hover:text-fg disabled:opacity-40 disabled:hover:text-muted";
  return (
    <div className="flex min-w-0 items-center gap-1.5 border-t border-border bg-bg px-2 py-1.5" role="navigation" aria-label="Investigation trail">
      {focused ? (
        <>
          <button type="button" className={btn} onClick={onBack} disabled={!canBack(trail)} title="Back to the previous step" aria-label="Back">
            <ChevronLeft className="size-3.5" />
          </button>
          <button type="button" className={btn} onClick={onForward} disabled={!canForward(trail)} title="Forward to the next step" aria-label="Forward">
            <ChevronRight className="size-3.5" />
          </button>
          <Hint label="About the trail">
            Every entity you focus is added here in order. Click a step to go back to it: later steps stay (fainter) so you can go forward again. Focusing a new entity from an earlier step
            replaces the steps after it. <b>Exit focus</b> returns to the overview and clears the trail (it asks first and offers to save it).
          </Hint>
          <ol className="flex min-w-0 flex-1 items-center gap-1 overflow-x-auto py-0.5 [scrollbar-width:thin]">
            {trail.steps.map((id, k) => {
              const n = nodeOf(id);
              const current = k === trail.pos;
              const after = k > trail.pos;
              return (
                <li key={`${id}-${k}`} className="flex shrink-0 items-center gap-1">
                  {k > 0 && <ChevronRight className={cn("size-3 text-subtle", after && "opacity-40")} />}
                  <button
                    type="button"
                    onClick={() => onJump(k)}
                    aria-current={current ? "step" : undefined}
                    title={n ? `${n.label}${current ? " (current)" : after ? " (forward)" : ""}` : id}
                    className={cn(
                      "inline-flex max-w-[12rem] items-center gap-1.5 rounded-md border px-2 py-1 text-[11px]",
                      current ? "border-primary bg-primary/10 font-semibold text-fg" : "border-border bg-bg-elevated text-muted hover:text-fg",
                      after && "opacity-50",
                    )}
                  >
                    <span aria-hidden className="inline-block size-1.5 shrink-0 rounded-full" style={{ backgroundColor: n ? theme.type[n.type] : "var(--color-subtle)" }} />
                    <span className="truncate">{n?.label ?? id.split(":").slice(1).join(":")}</span>
                  </button>
                </li>
              );
            })}
          </ol>
          <button type="button" className={btn} onClick={onSave} title="Save this trail and the current view">
            <Save className="size-3.5" /> <span className="hidden xl:inline">Save</span>
          </button>
          {saved}
          <button type="button" className={cn(btn, "text-fg")} onClick={onExit} title="Leave focus and return to the overview">
            <LogOut className="size-3.5" /> Exit focus
          </button>
        </>
      ) : (
        <>
          <span className="min-w-0 flex-1 truncate px-1 text-[11px] text-subtle">Double-click an entity (or use Focus on this) to start a trail.</span>
          {saved}
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Saved investigations menu
// ---------------------------------------------------------------------------

export function SavedViewsMenu({ views, onServer, onOpen, onDelete }: { views: SavedView[]; onServer: boolean; onOpen: (v: SavedView) => void; onDelete: (v: SavedView) => void }) {
  const [open, setOpen] = useState(false);
  return (
    <Popover.Root open={open} onOpenChange={setOpen}>
      <Popover.Trigger asChild>
        <button type="button" className="inline-flex h-7 shrink-0 items-center gap-1.5 rounded-md border border-border bg-bg-elevated px-2 text-xs text-muted hover:text-fg" title="Saved investigations">
          <FolderOpen className="size-3.5" /> <span className="hidden xl:inline">Saved</span>
          {views.length > 0 && <span className="rounded bg-bg-subtle px-1 font-mono text-[10px]">{views.length}</span>}
        </button>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content side="top" align="end" sideOffset={6} className="dropdown-liquid-glass z-50 w-[min(26rem,calc(100vw-2rem))] rounded-xl border border-border p-2 shadow-xl">
          <div className="flex items-center justify-between px-2 pb-2 pt-1">
            <span className="text-xs font-semibold uppercase tracking-wider text-subtle">Saved investigations</span>
            <span className="text-[10px] text-subtle">{onServer ? "Saved for your account" : "Kept in this browser"}</span>
          </div>
          {views.length === 0 ? (
            <p className="px-2 pb-2 text-xs text-muted">Nothing saved yet. Focus an entity, follow a trail, then use Save on the trail bar.</p>
          ) : (
            <ul className="max-h-80 space-y-1 overflow-y-auto">
              {views.map((v) => (
                <li key={v.id} className="group rounded-lg px-2 py-2 hover:bg-bg-subtle">
                  <div className="flex items-start gap-2">
                    <Bookmark className="mt-0.5 size-3.5 shrink-0" style={{ color: "var(--color-primary)" }} />
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-sm font-medium">{v.name}</div>
                      <div className="truncate text-[11px] text-subtle">{v.state.labels.join(" → ")}</div>
                      {v.note && <div className="mt-0.5 line-clamp-2 text-[11px] text-muted">{v.note}</div>}
                      <div className="mt-0.5 text-[10px] text-subtle">
                        {v.state.trail.length} step{v.state.trail.length === 1 ? "" : "s"} · {v.state.dimension.toUpperCase()} · {v.state.hops === 2 ? "2 hops" : "direct links"} · {new Date(v.updatedAt).toLocaleDateString()}
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        onOpen(v);
                        setOpen(false);
                      }}
                      className="h-7 shrink-0 rounded-md px-2 text-xs font-medium hover:bg-bg-elevated"
                      style={{ color: "var(--color-primary)" }}
                    >
                      Open
                    </button>
                    <button type="button" onClick={() => onDelete(v)} aria-label={`Delete ${v.name}`} title="Delete" className="inline-flex size-7 shrink-0 items-center justify-center rounded-md text-subtle hover:bg-bg-elevated hover:text-danger">
                      <Trash2 className="size-3.5" />
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}

// ---------------------------------------------------------------------------
// Dialogs: save, exit focus, guide
// ---------------------------------------------------------------------------

function DialogFrame({ open, onOpenChange, title, description, children, wide }: { open: boolean; onOpenChange: (o: boolean) => void; title: string; description?: string; children: ReactNode; wide?: boolean }) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/50 backdrop-blur-[2px]" />
        <Dialog.Content
          className={cn(
            "dropdown-liquid-glass fixed left-1/2 top-1/2 z-50 flex max-h-[85vh] -translate-x-1/2 -translate-y-1/2 flex-col rounded-xl border border-border p-5 focus:outline-none",
            wide ? "w-[min(46rem,calc(100vw-2rem))]" : "w-[min(30rem,calc(100vw-2rem))]",
          )}
        >
          <div className="mb-3 flex items-start justify-between gap-3">
            <div>
              <Dialog.Title className="text-base font-semibold text-fg">{title}</Dialog.Title>
              {description && <Dialog.Description className="mt-0.5 text-sm text-muted">{description}</Dialog.Description>}
            </div>
            <Dialog.Close aria-label="Close" className="inline-flex size-7 items-center justify-center rounded-md text-muted hover:bg-bg-subtle hover:text-fg">
              <X className="size-4" />
            </Dialog.Close>
          </div>
          <div className="min-h-0 overflow-y-auto">{children}</div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

export function SaveViewDialog({
  open,
  onOpenChange,
  labels,
  onSave,
  busy,
  error,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  labels: string[];
  onSave: (name: string, note: string) => void;
  busy: boolean;
  error?: string | null;
}) {
  const suggested = useMemo(() => (labels.length ? `${labels[0]}${labels.length > 1 ? ` → ${labels[labels.length - 1]}` : ""}` : "Investigation"), [labels]);
  const [name, setName] = useState("");
  const [note, setNote] = useState("");
  const field = "w-full rounded-lg border border-border bg-bg-elevated px-3 text-sm text-fg placeholder:text-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/60";
  return (
    <DialogFrame open={open} onOpenChange={onOpenChange} title="Save investigation" description="Saves the trail and the current view: filters, lens, detail, 2D/3D and depth.">
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          onSave(name.trim() || suggested, note.trim());
        }}
      >
        <p className="rounded-lg border border-border bg-bg-elevated px-3 py-2 text-xs text-muted">{labels.join(" → ") || "No steps yet"}</p>
        <label className="block text-sm">
          <span className="mb-1 block text-xs text-muted">Name</span>
          <input autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder={suggested} maxLength={80} className={cn(field, "h-9")} />
        </label>
        <label className="block text-sm">
          <span className="mb-1 block text-xs text-muted">Note (optional)</span>
          <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={3} maxLength={500} placeholder="What you were looking into, what you found…" className={cn(field, "py-2")} />
        </label>
        {error && <p className="text-xs text-danger">{error}</p>}
        <div className="flex justify-end gap-2">
          <Dialog.Close className="h-9 rounded-lg border border-border px-3 text-sm hover:bg-bg-subtle">Cancel</Dialog.Close>
          <button type="submit" disabled={busy} className="btn-primary inline-flex h-9 items-center gap-1.5 rounded-lg px-4 text-sm font-semibold disabled:opacity-70">
            <Save className="size-4" /> {busy ? "Saving…" : "Save"}
          </button>
        </div>
      </form>
    </DialogFrame>
  );
}

export function ExitFocusDialog({ open, onOpenChange, labels, onLeave, onSaveFirst }: { open: boolean; onOpenChange: (o: boolean) => void; labels: string[]; onLeave: () => void; onSaveFirst: () => void }) {
  return (
    <DialogFrame open={open} onOpenChange={onOpenChange} title="Leave focus?" description="You will return to the overview, and this trail will be cleared.">
      <p className="mb-4 rounded-lg border border-border bg-bg-elevated px-3 py-2 text-xs text-muted">
        {labels.length} step{labels.length === 1 ? "" : "s"}: {labels.join(" → ")}
      </p>
      <div className="flex flex-wrap justify-end gap-2">
        <Dialog.Close className="h-9 rounded-lg border border-border px-3 text-sm hover:bg-bg-subtle">Stay in focus</Dialog.Close>
        <button type="button" onClick={onSaveFirst} className="inline-flex h-9 items-center gap-1.5 rounded-lg border border-border px-3 text-sm hover:bg-bg-subtle">
          <Save className="size-4" /> Save trail, then leave
        </button>
        <button type="button" onClick={onLeave} className="btn-primary inline-flex h-9 items-center gap-1.5 rounded-lg px-4 text-sm font-semibold">
          <LogOut className="size-4" /> Leave focus
        </button>
      </div>
    </DialogFrame>
  );
}

/** Joins hard-wrapped lines into their paragraph or list item (the viewer treats each line as a block). */
function unwrapMarkdown(md: string): string {
  const out: string[] = [];
  for (const line of md.split("\n")) {
    const prev = out[out.length - 1];
    const startsBlock = /^\s*([-*]\s|\d+\.\s|#|\||>|```)/.test(line);
    if (line.trim() && prev?.trim() && !startsBlock && !/^\s*(\||#|```)/.test(prev)) out[out.length - 1] = `${prev.trimEnd()} ${line.trim()}`;
    else out.push(line);
  }
  return out.join("\n");
}

export function GuideButton() {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button type="button" onClick={() => setOpen(true)} className="inline-flex h-7 items-center gap-1.5 rounded-md border border-border bg-bg-elevated px-2.5 text-xs text-muted hover:text-fg" title="How to use the Intel Graph">
        <BookOpen className="size-3.5" /> Guide
      </button>
      <DialogFrame open={open} onOpenChange={setOpen} title="Intel Graph guide" wide>
        <MarkdownView content={unwrapMarkdown(guide.replace(/^# .*\n+/, ""))} className="text-sm" />
      </DialogFrame>
    </>
  );
}
