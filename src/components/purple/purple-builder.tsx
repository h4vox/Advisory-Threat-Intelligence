import { useEffect, useId, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { FileText, Layers, Loader2, Search, Sparkles, Swords, Users, X } from "lucide-react";
import { suggestPurpleSeeds, type PurpleSuggestion } from "@/lib/aie/server-emulation";
import { PURPLE_PLATFORMS, type PurplePlatform } from "@/lib/aie/purple/types";
import { SegmentedTabs } from "@/components/layout/page";
import { EntityIcon } from "@/components/ui/entity";
import { Select } from "@/components/ui/select";
import { cn } from "@/lib/cn";

export type BuilderKind = "actor" | "report" | "campaign" | "custom";

export type BuilderState = {
  kind: BuilderKind;
  value: string;
  /** Display label for the chosen value (e.g. "Akira" for G1024). */
  label: string;
  techniques: string[];
  platforms: PurplePlatform[];
  excludeHighRisk: boolean;
  maxSteps: number;
};

const KIND_TABS = [
  { value: "actor" as const, label: "Threat actor", icon: Users },
  { value: "report" as const, label: "Report", icon: FileText },
  { value: "campaign" as const, label: "Campaign", icon: Swords },
  { value: "custom" as const, label: "Techniques", icon: Layers },
];

const PLACEHOLDER: Record<BuilderKind, string> = {
  actor: "ATT&CK group, alias or G-ID (APT29, Cozy Bear, G1024)",
  report: "Search library reports by title or id",
  campaign: "ATT&CK campaign name or C-ID (C0024)",
  custom: "Add techniques by id or name (T1059.001, LSASS)",
};

const SUGGEST_KIND: Record<PurpleSuggestion["kind"], "actor" | "advisory" | "technique"> = {
  actor: "actor",
  campaign: "actor",
  report: "advisory",
  technique: "technique",
};

function useDebounced<T>(v: T, ms: number) {
  const [d, setD] = useState(v);
  useEffect(() => {
    const t = setTimeout(() => setD(v), ms);
    return () => clearTimeout(t);
  }, [v, ms]);
  return d;
}

export function PurpleBuilder({
  state,
  onChange,
  onGenerate,
  busy,
}: {
  state: BuilderState;
  onChange: (next: BuilderState) => void;
  onGenerate: (s: BuilderState) => void;
  busy: boolean;
}) {
  const [text, setText] = useState(state.kind === "custom" ? "" : state.label || state.value);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const listId = useId();
  const boxRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setText(state.kind === "custom" ? "" : state.label || state.value);
  }, [state.kind, state.value, state.label]);

  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      if (boxRef.current && !boxRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  const q = useDebounced(text, 180);
  const { data, isFetching } = useQuery({
    queryKey: ["purple-suggest", state.kind, q],
    queryFn: () => suggestPurpleSeeds({ data: { q, kind: state.kind } }),
    enabled: open && (q.trim().length > 0 || state.kind === "report"),
    staleTime: 60_000,
  });
  const items = open ? (data?.items ?? []) : [];

  const pick = (it: PurpleSuggestion) => {
    if (state.kind === "custom") {
      if (!state.techniques.includes(it.id)) onChange({ ...state, techniques: [...state.techniques, it.id] });
      setText("");
      return;
    }
    const next = { ...state, value: it.id, label: it.name };
    onChange(next);
    setText(it.name);
    setOpen(false);
    onGenerate(next);
  };

  const addTypedTechniques = () => {
    const ids = text
      .split(/[\s,;]+/)
      .map((x) => x.trim().toUpperCase())
      .filter((x) => /^T\d{4}(\.\d{3})?$/.test(x));
    if (!ids.length) return false;
    onChange({ ...state, techniques: Array.from(new Set([...state.techniques, ...ids])) });
    setText("");
    return true;
  };

  const submit = () => {
    if (state.kind === "custom") {
      const ids = text
        .split(/[\s,;]+/)
        .map((x) => x.trim().toUpperCase())
        .filter((x) => /^T\d{4}(\.\d{3})?$/.test(x));
      const next = { ...state, techniques: Array.from(new Set([...state.techniques, ...ids])) };
      if (ids.length) {
        onChange(next);
        setText("");
      }
      onGenerate(next);
    } else {
      const typed = text.trim();
      const next = typed && typed !== state.label ? { ...state, value: typed, label: typed } : state;
      if (next !== state) onChange(next);
      onGenerate(next);
    }
    setOpen(false);
  };

  const canGenerate = state.kind === "custom" ? state.techniques.length > 0 || /T\d{4}/i.test(text) : Boolean(text.trim() || state.value);

  return (
    <section className="rounded-xl border border-border bg-bg-card p-5">
      <div className="flex flex-col gap-4">
        <div className="max-w-full overflow-x-auto">
          <SegmentedTabs
            ariaLabel="Build from"
            items={KIND_TABS}
            value={state.kind}
            onChange={(k) => {
              onChange({ ...state, kind: k, value: "", label: "", techniques: k === "custom" ? state.techniques : [] });
              setText("");
            }}
          />
        </div>

        <form
          className="flex flex-col gap-2 sm:flex-row"
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
        >
          <div ref={boxRef} className="relative min-w-0 flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-subtle" />
            <input
              value={text}
              onChange={(e) => {
                setText(e.target.value);
                setOpen(true);
                setActive(0);
              }}
              onFocus={() => setOpen(true)}
              onKeyDown={(e) => {
                if (e.key === "ArrowDown" && items.length) {
                  e.preventDefault();
                  setActive((a) => Math.min(items.length - 1, a + 1));
                } else if (e.key === "ArrowUp" && items.length) {
                  e.preventDefault();
                  setActive((a) => Math.max(0, a - 1));
                } else if (e.key === "Enter" && open && items[active] && text.trim()) {
                  e.preventDefault();
                  if (state.kind === "custom" && /^T\d{4}/i.test(text.trim()) && addTypedTechniques()) return;
                  pick(items[active]);
                } else if (e.key === "Escape") {
                  setOpen(false);
                }
              }}
              role="combobox"
              aria-expanded={open && items.length > 0}
              aria-controls={listId}
              aria-autocomplete="list"
              aria-label={PLACEHOLDER[state.kind]}
              placeholder={PLACEHOLDER[state.kind]}
              className="h-10 w-full rounded-lg border border-border bg-bg-elevated pl-9 pr-9 text-sm text-fg outline-none placeholder:text-subtle focus:border-[var(--color-primary)]"
            />
            {isFetching && open && <Loader2 className="absolute right-3 top-1/2 size-4 -translate-y-1/2 animate-spin text-subtle" />}
            {open && items.length > 0 && (
              <ul
                id={listId}
                role="listbox"
                className="dropdown-liquid-glass absolute inset-x-0 top-full z-30 mt-1 max-h-80 overflow-y-auto rounded-lg border border-border bg-bg-elevated py-1 shadow-xl"
              >
                {items.map((it, i) => (
                  <li key={`${it.kind}-${it.id}`} role="option" aria-selected={i === active}>
                    <button
                      type="button"
                      onMouseEnter={() => setActive(i)}
                      onClick={() => pick(it)}
                      className={cn("flex w-full items-center gap-2.5 px-3 py-2 text-left", i === active && "bg-bg-subtle")}
                    >
                      <EntityIcon kind={SUGGEST_KIND[it.kind]} size="sm" />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-sm text-fg">{it.name}</span>
                        <span className="block truncate text-xs text-subtle">{it.hint}</span>
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
          <button
            type="submit"
            disabled={!canGenerate || busy}
            className="btn-primary inline-flex h-10 shrink-0 items-center justify-center gap-2 rounded-lg px-4 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy ? <Loader2 className="size-4 animate-spin" /> : <Sparkles className="size-4" strokeWidth={1.75} />}
            Generate path
          </button>
        </form>

        {state.kind === "custom" && state.techniques.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {state.techniques.map((t) => (
              <span
                key={t}
                className="inline-flex items-center gap-1 rounded-md py-0.5 pl-2 pr-1 font-mono text-xs"
                style={{ color: "var(--color-cat-technique)", backgroundColor: "color-mix(in oklab, var(--color-cat-technique) 14%, transparent)" }}
              >
                {t}
                <button
                  type="button"
                  aria-label={`Remove ${t}`}
                  onClick={() => onChange({ ...state, techniques: state.techniques.filter((x) => x !== t) })}
                  className="flex size-4 items-center justify-center rounded hover:bg-bg-subtle"
                >
                  <X className="size-3" />
                </button>
              </span>
            ))}
          </div>
        )}

        <div className="flex flex-col gap-3 border-t border-border pt-4 lg:flex-row lg:items-center lg:justify-between">
          <fieldset className="min-w-0">
            <legend className="mb-1.5 text-xs text-muted">Target platforms</legend>
            <div className="flex flex-wrap gap-1.5">
              {PURPLE_PLATFORMS.map((p) => {
                const on = state.platforms.includes(p.id);
                return (
                  <button
                    key={p.id}
                    type="button"
                    aria-pressed={on}
                    onClick={() => onChange({ ...state, platforms: on ? state.platforms.filter((x) => x !== p.id) : [...state.platforms, p.id] })}
                    className={cn(
                      "h-8 rounded-md border px-2.5 text-xs font-medium transition-colors",
                      on
                        ? "border-[color-mix(in_oklab,var(--color-primary)_45%,transparent)] bg-[color-mix(in_oklab,var(--color-primary)_14%,transparent)] text-fg"
                        : "border-border bg-bg-elevated text-muted hover:text-fg",
                    )}
                  >
                    {p.label}
                  </button>
                );
              })}
            </div>
            {state.platforms.length === 0 && <p className="mt-1 text-xs text-subtle">None selected: every platform is in scope.</p>}
          </fieldset>
          <div className="flex flex-wrap items-center gap-4">
            <label className="inline-flex cursor-pointer items-center gap-2 text-sm text-fg">
              <input
                type="checkbox"
                checked={state.excludeHighRisk}
                onChange={(e) => onChange({ ...state, excludeHighRisk: e.target.checked })}
                className="size-4 accent-[var(--color-primary)]"
              />
              Exclude high risk
            </label>
            <label className="inline-flex items-center gap-2 text-sm text-fg">
              Max steps
              <Select
                size="sm"
                value={String(state.maxSteps)}
                onValueChange={(v) => onChange({ ...state, maxSteps: Number(v) })}
                className="rounded-md"
              >
                {[6, 8, 10, 12, 16, 20, 30, 40].map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </Select>
            </label>
          </div>
        </div>
      </div>
    </section>
  );
}
