import { useEffect, useId, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { CornerDownLeft, HelpCircle, Search, X } from "lucide-react";
import { suggestEntities } from "@/lib/aie/server-search";
import type { EntitySuggestion } from "@/lib/aie/search/types";
import { EntityIcon, type EntityKind } from "@/components/ui/entity";
import { cn } from "@/lib/cn";
import { SYNTAX_HINTS } from "./search-syntax";

const STATIC_VALUES: Record<string, string[]> = {
  "type:": ["advisory", "dfir", "incident", "malware", "vulnerability", "campaign", "emulation", "atomic", "flow", "detection", "hunting", "kev"],
  "has:": ["iocs", "emulation", "evidence"],
  "tier:": ["1", "2", "3", "4"],
};

const KIND_ICON: Record<EntitySuggestion["kind"], EntityKind> = {
  group: "actor",
  campaign: "actor",
  software: "malware",
  technique: "technique",
  tactic: "technique",
  type: "advisory",
};

const KIND_LABEL: Record<EntitySuggestion["kind"], string> = {
  group: "Threat actor",
  campaign: "Campaign",
  software: "Software",
  technique: "Technique",
  tactic: "Tactic",
  type: "Document type",
};

type Option = { key: string; label: string; detail?: string; kind: EntitySuggestion["kind"] | "syntax"; insert: string };

/** The token under the caret (the last word, or an open quoted value). */
function currentToken(value: string): { start: number; token: string } {
  const quotes = (value.match(/"/g) ?? []).length;
  if (quotes % 2 === 1) {
    const q = value.lastIndexOf('"');
    const before = value.slice(0, q);
    const fieldStart = before.search(/[a-z-]+:$/i);
    const start = fieldStart >= 0 ? fieldStart : q;
    return { start, token: value.slice(start) };
  }
  const start = value.search(/\S+$/);
  return start === -1 ? { start: value.length, token: "" } : { start, token: value.slice(start) };
}

export function SearchBar({
  value,
  onChange,
  onSubmit,
  autoFocus,
  className,
}: {
  value: string;
  onChange: (v: string) => void;
  onSubmit: (v: string) => void;
  autoFocus?: boolean;
  className?: string;
}) {
  const listId = useId();
  const inputRef = useRef<HTMLInputElement>(null);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);
  const [showHints, setShowHints] = useState(false);
  const { start, token } = currentToken(value);
  const fieldMatch = token.match(/^-?([a-z-]+:)"?(.*)$/i);
  const field = fieldMatch ? fieldMatch[1].toLowerCase() : null;
  const fieldValue = fieldMatch ? fieldMatch[2] : token.replace(/^[-"]+/, "");
  const entityPrefix = field && STATIC_VALUES[field] ? "" : fieldValue;

  const [debounced, setDebounced] = useState("");
  useEffect(() => {
    const t = setTimeout(() => setDebounced(entityPrefix.trim()), 140);
    return () => clearTimeout(t);
  }, [entityPrefix]);

  const suggestions = useQuery({
    queryKey: ["search-suggest", debounced],
    queryFn: () => suggestEntities({ data: { prefix: debounced, limit: 8 } }),
    enabled: open && debounced.length >= 2,
    staleTime: 5 * 60_000,
  });

  const options: Option[] = useMemo(() => {
    if (field && STATIC_VALUES[field]) {
      return STATIC_VALUES[field]
        .filter((v) => v.startsWith(fieldValue.toLowerCase()))
        .map((v) => ({ key: `${field}${v}`, label: `${field}${v}`, kind: "syntax" as const, insert: `${field}${v}` }));
    }
    if (!token && !value.trim()) return [];
    const list = (debounced.length >= 2 ? suggestions.data ?? [] : []).filter((s) => {
      if (field === "actor:") return s.kind === "group" || s.kind === "campaign";
      if (field === "malware:") return s.kind === "software";
      if (field === "campaign:") return s.kind === "campaign";
      if (field === "technique:") return s.kind === "technique";
      if (field === "tactic:") return s.kind === "tactic";
      return true;
    });
    return list.map((s) => ({
      key: `${s.kind}:${s.id}`,
      label: s.kind === "technique" ? `${s.id} ${s.name}` : s.name,
      detail: [s.kind === "technique" || s.kind === "tactic" || s.kind === "type" ? null : s.id, s.alias ? `alias ${s.alias}` : null].filter(Boolean).join(" · "),
      kind: s.kind,
      insert: s.insert,
    }));
  }, [field, fieldValue, token, value, debounced, suggestions.data]);

  useEffect(() => setActive(-1), [options.length, token]);

  const apply = (o: Option) => {
    const negated = token.startsWith("-") ? "-" : "";
    const next = `${value.slice(0, start)}${negated}${o.insert} `;
    onChange(next);
    setOpen(STATIC_VALUES[o.insert] !== undefined);
    requestAnimationFrame(() => inputRef.current?.focus());
  };

  const showList = open && options.length > 0;

  return (
    <div className={cn("relative", className)}>
      <form
        role="search"
        onSubmit={(e) => {
          e.preventDefault();
          setOpen(false);
          onSubmit(value);
        }}
        className="flex items-center gap-2 rounded-xl border border-border bg-bg-elevated px-3 shadow-[var(--shadow-card)] focus-within:ring-2 focus-within:ring-[color-mix(in_oklab,var(--color-primary)_45%,transparent)]"
      >
        <Search className="size-5 shrink-0 text-subtle" strokeWidth={1.75} />
        <input
          ref={inputRef}
          value={value}
          autoFocus={autoFocus}
          onChange={(e) => {
            onChange(e.target.value);
            setOpen(true);
          }}
          onFocus={() => setOpen(true)}
          onBlur={() => setTimeout(() => setOpen(false), 120)}
          onKeyDown={(e) => {
            if (!showList) return;
            if (e.key === "ArrowDown") {
              e.preventDefault();
              setActive((a) => (a + 1) % options.length);
            } else if (e.key === "ArrowUp") {
              e.preventDefault();
              setActive((a) => (a <= 0 ? options.length - 1 : a - 1));
            } else if ((e.key === "Enter" || e.key === "Tab") && active >= 0) {
              e.preventDefault();
              apply(options[active]);
            } else if (e.key === "Escape") {
              setOpen(false);
            }
          }}
          role="combobox"
          aria-expanded={showList}
          aria-controls={listId}
          aria-autocomplete="list"
          aria-activedescendant={active >= 0 ? `${listId}-${active}` : undefined}
          aria-label="Search intelligence"
          placeholder='Search actors, techniques, CVEs, reports… e.g. Cozy Bear since:2024'
          spellCheck={false}
          className="h-12 min-w-0 flex-1 bg-transparent text-[15px] text-fg outline-none placeholder:text-subtle"
        />
        {value && (
          <button
            type="button"
            aria-label="Clear search"
            onClick={() => {
              onChange("");
              inputRef.current?.focus();
            }}
            className="flex size-7 shrink-0 items-center justify-center rounded-md text-muted hover:bg-bg-subtle hover:text-fg"
          >
            <X className="size-4" />
          </button>
        )}
        <button
          type="button"
          aria-label="Search syntax"
          aria-expanded={showHints}
          onClick={() => setShowHints((v) => !v)}
          className={cn("hidden size-8 shrink-0 items-center justify-center rounded-md text-muted hover:bg-bg-subtle hover:text-fg sm:flex", showHints && "bg-bg-subtle text-fg")}
        >
          <HelpCircle className="size-4" strokeWidth={1.75} />
        </button>
        <button type="submit" className="btn-primary inline-flex h-9 shrink-0 items-center gap-1.5 rounded-lg px-3 text-sm font-medium">
          <span className="max-sm:sr-only">Search</span>
          <CornerDownLeft className="size-4 sm:hidden" />
        </button>
      </form>

      {showList && (
        <ul
          id={listId}
          role="listbox"
          className="dropdown-liquid-glass absolute inset-x-0 top-full z-30 mt-1.5 max-h-80 overflow-y-auto rounded-xl border border-border bg-bg-elevated p-1.5 shadow-xl"
        >
          {options.map((o, i) => (
            <li
              key={o.key}
              id={`${listId}-${i}`}
              role="option"
              aria-selected={i === active}
              onMouseDown={(e) => {
                e.preventDefault();
                apply(o);
              }}
              onMouseEnter={() => setActive(i)}
              className={cn("flex cursor-pointer items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm", i === active && "bg-bg-subtle")}
            >
              {o.kind === "syntax" ? (
                <span className="flex size-6 items-center justify-center rounded-md bg-bg-subtle font-mono text-[10px] text-muted">:</span>
              ) : (
                <EntityIcon kind={KIND_ICON[o.kind]} size="sm" />
              )}
              <span className="min-w-0 flex-1 truncate text-fg">{o.label}</span>
              {o.detail && <span className="hidden truncate text-xs text-subtle sm:inline">{o.detail}</span>}
              <span className="shrink-0 text-[11px] text-subtle">{o.kind === "syntax" ? "Filter" : KIND_LABEL[o.kind]}</span>
            </li>
          ))}
        </ul>
      )}

      {showHints && (
        <div className="mt-2 grid gap-x-6 gap-y-1.5 rounded-xl border border-border bg-bg-card p-4 text-sm sm:grid-cols-2 lg:grid-cols-3">
          {SYNTAX_HINTS.map((h) => (
            <button
              key={h.field}
              type="button"
              onClick={() => {
                onChange(`${value.trim() ? `${value.trim()} ` : ""}${h.field === '"…"' ? '"' : h.field === "-" ? "-" : h.field}`);
                inputRef.current?.focus();
              }}
              className="flex min-w-0 items-baseline gap-2 rounded-md px-1.5 py-1 text-left hover:bg-bg-subtle"
            >
              <code className="shrink-0 font-mono text-xs text-accent">{h.example}</code>
              <span className="truncate text-xs text-muted">{h.help}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
