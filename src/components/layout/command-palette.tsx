import { useEffect, useState, type ComponentType } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { Command } from "cmdk";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { ArrowRight, Search } from "lucide-react";
import { searchIntel } from "@/lib/aie/server-search";
import type { SearchResult } from "@/lib/aie/search/types";
import { DOC_TYPE_META, EntityIcon, type EntityKind } from "@/components/ui/entity";
import { isDirectMatch, linkNote } from "@/components/search/link-note";

export type PaletteNavItem = {
  to: string;
  label: string;
  icon: ComponentType<{ className?: string; strokeWidth?: number }>;
  group: string;
};

const RESULT_KIND_ICON: Record<SearchResult["kind"], EntityKind> = {
  report: "advisory",
  group: "actor",
  campaign: "actor",
  software: "malware",
  technique: "technique",
  emulation: "emulation",
  vulnerability: "cve",
};

const RESULT_KIND_LABEL: Record<SearchResult["kind"], string> = {
  report: "Report",
  group: "Actor",
  campaign: "Campaign",
  software: "Software",
  technique: "Technique",
  emulation: "Emulation",
  vulnerability: "CVE",
};

const GROUP_CLS =
  "mt-1 [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-[11px] [&_[cmdk-group-heading]]:font-medium [&_[cmdk-group-heading]]:text-subtle";

/** ⌘K / Ctrl+K: jump to any page, or search entities and reports with the intelligence search engine. */
export function CommandPalette({
  open,
  onOpenChange,
  navItems,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  navItems: PaletteNavItem[];
}) {
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [debounced, setDebounced] = useState("");

  useEffect(() => {
    const t = setTimeout(() => setDebounced(query.trim()), 250);
    return () => clearTimeout(t);
  }, [query]);

  useEffect(() => {
    if (!open) setQuery("");
  }, [open]);

  const search = useQuery({
    queryKey: ["palette-search", debounced],
    queryFn: () => searchIntel({ data: { q: debounced, group: "all", limit: 14 } }),
    enabled: open && debounced.length >= 2,
    staleTime: 30_000,
  });
  const results = search.data?.interpreted.raw === debounced ? search.data.results : [];
  // The entity the query named first, then cards that are only linked to it in ATT&CK.
  const entityResults = results
    .filter((r) => r.kind !== "report")
    .sort((a, b) => Number(isDirectMatch(b)) - Number(isDirectMatch(a)))
    .slice(0, 5);
  const reportResults = results.filter((r) => r.kind === "report").slice(0, 6);
  const openResult = (r: SearchResult) => {
    onOpenChange(false);
    void navigate({ to: r.href.to, params: r.href.params, search: r.href.search } as never);
  };

  const pageMatches = navItems.filter(
    (n) => !query || n.label.toLowerCase().includes(query.toLowerCase()),
  );

  const go = (to: string, search?: Record<string, string>) => {
    onOpenChange(false);
    void navigate({ to, search: search as never });
  };

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/50 backdrop-blur-[1px]" />
        <Dialog.Content className="fixed left-1/2 top-[12vh] z-50 w-[calc(100%-2rem)] max-w-xl -translate-x-1/2 overflow-hidden rounded-xl border border-border bg-bg-elevated shadow-2xl">
          <Dialog.Title className="sr-only">Search</Dialog.Title>
          <Dialog.Description className="sr-only">
            Jump to a page or search the report library.
          </Dialog.Description>
          <Command shouldFilter={false} label="Search">
            <div className="flex items-center gap-2 border-b border-border px-4">
              <Search className="size-4 text-subtle" />
              <Command.Input
                value={query}
                onValueChange={setQuery}
                placeholder="Search pages, actors, techniques, CVEs, reports…"
                className="h-12 w-full bg-transparent text-sm text-fg outline-none placeholder:text-subtle"
              />
              <kbd className="rounded border border-border px-1.5 py-0.5 font-mono text-[10px] text-subtle">
                Esc
              </kbd>
            </div>
            <Command.List className="max-h-[60vh] overflow-y-auto p-2">
              <Command.Empty className="px-3 py-6 text-center text-sm text-muted">
                No matches.
              </Command.Empty>
              {pageMatches.length > 0 && (
                <Command.Group heading="Pages" className={GROUP_CLS}>
                  {pageMatches.map((n) => (
                    <Command.Item
                      key={n.to}
                      value={`page-${n.to}`}
                      onSelect={() => go(n.to)}
                      className="flex cursor-pointer items-center gap-2.5 rounded-md px-2 py-2 text-sm text-fg data-[selected=true]:bg-bg-subtle"
                    >
                      <n.icon className="size-4 text-muted" strokeWidth={1.75} />
                      {n.label}
                      <span className="ml-auto text-xs text-subtle">{n.group}</span>
                    </Command.Item>
                  ))}
                </Command.Group>
              )}
              {debounced.length >= 2 && (
                <>
                  {search.data && search.data.interpreted.summary && (
                    <div className="px-2 pb-1 pt-2 text-[11px] text-subtle">
                      Interpreted as <span className="text-muted">{search.data.interpreted.summary}</span>
                    </div>
                  )}
                  {entityResults.length > 0 && (
                    <Command.Group heading="Entities" className={GROUP_CLS}>
                      {entityResults.map((r) => (
                        <ResultItem key={`${r.kind}:${r.id}`} r={r} onSelect={() => openResult(r)} />
                      ))}
                    </Command.Group>
                  )}
                  <Command.Group heading={search.isFetching ? "Reports · searching…" : "Reports"} className={GROUP_CLS}>
                    {reportResults.map((r) => (
                      <ResultItem key={`${r.kind}:${r.id}`} r={r} onSelect={() => openResult(r)} />
                    ))}
                    {!search.isFetching && search.data && reportResults.length === 0 && (
                      <div className="px-2 py-2 text-xs text-subtle">No library reports match “{debounced}”.</div>
                    )}
                  </Command.Group>
                  <Command.Group className={GROUP_CLS}>
                    <Command.Item
                      value="search-all"
                      onSelect={() => go("/search", { q: debounced })}
                      className="flex cursor-pointer items-center gap-2.5 rounded-md px-2 py-2 text-sm text-fg data-[selected=true]:bg-bg-subtle"
                    >
                      <Search className="size-4 text-muted" strokeWidth={1.75} />
                      <span className="min-w-0 truncate">
                        Search everything for “{debounced}”
                        {search.data ? <span className="text-subtle"> · {search.data.counts.all} results</span> : null}
                      </span>
                      <ArrowRight className="ml-auto size-4 text-subtle" />
                    </Command.Item>
                  </Command.Group>
                </>
              )}
            </Command.List>
          </Command>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function ResultItem({ r, onSelect }: { r: SearchResult; onSelect: () => void }) {
  const kind = r.kind === "report" && r.docTypes[0] ? DOC_TYPE_META[r.docTypes[0]]?.kind ?? "advisory" : RESULT_KIND_ICON[r.kind];
  return (
    <Command.Item
      value={`${r.kind}-${r.id}`}
      onSelect={onSelect}
      className="flex cursor-pointer items-start gap-2.5 rounded-md px-2 py-2 text-sm text-fg data-[selected=true]:bg-bg-subtle"
    >
      <EntityIcon kind={kind} size="sm" />
      <span className="min-w-0 flex-1">
        <span className="block truncate">{r.title}</span>
        <span className="block truncate text-xs text-subtle">
          {linkNote(r) ? <span className="text-muted">{linkNote(r)} · </span> : null}
          {r.subtitle || r.publisher}
        </span>
      </span>
      <span className="mt-0.5 shrink-0 text-[11px] text-subtle">{RESULT_KIND_LABEL[r.kind]}</span>
    </Command.Item>
  );
}
