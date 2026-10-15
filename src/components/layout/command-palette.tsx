import { useEffect, useState, type ComponentType } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { Command } from "cmdk";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { FileText, Search } from "lucide-react";
import { listReports } from "@/lib/aie/server";

export type PaletteNavItem = {
  to: string;
  label: string;
  icon: ComponentType<{ className?: string; strokeWidth?: number }>;
  group: string;
};

/** ⌘K / Ctrl+K: jump to any page or find a report by title or content. */
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

  const reports = useQuery({
    queryKey: ["palette-reports", debounced],
    queryFn: () => listReports({ data: { q: debounced, limit: 8 } }),
    enabled: open && debounced.length >= 2,
    staleTime: 30_000,
  });

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
                placeholder="Search pages and reports…"
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
                <Command.Group
                  heading="Pages"
                  className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-[11px] [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wider [&_[cmdk-group-heading]]:text-subtle"
                >
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
                <Command.Group
                  heading={reports.isFetching ? "Reports · searching…" : "Reports"}
                  className="mt-1 [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-[11px] [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wider [&_[cmdk-group-heading]]:text-subtle"
                >
                  {(reports.data ?? []).map((r) => (
                    <Command.Item
                      key={r.id}
                      value={`report-${r.id}`}
                      onSelect={() => {
                        onOpenChange(false);
                        void navigate({ to: "/library/$reportId", params: { reportId: r.id } });
                      }}
                      className="flex cursor-pointer items-start gap-2.5 rounded-md px-2 py-2 text-sm text-fg data-[selected=true]:bg-bg-subtle"
                    >
                      <FileText className="mt-0.5 size-4 shrink-0 text-muted" strokeWidth={1.75} />
                      <span className="min-w-0">
                        <span className="block truncate">{r.title}</span>
                        <span className="block truncate text-xs text-subtle">
                          {r.publisher || r.sourceName}
                        </span>
                      </span>
                    </Command.Item>
                  ))}
                  {!reports.isFetching && (reports.data ?? []).length === 0 && (
                    <div className="px-2 py-2 text-xs text-subtle">
                      No reports match “{debounced}”.
                    </div>
                  )}
                </Command.Group>
              )}
            </Command.List>
          </Command>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
