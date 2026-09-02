import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { ExternalLink } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { Badge } from "@/components/ui/badge";
import { listSources, toggleSource } from "@/lib/aie/server";

export const Route = createFileRoute("/sources")({ component: SourcesPage });

function SourcesPage() {
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ["sources"], queryFn: () => listSources() });
  const mut = useMutation({
    mutationFn: (input: { id: string; enabled: boolean }) => toggleSource({ data: input }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["sources"] });
      void qc.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });

  return (
    <AppShell>
      <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-subtle">Registry</p>
      <h1 className="mt-1 text-3xl font-medium tracking-tight">Sources</h1>
      <p className="mt-3 max-w-2xl text-sm leading-relaxed text-muted">
        Seeds are starting points, not a hard-coded crawl list. Priority 1 sources produce the
        most usable infection chains for later extraction.
      </p>

      <div className="mt-8 grid gap-3">
        {data?.map((s) => (
          <article
            key={s.id}
            className="flex flex-col gap-4 rounded-xl border border-border bg-bg-elevated p-5 md:flex-row md:items-center md:justify-between"
          >
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-base font-medium">{s.name}</h2>
                <Badge tone="accent">P{s.priority}</Badge>
                <Badge tone={s.trustLevel === "official" ? "sage" : "neutral"}>{s.trustLevel}</Badge>
                <Badge>{s.category.replaceAll("_", " ")}</Badge>
              </div>
              <p className="mt-2 text-sm text-muted">{s.notes}</p>
              <a
                href={s.homepageUrl}
                target="_blank"
                rel="noreferrer"
                className="mt-2 inline-flex items-center gap-1 font-mono text-xs text-subtle hover:text-fg"
              >
                {s.homepageUrl.replace(/^https:\/\//, "")}
                <ExternalLink className="size-3" />
              </a>
            </div>
            <button
              type="button"
              onClick={() => mut.mutate({ id: s.id, enabled: !s.enabled })}
              className="h-11 shrink-0 rounded-md border border-border px-4 text-sm hover:bg-bg-subtle"
            >
              {s.enabled ? "Enabled" : "Paused"}
            </button>
          </article>
        ))}
      </div>
    </AppShell>
  );
}
