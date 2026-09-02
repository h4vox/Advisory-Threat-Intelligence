import { useQuery } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { ArrowUpRight, FileText, Filter, Search, ShieldAlert } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { listReports } from "@/lib/aie/server";
import { formatDateTime } from "@/lib/aie/format";
import { cn } from "@/lib/cn";

export const Route = createFileRoute("/library")({ component: LibraryPage });

const CLASSIFICATIONS = [
  { id: "ALL", label: "All Types" },
  { id: "ADVERSARY_EMULATION", label: "Adversary Emulation" },
  { id: "INTRUSION_REPORT", label: "Intrusion Reports" },
  { id: "ATTACK_CHAIN_REPORT", label: "Attack Chains" },
  { id: "MALWARE_ANALYSIS", label: "Malware Analysis" },
  { id: "THREAT_ACTOR_REPORT", label: "Threat Actors" },
  { id: "PURPLE_TEAM", label: "Purple Team" },
  { id: "SECURITY_ADVISORY", label: "Advisories" },
];

function LibraryPage() {
  const [q, setQ] = useState("");
  const [selectedClass, setSelectedClass] = useState("ALL");

  const { data, isLoading } = useQuery({
    queryKey: ["reports", q, selectedClass],
    queryFn: () => listReports({ data: { q, classification: selectedClass } }),
  });

  return (
    <AppShell>
      <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-subtle">Knowledge Base</p>
          <h1 className="mt-1 text-3xl font-medium tracking-tight">Intelligence Library</h1>
          <p className="mt-1 text-xs text-muted">
            Acquired adversary intelligence, normalized evidence, IOCs, and reconstructed attack chains.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search title, actor, TTP, or source…"
            className="w-full md:w-80 text-xs"
          />
        </div>
      </div>

      {/* Category Pills */}
      <div className="mt-6 flex flex-wrap gap-1.5 border-b border-border pb-3">
        {CLASSIFICATIONS.map((c) => (
          <button
            key={c.id}
            type="button"
            onClick={() => setSelectedClass(c.id)}
            className={cn(
              "rounded-full px-3 py-1 text-xs font-medium transition-colors",
              selectedClass === c.id
                ? "bg-fg text-bg"
                : "bg-bg-elevated text-muted hover:text-fg border border-border",
            )}
          >
            {c.label}
          </button>
        ))}
      </div>

      <div className="mt-6 grid gap-3">
        {isLoading ? <p className="py-8 text-center text-sm text-muted">Loading intelligence store…</p> : null}
        {!isLoading && data?.length === 0 ? (
          <div className="rounded-xl border border-border bg-bg-elevated py-12 text-center text-sm text-muted">
            No threat intelligence reports match your filter. Ingest new reports or run the autonomous crawler.
          </div>
        ) : null}
        {data?.map((r) => (
          <Link
            key={r.id}
            to="/library/$reportId"
            params={{ reportId: r.id }}
            className="block rounded-xl border border-border bg-bg-elevated p-5 transition-colors hover:border-border/80 hover:bg-bg-subtle/40"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-2">
                <Badge tone="neutral">{r.sourceName}</Badge>
                <Badge tone="accent">{r.classification}</Badge>
                <Badge tone={r.status === "acquired" ? "sage" : "warn"}>{r.status}</Badge>
                <Badge tone="sage" className="gap-1">
                  <FileText className="size-2.5" /> PDF
                </Badge>
              </div>
              <span className="font-mono text-[11px] text-subtle tabular-nums">
                {Math.round(r.qualityScore * 100)}% quality · {r.wordCount} words · {r.iocCount} IOCs
              </span>
            </div>

            <div className="mt-3 flex items-start justify-between gap-4">
              <div>
                <h2 className="text-base font-medium leading-snug">{r.title}</h2>
                <p className="mt-1.5 line-clamp-2 text-xs text-muted leading-relaxed">{r.excerpt}</p>
              </div>
              <ArrowUpRight className="mt-1 size-4 shrink-0 text-subtle" />
            </div>

            <div className="mt-3 flex items-center justify-between border-t border-border pt-2.5 font-mono text-[10px] text-subtle">
              <span>Domain: {r.sourceDomain || "Verified source"}</span>
              <span className="flex items-center gap-3">
                <span className="text-accent flex items-center gap-1">
                  <FileText className="size-3" /> View & Download PDF
                </span>
                <span>Ingested: {formatDateTime(r.ingestedAt)}</span>
              </span>
            </div>
          </Link>
        ))}
      </div>
    </AppShell>
  );
}
