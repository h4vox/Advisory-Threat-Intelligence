import { useQuery } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowUpRight, Bot, Fingerprint, Hash, Play, Shield, Workflow, Zap } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { getDashboard } from "@/lib/aie/server";
import { formatDateTime } from "@/lib/aie/format";

export const Route = createFileRoute("/")({ component: Home });

function Home() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["dashboard"],
    queryFn: () => getDashboard(),
    refetchInterval: 5000,
  });

  return (
    <AppShell>
      <div className="mb-8 flex flex-col justify-between gap-4 md:flex-row md:items-center">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-subtle">
            Adversary Intelligence Engine · Retrieval Console
          </p>
          <h1 className="mt-1 text-3xl font-medium tracking-tight md:text-4xl">Autonomous Threat Intelligence</h1>
          <p className="mt-2 max-w-2xl text-sm leading-relaxed text-muted">
            Continuous discovery, qualification, cryptographic hashing, and attack-chain extraction for adversary emulation, threat hunting, and detection engineering.
          </p>
        </div>
        <Link to="/ingest">
          <Button className="gap-2">
            <Zap className="size-4" />
            <span>Open Ingest & Crawler</span>
          </Button>
        </Link>
      </div>

      <ol className="mb-10 grid grid-cols-1 gap-2 xs:grid-cols-2 sm:grid-cols-3 md:grid-cols-5">
        {[
          { label: "Autonomous Discovery", desc: "Feeds & Targeted Search" },
          { label: "Resource Extraction", desc: "Permalinks Only" },
          { label: "Heuristic Gate", desc: "TTP Qualification" },
          { label: "Acquire & PDF", desc: "SHA-256 & Exact PDF" },
          { label: "Attack Chain", desc: "ATT&CK & Emulation" },
        ].map((step, i) => (
          <li
            key={step.label}
            className="rounded-lg border border-border bg-bg-elevated p-3"
          >
            <div className="font-mono text-[10px] text-subtle">{String(i + 1).padStart(2, "0")}</div>
            <div className="mt-1 text-sm font-medium">{step.label}</div>
            <div className="mt-0.5 text-[11px] text-muted">{step.desc}</div>
          </li>
        ))}
      </ol>

      {error ? (
        <p className="text-sm text-danger">{error.message}</p>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Stat label="Threat Sources" value={data?.sourceCount} sub={`${data?.enabledSources ?? "—"} active feeds`} />
          <Stat label="Reports Stored" value={data?.acquiredCount} sub={`${data?.reportCount ?? "—"} total in store`} />
          <Stat label="Avg Quality Gate" value={data ? Math.round(data.avgQuality * 100) + "%" : undefined} sub="Adversary TTP density" />
          <Stat label="IOCs Harvested" value={data?.iocCount} sub="IPs, Domains, CVEs, Hashes" />
        </div>
      )}

      <div className="mt-10 grid gap-8 lg:grid-cols-5">
        <section className="lg:col-span-3">
          <div className="mb-3 flex items-baseline justify-between">
            <h2 className="text-lg font-medium">Recently Acquired Intelligence</h2>
            <Link to="/library" className="text-sm text-muted hover:text-fg">
              Open library
            </Link>
          </div>
          <div className="divide-y divide-border rounded-xl border border-border bg-bg-elevated">
            {isLoading && <p className="p-5 text-sm text-muted">Loading store…</p>}
            {data?.recent.map((r) => (
              <Link
                key={r.id}
                to="/library/$reportId"
                params={{ reportId: r.id }}
                className="flex items-start justify-between gap-4 px-5 py-4 transition-colors hover:bg-bg-subtle"
              >
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge tone="neutral">{r.sourceName}</Badge>
                    <Badge tone="accent">{r.classification}</Badge>
                    <Badge tone={r.status === "acquired" ? "sage" : "warn"}>{r.status}</Badge>
                    <Badge tone="sage">PDF Ready</Badge>
                  </div>
                  <div className="mt-2 text-sm font-medium leading-snug">{r.title}</div>
                  <p className="mt-1 line-clamp-2 text-xs text-muted">{r.excerpt}</p>
                </div>
                <ArrowUpRight className="mt-1 size-4 shrink-0 text-subtle" />
              </Link>
            ))}
          </div>
        </section>

        <section className="lg:col-span-2">
          <h2 className="mb-3 text-lg font-medium">Ingest & Crawl Audit Log</h2>
          <ul className="space-y-2">
            {data?.events.map((e) => (
              <li key={e.id} className="rounded-lg border border-border bg-bg-elevated px-4 py-3">
                <div className="flex items-center justify-between gap-2">
                  <Badge
                    tone={
                      e.outcome === "failed" || e.outcome === "rejected"
                        ? "danger"
                        : e.outcome === "duplicate"
                          ? "warn"
                          : "sage"
                    }
                  >
                    {e.outcome}
                  </Badge>
                  <span className="font-mono text-[10px] text-subtle">
                    {formatDateTime(e.createdAt)}
                  </span>
                </div>
                <p className="mt-2 truncate font-mono text-xs text-muted">{e.url}</p>
                {e.detail ? <p className="mt-1 text-xs text-subtle">{e.detail}</p> : null}
              </li>
            ))}
          </ul>

          <div className="mt-6 grid gap-2">
            <Hint icon={Workflow} text="Discriminator filters out index/category pages — only individual reports are stored." />
            <Hint icon={Hash} text="Cryptographic SHA-256 evidence hashing for raw bytes and clean text." />
            <Hint icon={Fingerprint} text="Regex IOC harvest with MITRE ATT&CK and threat actor extraction." />
            <Hint icon={Shield} text="All external content is strictly treated as untrusted threat intelligence data." />
          </div>
        </section>
      </div>
    </AppShell>
  );
}

function Stat({ label, value, sub }: { label: string; value?: number | string; sub: string }) {
  return (
    <div className="rounded-xl border border-border bg-bg-elevated px-5 py-4">
      <div className="text-xs uppercase tracking-wider text-subtle">{label}</div>
      <div className="mt-2 font-mono text-3xl tabular-nums tracking-tight">
        {value ?? "—"}
      </div>
      <div className="mt-1 text-xs text-muted">{sub}</div>
    </div>
  );
}

function Hint({ icon: Icon, text }: { icon: typeof Hash; text: string }) {
  return (
    <div className="flex gap-2.5 rounded-md px-1 py-1 text-xs leading-relaxed text-muted">
      <Icon className="mt-0.5 size-3.5 shrink-0 text-subtle" strokeWidth={1.75} />
      <span>{text}</span>
    </div>
  );
}
