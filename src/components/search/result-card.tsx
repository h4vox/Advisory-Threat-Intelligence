import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { ArrowUpRight, ChevronDown, Copy, Search as SearchIcon } from "lucide-react";
import type { SearchResult } from "@/lib/aie/search/types";
import { DOC_TYPE_META, DocTypeBadge, EntityChip, EntityIcon, type EntityKind } from "@/components/ui/entity";
import { cn } from "@/lib/cn";
import { Highlight } from "./highlight";
import { linkNote } from "./link-note";

const KIND_LABEL: Record<SearchResult["kind"], string> = {
  report: "Report",
  group: "Threat actor",
  software: "Software",
  campaign: "Campaign",
  technique: "Technique",
  emulation: "Emulation",
  vulnerability: "Vulnerability",
};

function iconKind(r: SearchResult): EntityKind {
  switch (r.kind) {
    case "group":
    case "campaign":
      return "actor";
    case "software":
      return "malware";
    case "technique":
      return "technique";
    case "emulation":
      return "emulation";
    case "vulnerability":
      return "cve";
    default:
      return r.docTypes[0] ? DOC_TYPE_META[r.docTypes[0]]?.kind ?? "advisory" : "advisory";
  }
}

const FIELD_LABEL: Record<string, string> = {
  title: "title",
  aliases: "names / aliases",
  summary: "summary",
  body: "body",
  entities: "entities",
  techniques: "techniques",
  cves: "CVE ids",
};

function WhyPanel({ r }: { r: SearchResult }) {
  const w = r.why;
  const additive = w.breakdown.filter((b) => !b.key.startsWith("mult:"));
  const mults = w.breakdown.filter((b) => b.key.startsWith("mult:"));
  const max = Math.max(0.001, ...additive.map((b) => b.value));
  return (
    <div className="mt-3 grid gap-4 border-t border-border pt-3 text-xs md:grid-cols-2">
      <div className="space-y-2.5">
        {w.matchedEntities.length > 0 && (
          <div>
            <div className="mb-1 text-muted">Entities (aliases resolved)</div>
            <ul className="space-y-1">
              {w.matchedEntities.map((e) => (
                <li key={`${e.kind}:${e.id}`} className="text-fg">
                  <span className="font-medium">{e.name}</span> <span className="font-mono text-subtle">{e.id}</span>
                  <span className="text-muted">
                    {e.rel === "uses"
                      ? ` · linked in ATT&CK (${r.kind === "group" ? "uses" : "used by"} ${e.name})`
                      : e.via.toLowerCase() !== e.queryForm.toLowerCase()
                        ? ` · you searched “${e.queryForm}”, this ${r.kind === "report" ? "report" : "entry"} says “${e.via}”`
                        : ""}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
        {w.matchedTechniques.length > 0 && (
          <div>
            <div className="mb-1 text-muted">Techniques</div>
            <ul className="space-y-1">
              {w.matchedTechniques.map((t) => (
                <li key={t.id} className="text-fg">
                  <span className="font-mono">{t.id}</span> {t.name}
                  {t.relation !== "exact" && <span className="text-muted"> · via {t.relation === "parent" ? "parent technique" : "sub-technique"}</span>}
                </li>
              ))}
            </ul>
          </div>
        )}
        <div>
          <div className="mb-1 text-muted">Matched in</div>
          <div className="flex flex-wrap gap-1">
            {w.matchedFields.length === 0 ? (
              <span className="text-subtle">filters only</span>
            ) : (
              w.matchedFields.map((f) => (
                <span key={f} className="rounded-md bg-bg-subtle px-1.5 py-0.5 text-fg">
                  {FIELD_LABEL[f] ?? f}
                </span>
              ))
            )}
          </div>
        </div>
        {w.matchedTerms.length > 0 && (
          <div>
            <div className="mb-1 text-muted">Terms</div>
            <div className="font-mono text-fg">{w.matchedTerms.join(" · ")}</div>
          </div>
        )}
        {r.duplicates && r.duplicates.length > 0 && (
          <div>
            <div className="mb-1 flex items-center gap-1 text-muted">
              <Copy className="size-3" /> Near-duplicates collapsed
            </div>
            <ul className="space-y-0.5">
              {r.duplicates.map((d) => (
                <li key={d.id}>
                  <Link to="/library/$reportId" params={{ reportId: d.id }} className="text-accent hover:underline">
                    {d.title}
                  </Link>
                  {d.publisher && <span className="text-subtle"> · {d.publisher}</span>}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
      <div>
        <div className="mb-1.5 flex items-center justify-between text-muted">
          <span>Score breakdown</span>
          <span className="font-mono text-fg tabular-nums">{r.score.toFixed(2)}</span>
        </div>
        <ul className="space-y-1.5">
          {additive.map((b) => (
            <li key={b.key}>
              <div className="flex items-baseline justify-between gap-3">
                <span className="min-w-0 truncate text-fg" title={b.label}>
                  {b.label}
                </span>
                <span className="shrink-0 font-mono text-muted tabular-nums">+{b.value.toFixed(2)}</span>
              </div>
              <div className="mt-0.5 h-1 overflow-hidden rounded-full bg-bg-subtle">
                <div className="h-full rounded-full bg-[var(--color-primary)]" style={{ width: `${(b.value / max) * 100}%` }} />
              </div>
            </li>
          ))}
          {mults.map((b) => (
            <li key={b.key} className="flex items-baseline justify-between gap-3">
              <span className="min-w-0 truncate text-muted" title={b.label}>
                {b.label}
              </span>
              <span className={cn("shrink-0 font-mono tabular-nums", b.value < 1 ? "text-warn" : b.value > 1 ? "text-sage" : "text-subtle")}>×{b.value.toFixed(2)}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export function ResultCard({ r, onPivot }: { r: SearchResult; onPivot?: (q: string) => void }) {
  const [open, setOpen] = useState(false);
  const kind = iconKind(r);
  const note = linkNote(r);
  const linkProps = { to: r.href.to, params: r.href.params, search: r.href.search } as unknown as { to: "/search" };
  return (
    <article className="rounded-xl border border-border bg-bg-card p-4 transition-colors hover:border-[color-mix(in_oklab,var(--color-primary)_35%,var(--color-border))] sm:p-5">
      <div className="flex gap-3">
        <EntityIcon kind={kind} size="md" />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span className="text-[11px] font-medium text-subtle">{KIND_LABEL[r.kind]}</span>
            {r.kind === "report" && r.docTypes.slice(0, 2).map((t) => <DocTypeBadge key={t} type={t} />)}
            {r.tier && r.kind === "report" && <span className="rounded-md bg-bg-subtle px-1.5 py-0.5 text-[11px] text-muted">Tier {r.tier}</span>}
          </div>
          <h3 className="mt-1 text-[15px] font-medium leading-snug text-fg">
            <Link {...linkProps} className="break-words hover:text-accent hover:underline">
              <Highlight text={r.title} terms={r.highlights} />
            </Link>
          </h3>
          {r.subtitle && <p className="mt-0.5 truncate text-xs text-muted">{r.subtitle}</p>}
          {note && <p className="mt-1 text-xs font-medium text-accent">{note} · linked in ATT&CK</p>}
          {r.snippet && (
            <p className="mt-2 line-clamp-3 text-sm leading-relaxed text-muted">
              <Highlight text={r.snippet} terms={r.highlights} />
            </p>
          )}
          {(r.entities.length > 0 || (r.stats && r.stats.length > 0)) && (
            <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
              {r.entities.map((e) => (
                <EntityChip key={`${e.kind}:${e.label}`} kind={e.kind}>
                  {e.label}
                </EntityChip>
              ))}
              {r.stats?.map((s) => (
                <span key={s.label} className="rounded-md bg-bg-subtle px-2 py-0.5 text-xs text-muted">
                  {s.label} <span className="text-fg tabular-nums">{s.value}</span>
                </span>
              ))}
            </div>
          )}
          <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs">
            <button
              type="button"
              onClick={() => setOpen((v) => !v)}
              aria-expanded={open}
              className="inline-flex items-center gap-1 font-medium text-muted hover:text-fg"
            >
              <ChevronDown className={cn("size-3.5 transition-transform", !open && "-rotate-90")} />
              Why this result
            </button>
            {r.pivot && onPivot && (
              <button type="button" onClick={() => onPivot(r.pivot!.q)} className="inline-flex items-center gap-1 text-accent hover:underline">
                <SearchIcon className="size-3.5" />
                {r.pivot.label}
              </button>
            )}
            {r.externalUrl && (
              <a href={r.externalUrl} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 text-muted hover:text-fg">
                <ArrowUpRight className="size-3.5" />
                {r.kind === "report" || r.kind === "emulation" ? "Source" : r.kind === "vulnerability" ? "NVD" : "ATT&CK"}
              </a>
            )}
            <span className="ml-auto font-mono text-subtle tabular-nums" title="Relevance score">
              {r.score.toFixed(2)}
            </span>
          </div>
          {open && <WhyPanel r={r} />}
        </div>
      </div>
    </article>
  );
}
