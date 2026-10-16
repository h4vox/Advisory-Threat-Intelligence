import type { ReactNode } from "react";
import { ShieldAlert } from "lucide-react";
import { EntityChip, EntityIcon, type EntityKind } from "@/components/ui/entity";
import { StatusChip } from "@/components/ui/primitives";
import type { StructuredIntel } from "@/lib/aie/types";
import { lookupAttackTechnique } from "@/lib/aie/mitre-matrix";
import { formatDate } from "./report-utils";

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-1 gap-1.5 py-3 sm:grid-cols-[10rem_minmax(0,1fr)] sm:gap-4">
      <dt className="text-sm text-muted">{label}</dt>
      <dd className="min-w-0 text-sm text-fg">{children}</dd>
    </div>
  );
}

function Chips({ kind, items, empty = "None recorded", max = 40 }: { kind: EntityKind; items: string[]; empty?: string; max?: number }) {
  if (!items.length) return <span className="text-subtle">{empty}</span>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {items.slice(0, max).map((i) => {
        const tech = kind === "technique" ? lookupAttackTechnique(i) : null;
        return (
          <EntityChip key={i} kind={kind} title={tech ? `${i} · ${tech.name}` : undefined}>
            {i}
          </EntityChip>
        );
      })}
      {items.length > max && <span className="text-xs text-muted">+{items.length - max} more</span>}
    </div>
  );
}

function TechniqueSteps({ ids }: { ids: string[] }) {
  if (!ids.length) return <span className="text-subtle">No techniques recorded</span>;
  return (
    <ol className="space-y-1.5">
      {ids.map((id, i) => {
        const t = lookupAttackTechnique(id);
        return (
          <li key={`${id}-${i}`} className="flex items-start gap-2.5">
            <span className="mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full bg-bg-subtle text-[10px] font-medium tabular-nums text-muted">{i + 1}</span>
            <EntityChip kind="technique">{id}</EntityChip>
            <span className="min-w-0 text-sm text-fg">
              {t?.name ?? <span className="text-subtle">Not in bundled ATT&CK data</span>}
              {t?.tactic && <span className="text-muted"> · {t.tactic}</span>}
            </span>
          </li>
        );
      })}
    </ol>
  );
}

const TITLE: Record<StructuredIntel["kind"], { title: string; kind: EntityKind }> = {
  attack_group: { title: "ATT&CK group", kind: "actor" },
  attack_software: { title: "ATT&CK software", kind: "malware" },
  attack_campaign: { title: "ATT&CK campaign", kind: "actor" },
  atomic_test: { title: "Atomic Red Team tests", kind: "emulation" },
  emulation_plan: { title: "Adversary emulation plan", kind: "emulation" },
  attack_flow: { title: "Attack flow", kind: "flow" },
  kev: { title: "Known exploited vulnerability", kind: "cve" },
};

/** Structured summary for records that came from a structured source (ATT&CK STIX, Atomic, CTID, KEV). */
export function StructuredPanel({ data }: { data: StructuredIntel }) {
  const meta = TITLE[data.kind];
  let body: ReactNode = null;

  switch (data.kind) {
    case "attack_group":
      body = (
        <>
          <Row label="ATT&CK ID">
            <span className="font-mono">{data.attackId}</span>
          </Row>
          <Row label="Aliases">
            <Chips kind="actor" items={data.aliases} />
          </Row>
          <Row label={`Techniques used (${data.techniques.length})`}>
            <Chips kind="technique" items={data.techniques} />
          </Row>
          <Row label="Software">
            <Chips kind="malware" items={data.software} />
          </Row>
          {data.campaigns.length > 0 && (
            <Row label="Campaigns">
              <Chips kind="actor" items={data.campaigns} />
            </Row>
          )}
        </>
      );
      break;
    case "attack_software":
      body = (
        <>
          <Row label="ATT&CK ID">
            <span className="font-mono">{data.attackId}</span> <span className="text-muted">· {data.softwareType}</span>
          </Row>
          <Row label="Aliases">
            <Chips kind="malware" items={data.aliases} />
          </Row>
          <Row label="Platforms">{data.platforms.join(", ") || <span className="text-subtle">Not recorded</span>}</Row>
          <Row label={`Techniques (${data.techniques.length})`}>
            <Chips kind="technique" items={data.techniques} />
          </Row>
          <Row label="Used by">
            <Chips kind="actor" items={data.groups} />
          </Row>
        </>
      );
      break;
    case "attack_campaign":
      body = (
        <>
          <Row label="ATT&CK ID">
            <span className="font-mono">{data.attackId}</span>
          </Row>
          <Row label="Active">
            {formatDate(data.firstSeen) ?? "Unknown"} – {formatDate(data.lastSeen) ?? "Unknown"}
          </Row>
          <Row label="Attributed to">
            <Chips kind="actor" items={data.groups} />
          </Row>
          <Row label="Software">
            <Chips kind="malware" items={data.software} />
          </Row>
          <Row label={`Techniques (${data.techniques.length})`}>
            <Chips kind="technique" items={data.techniques} />
          </Row>
        </>
      );
      break;
    case "atomic_test":
      body = (
        <>
          <Row label="Technique">
            <TechniqueSteps ids={[data.techniqueId]} />
          </Row>
          <div className="py-3">
            <p className="mb-2 text-sm text-muted">{data.tests.length} tests</p>
            <ul className="divide-y divide-border rounded-lg border border-border">
              {data.tests.map((t, i) => (
                <li key={t.guid ?? i} className="flex flex-col gap-1.5 px-3 py-2.5 sm:flex-row sm:items-center sm:justify-between">
                  <span className="min-w-0 text-sm text-fg">{t.name}</span>
                  <span className="flex flex-wrap items-center gap-1.5">
                    {t.platforms.map((p) => (
                      <span key={p} className="rounded bg-bg-subtle px-1.5 py-0.5 text-[11px] text-muted">
                        {p}
                      </span>
                    ))}
                    <span className="rounded bg-bg-subtle px-1.5 py-0.5 font-mono text-[11px] text-muted">{t.executor}</span>
                    {t.elevationRequired && <StatusChip tone="warning">Elevated</StatusChip>}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        </>
      );
      break;
    case "emulation_plan":
      body = (
        <>
          <Row label="Adversary">
            <EntityChip kind="actor">{data.adversary}</EntityChip>{" "}
            <span className="ml-1 text-muted">{data.planType === "micro" ? "Micro emulation plan" : "Full emulation plan"}</span>
          </Row>
          <Row label={`Techniques (${data.techniques.length})`}>
            <TechniqueSteps ids={data.techniques} />
          </Row>
          {data.files.length > 0 && (
            <Row label="Plan files">
              <ul className="space-y-1 font-mono text-xs text-muted">
                {data.files.slice(0, 12).map((f) => (
                  <li key={f} className="truncate">
                    {f}
                  </li>
                ))}
                {data.files.length > 12 && <li>+{data.files.length - 12} more</li>}
              </ul>
            </Row>
          )}
        </>
      );
      break;
    case "attack_flow":
      body = (
        <>
          <Row label="Flow">
            {data.flowName}
            {data.scope && <span className="text-muted"> · {data.scope}</span>}
          </Row>
          <Row label={`Actions (${data.actions.length})`}>
            <ol className="space-y-2">
              {data.actions.map((a, i) => (
                <li key={a.id} className="flex items-start gap-2.5">
                  <span
                    className="mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full text-[10px] font-semibold tabular-nums"
                    style={{ color: "var(--color-cat-flow)", backgroundColor: "color-mix(in oklab, var(--color-cat-flow) 16%, transparent)" }}
                  >
                    {i + 1}
                  </span>
                  <div className="min-w-0">
                    <p className="flex flex-wrap items-center gap-1.5 text-sm text-fg">
                      {a.techniqueId && <EntityChip kind="technique">{a.techniqueId}</EntityChip>}
                      {a.name}
                    </p>
                    {a.description && <p className="mt-0.5 line-clamp-2 text-xs text-muted">{a.description}</p>}
                  </div>
                </li>
              ))}
            </ol>
          </Row>
          <Row label="Relationships">
            <span className="tabular-nums">{data.relationships.length}</span> edges between actions
          </Row>
        </>
      );
      break;
    case "kev":
      body = (
        <>
          <Row label="CVE">
            <EntityChip kind="cve">{data.cveId}</EntityChip>
          </Row>
          <Row label="Product">
            {data.vendor} · {data.product}
          </Row>
          <Row label="Added to KEV">{formatDate(data.dateAdded) ?? data.dateAdded}</Row>
          <Row label="Remediation due">
            {data.dueDate ? (
              <span className="inline-flex items-center gap-1.5 font-medium" style={{ color: "var(--color-cat-cve)" }}>
                <ShieldAlert className="size-4" />
                {formatDate(data.dueDate) ?? data.dueDate}
              </span>
            ) : (
              <span className="text-subtle">Not set</span>
            )}
          </Row>
          {data.ransomwareUse && <Row label="Ransomware use">{data.ransomwareUse}</Row>}
          {data.requiredAction && <Row label="Required action">{data.requiredAction}</Row>}
        </>
      );
      break;
  }

  return (
    <div className="rounded-xl border border-border bg-bg-card">
      <div className="flex items-center gap-3 border-b border-border px-5 py-4">
        <EntityIcon kind={meta.kind} />
        <div>
          <h3 className="text-base font-medium text-fg">{meta.title}</h3>
          <p className="text-xs text-muted">Structured record from the source, not text extraction</p>
        </div>
      </div>
      <dl className="divide-y divide-border px-5">{body}</dl>
    </div>
  );
}
