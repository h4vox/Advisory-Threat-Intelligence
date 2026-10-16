import { useMemo, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import type { ColumnDef } from "@tanstack/react-table";
import { Bell, Bot, Download, FileText, Globe2, Inbox, Keyboard, Library, Moon, Palette, PanelTop, Plus, Radar, Search, ShieldAlert, Sparkles, Upload, UserRound } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { ActionButton, SectionCard, SegmentedTabs, StatCard, Toolbar } from "@/components/layout/page";
import { DataTable } from "@/components/ui/data-table";
import { EmptyState, Meter, PropertyList, StatusChip, StatusDot } from "@/components/ui/primitives";
import { DashboardTemplate, Pagination, TwoUp } from "@/components/templates/page-templates";
import { DOC_TYPE_META, DocTypeBadge, EntityChip, EntityIcon, entityMeta, type EntityKind } from "@/components/ui/entity";
import type { DocType } from "@/lib/aie/types";

const KINDS: EntityKind[] = ["actor", "malware", "technique", "cve", "ioc", "source", "advisory", "emulation", "flow"];
const SAMPLE_DOC_TYPES: DocType[] = [
  "THREAT_REPORT",
  "THREAT_ADVISORY",
  "INCIDENT_REPORT",
  "MALWARE_REPORT",
  "VULNERABILITY_ADVISORY",
  "CAMPAIGN_REPORT",
  "ADVERSARY_EMULATION_PLAN",
  "ATTACK_FLOW",
  "ATOMIC_TEST",
  "KEV_ENTRY",
];

const CHROME: Array<{ icon: typeof Bell; name: string; note: string }> = [
  { icon: PanelTop, name: "Breadcrumb", note: "Section / page, derived from the sidebar groups" },
  { icon: Search, name: "Search field", note: "Opens the ⌘K palette (pages + report search)" },
  { icon: Sparkles, name: "UI style switch", note: "Default / Liquid glass segmented control" },
  { icon: Moon, name: "Theme toggle", note: "Dark (default) / light" },
  { icon: Bell, name: "Activity", note: "Recent crawl & ingest events from the dashboard feed" },
  { icon: Bot, name: "AI Agent", note: "Opens the agent chat drawer" },
  { icon: UserRound, name: "Profile menu", note: "Profile dialog, Settings, Keyboard shortcuts, Sign out" },
  { icon: Keyboard, name: "Shortcuts", note: "⌘K search · ? shortcuts sheet · Esc closes" },
];

export const Route = createFileRoute("/ui-kit")({ component: UiKit });

type SampleRow = { id: string; title: string; publisher: string; published: string; quality: number; iocs: number; status: "Observed" | "Pending" | "Rejected" };

// Illustrative sample rows for the component gallery only (not intelligence data).
const SAMPLE: SampleRow[] = [
  { id: "rpt_a1", title: "Example intrusion report", publisher: "Example Research", published: "2026-09-02", quality: 0.92, iocs: 24, status: "Observed" },
  { id: "rpt_b2", title: "Example vulnerability advisory", publisher: "Example CERT", published: "2026-08-21", quality: 0.61, iocs: 3, status: "Pending" },
  { id: "rpt_c3", title: "Example vendor blog post", publisher: "Example Vendor", published: "2026-07-30", quality: 0.28, iocs: 0, status: "Rejected" },
];

const TONES = { Observed: "success", Pending: "warning", Rejected: "danger" } as const;

function UiKit() {
  const [tab, setTab] = useState<"all" | "chains" | "advisories">("all");
  const [page, setPage] = useState(1);
  const columns = useMemo<ColumnDef<SampleRow, any>[]>(
    () => [
      {
        accessorKey: "title",
        header: "Title",
        cell: ({ row }) => (
          <div className="flex min-w-0 items-center gap-2.5">
            <FileText className="size-4 shrink-0 text-muted" strokeWidth={1.75} />
            <span className="truncate font-medium">{row.original.title}</span>
          </div>
        ),
      },
      { accessorKey: "publisher", header: "Publisher", meta: { hideBelow: "md" } },
      { accessorKey: "published", header: "Published", meta: { hideBelow: "lg", className: "tabular-nums text-muted" } },
      {
        accessorKey: "quality",
        header: "Quality",
        cell: ({ getValue }) => (
          <div className="flex w-28 items-center gap-2">
            <Meter value={getValue<number>()} label="Quality" />
            <span className="w-9 text-right text-xs tabular-nums text-muted">{Math.round(getValue<number>() * 100)}%</span>
          </div>
        ),
        meta: { hideBelow: "sm" },
      },
      { accessorKey: "iocs", header: "IOCs", meta: { align: "right" } },
      {
        accessorKey: "status",
        header: "Status",
        cell: ({ getValue }) => <StatusChip tone={TONES[getValue<SampleRow["status"]>()]}>{getValue<string>()}</StatusChip>,
      },
    ],
    [],
  );

  return (
    <AppShell>
      <DashboardTemplate
        header={{
          title: "UI kit",
          description: "Reference components and templates. Build every screen from these (docs/UI_DESIGN_SYSTEM.md).",
          actions: (
            <>
              <ActionButton icon={Download}>Outline action</ActionButton>
              <ActionButton icon={Plus} variant="primary">
                Primary action
              </ActionButton>
            </>
          ),
          tabs: (
            <SegmentedTabs
              value={tab}
              onChange={setTab}
              ariaLabel="Example tabs"
              items={[
                { value: "all", label: "All", count: 3, icon: Library },
                { value: "chains", label: "Attack chains", count: 1 },
                { value: "advisories", label: "Advisories", count: 1 },
              ]}
            />
          ),
        }}
        stats={
          <>
            <StatCard icon={Globe2} kind="source" label="Sources" value={20} hint="Example hint text" to="/sources" />
            <StatCard icon={Library} kind="advisory" label="Reports" value={654} delta={{ value: "12", direction: "up" }} to="/library" />
            <StatCard icon={ShieldAlert} kind="technique" label="Techniques" value={87} delta={{ value: "0", direction: "flat" }} />
            <StatCard icon={Radar} kind="ioc" label="IOCs" value={1203} delta={{ value: "4", direction: "down" }} />
          </>
        }
      >
        <TwoUp ratio="7:5">
          <SectionCard title="Colour system" icon={Palette} info="Primary = brand & the one primary action. Category hues identify kinds of things. Status hues carry state.">
            <div className="flex flex-wrap items-center gap-3">
              <span className="flex items-center gap-2.5">
                <span className="size-8 rounded-lg bg-primary" />
                <span>
                  <span className="block text-sm font-medium text-fg">Primary</span>
                  <span className="block font-mono text-[11px] text-subtle">--color-primary</span>
                </span>
              </span>
              <ActionButton variant="primary" icon={Plus}>
                Primary action
              </ActionButton>
            </div>
            <div className="mt-5 grid grid-cols-1 gap-x-4 gap-y-3 sm:grid-cols-2 xl:grid-cols-3">
              {KINDS.map((k) => (
                <div key={k} className="flex min-w-0 items-center gap-2.5">
                  <EntityIcon kind={k} />
                  <span className="min-w-0">
                    <span className="block truncate text-sm text-fg">{entityMeta(k).label}</span>
                    <span className="block truncate font-mono text-[11px] text-subtle">--color-cat-{k}</span>
                  </span>
                </div>
              ))}
            </div>
            <div className="mt-5 border-t border-border pt-4">
              <div className="mb-2 text-xs text-subtle">EntityChip</div>
              <div className="flex flex-wrap gap-2">
                <EntityChip kind="actor">APT29</EntityChip>
                <EntityChip kind="malware">Cobalt Strike</EntityChip>
                <EntityChip kind="technique">T1059.001</EntityChip>
                <EntityChip kind="cve">CVE-2024-3400</EntityChip>
                <EntityChip kind="ioc">203.0.113.7</EntityChip>
                <EntityChip kind="flow">Attack flow</EntityChip>
              </div>
            </div>
          </SectionCard>
          <SectionCard title="Document types" icon={FileText} iconKind="advisory" info="DocTypeBadge — one hue per document family (DOC_TYPE_META).">
            <div className="flex flex-wrap gap-2">
              {SAMPLE_DOC_TYPES.map((t) => (
                <span key={t} title={DOC_TYPE_META[t].label}>
                  <DocTypeBadge type={t} />
                </span>
              ))}
            </div>
            <div className="mt-5 border-t border-border pt-4">
              <div className="mb-2 text-xs text-subtle">Global top bar (see it above this page)</div>
              <ul className="space-y-2">
                {CHROME.map((c) => (
                  <li key={c.name} className="flex items-start gap-2.5 text-sm">
                    <c.icon className="mt-0.5 size-4 shrink-0 text-primary" strokeWidth={1.9} />
                    <span>
                      <span className="text-fg">{c.name}</span>
                      <span className="text-muted"> — {c.note}</span>
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          </SectionCard>
        </TwoUp>

        <SectionCard title="Data table" info="Sortable columns, row selection, row click, responsive column hiding." bodyClassName="px-5 pb-5 pt-4">
          <Toolbar
            left={
              <input
                placeholder="Search…"
                className="h-9 w-64 max-w-full rounded-lg border border-border bg-bg-elevated px-3 text-sm text-fg placeholder:text-subtle focus:outline-none focus:ring-1 focus:ring-ring"
              />
            }
            right={<ActionButton icon={Upload}>Export</ActionButton>}
          />
          <DataTable data={SAMPLE} columns={columns} getRowId={(r) => r.id} selectable onRowClick={() => undefined} />
          <div className="mt-4">
            <Pagination page={page} pageCount={3} total={60} pageSize={20} onPage={setPage} />
          </div>
        </SectionCard>

        <TwoUp ratio="7:5">
          <SectionCard title="Status and meters" icon={Radar} iconKind="ioc" actions={<StatusDot>Active</StatusDot>}>
            <div className="flex flex-wrap gap-2">
              <StatusChip>Neutral</StatusChip>
              <StatusChip tone="success" dot>
                Observed
              </StatusChip>
              <StatusChip tone="warning">At risk</StatusChip>
              <StatusChip tone="danger">Critical</StatusChip>
              <StatusChip tone="info">Inferred</StatusChip>
              <StatusChip tone="primary">Selected</StatusChip>
            </div>
            <div className="mt-6 space-y-3">
              <Meter value={0.9} tone="primary" label="Example" />
              <Meter value={0.82} tone="success" label="Example" />
              <Meter value={0.64} tone="info" label="Example" />
              <Meter value={0.45} tone="warning" label="Example" />
              <Meter value={0.12} tone="danger" label="Example" />
              <Meter value={0.7} color={entityMeta("technique").color} label="Category colour" />
            </div>
          </SectionCard>
          <SectionCard title="Property list">
            <PropertyList
              title={null}
              items={[
                { label: "ID", value: <span className="font-mono text-xs">rpt_a1b2c3d4</span> },
                { label: "Publisher", value: "Example Research" },
                { label: "Published", value: "Sep 2, 2026" },
                { label: "Status", value: <StatusChip tone="success">Observed</StatusChip> },
                { label: "Event date", value: null },
              ]}
            />
          </SectionCard>
        </TwoUp>

        <SectionCard title="Empty state">
          <EmptyState
            icon={Inbox}
            title="No reports yet"
            description="Reports appear here after the first crawl or manual ingest."
            action={<ActionButton variant="primary" icon={Upload} to="/ingest">Ingest a report</ActionButton>}
          />
        </SectionCard>
      </DashboardTemplate>
    </AppShell>
  );
}
