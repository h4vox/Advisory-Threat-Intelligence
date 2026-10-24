import { useMemo, useState } from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { AlertCircle, Plus, ScrollText, Search, ShieldAlert, Target, X } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { ActionButton, PageHeader, Toolbar } from "@/components/layout/page";
import { ActivitySpinner } from "@/components/ui/activity-spinner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { EmptyState, StatusChip, type Tone } from "@/components/ui/primitives";
import { cn } from "@/lib/cn";
import { createAdvisory, listAdvisories } from "@/lib/aie/server-advisories";
import type { AdvisorySeverity, AdvisoryStatus, AdvisorySubjectKind, AdvisorySummary, Tlp } from "@/lib/aie/advisory/types";

export const Route = createFileRoute("/advisories")({ component: AdvisoriesPage });

const SEVERITY_TONE: Record<AdvisorySeverity, Tone> = { critical: "danger", high: "warning", medium: "info", low: "neutral" };
const STATUS_TONE: Record<AdvisoryStatus, Tone> = { published: "success", review: "info", simulating: "warning", draft: "neutral", closed: "neutral" };

const SUBJECT_KINDS: Array<{ value: AdvisorySubjectKind; label: string; hint: string; placeholder: string }> = [
  { value: "actor", label: "Threat actor", hint: "ATT&CK group id (G0016) or an actor name", placeholder: "e.g. APT29 or G0016" },
  { value: "campaign", label: "Campaign", hint: "ATT&CK campaign id (C0024) or a campaign name", placeholder: "e.g. C0024" },
  { value: "malware", label: "Malware / tool", hint: "ATT&CK software id (S0154) or a malware name", placeholder: "e.g. Cobalt Strike or S0154" },
  { value: "vulnerability", label: "Vulnerability", hint: "One or more CVE ids", placeholder: "e.g. CVE-2026-1234" },
  { value: "reports", label: "Selected reports", hint: "Library report ids, comma or space separated", placeholder: "e.g. rpt_abc, rpt_def" },
];

const TLPS: Tlp[] = ["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"];

function AdvisoriesPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [statusFilter, setStatusFilter] = useState<"all" | AdvisoryStatus>("all");
  const [query, setQuery] = useState("");
  const [showCreate, setShowCreate] = useState(false);

  const { data: advisories, isLoading } = useQuery({ queryKey: ["advisories"], queryFn: () => listAdvisories() });

  const filtered = useMemo(() => {
    const list = advisories ?? [];
    const q = query.trim().toLowerCase();
    return list.filter((a) => {
      if (statusFilter !== "all" && a.status !== statusFilter) return false;
      if (!q) return true;
      return `${a.number} ${a.title} ${a.subject.name}`.toLowerCase().includes(q);
    });
  }, [advisories, statusFilter, query]);

  return (
    <AppShell>
      <div className="mx-auto max-w-7xl px-4 py-6 md:px-8">
        <PageHeader
          title="Advisories"
          icon={ScrollText}
          description="Generate evidence-backed threat advisories from the library and ATT&CK, then validate detection coverage with purple-team simulation runs."
          actions={
            <ActionButton variant="primary" icon={Plus} onClick={() => setShowCreate(true)}>
              New advisory
            </ActionButton>
          }
        />

        <Toolbar
          className="mb-5"
          left={
            <div className="flex flex-wrap items-center gap-1.5">
              {(["all", "draft", "review", "simulating", "published", "closed"] as const).map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => setStatusFilter(s)}
                  className={cn(
                    "rounded-lg border px-2.5 py-1 text-xs font-medium capitalize transition-colors",
                    statusFilter === s ? "border-primary/40 bg-primary/10 text-primary" : "border-border bg-bg-elevated text-muted hover:text-fg",
                  )}
                >
                  {s}
                </button>
              ))}
            </div>
          }
          right={
            <div className="relative w-full sm:w-64">
              <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-subtle" strokeWidth={1.75} />
              <Input placeholder="Filter advisories…" aria-label="Filter advisories" value={query} onChange={(e) => setQuery(e.target.value)} className="h-9 rounded-lg border-border bg-bg-elevated pl-9 text-sm" />
            </div>
          }
        />

        {isLoading ? (
          <div className="flex flex-col items-center justify-center py-24 text-muted">
            <ActivitySpinner size="lg" className="mb-2 text-accent" />
            <p className="text-sm">Loading advisories…</p>
          </div>
        ) : filtered.length === 0 ? (
          <EmptyState
            icon={ScrollText}
            title={advisories && advisories.length > 0 ? "No advisories match your filters" : "No advisories yet"}
            description={advisories && advisories.length > 0 ? "Try a different status or search term." : "Generate your first advisory from a threat actor, campaign, malware family, a CVE, or a set of library reports."}
            action={<ActionButton variant="primary" icon={Plus} onClick={() => setShowCreate(true)}>New advisory</ActionButton>}
          />
        ) : (
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
            {filtered.map((a) => (
              <AdvisoryCard key={a.id} advisory={a} onOpen={() => navigate({ to: "/advisories/$advisoryId", params: { advisoryId: a.id } })} />
            ))}
          </div>
        )}
      </div>

      {showCreate && (
        <CreateAdvisoryModal
          onClose={() => setShowCreate(false)}
          onCreated={(id) => {
            setShowCreate(false);
            void qc.invalidateQueries({ queryKey: ["advisories"] });
            navigate({ to: "/advisories/$advisoryId", params: { advisoryId: id } });
          }}
        />
      )}
    </AppShell>
  );
}

function AdvisoryCard({ advisory: a, onOpen }: { advisory: AdvisorySummary; onOpen: () => void }) {
  const rate = a.latestRun?.detectionRate;
  return (
    <button type="button" onClick={onOpen} className="flex flex-col rounded-xl border border-border bg-bg-card p-5 text-left transition-colors hover:border-border-strong">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="font-mono text-[11px] text-subtle">{a.number}</div>
          <h3 className="mt-0.5 truncate text-base font-medium text-fg">{a.title}</h3>
          <div className="mt-0.5 truncate text-xs text-subtle">
            <span className="capitalize">{a.subject.kind}</span> · {a.subject.name}
          </div>
        </div>
        <StatusChip tone={SEVERITY_TONE[a.severity]}>{a.severity}</StatusChip>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-1.5">
        <StatusChip tone={STATUS_TONE[a.status]}>{a.status}</StatusChip>
        <StatusChip tone="neutral">TLP:{a.tlp}</StatusChip>
      </div>

      <div className="mt-4 grid grid-cols-3 gap-2 text-center text-xs">
        <Stat label="Behaviours" value={a.behaviours} />
        <Stat label="In scope" value={a.scopedSteps} />
        <Stat label="Sources" value={a.sources} />
      </div>

      <div className="mt-auto flex items-center justify-between pt-4 text-[11px] text-subtle">
        {a.latestRun ? (
          <span className="flex items-center gap-1.5">
            <Target className="size-3.5 text-accent" />
            Run {a.latestRun.number}: {rate === null || rate === undefined ? "—" : `${Math.round(rate * 100)}% detected`}
          </span>
        ) : (
          <span className="flex items-center gap-1.5 text-subtle">
            <ShieldAlert className="size-3.5" />
            No simulation yet
          </span>
        )}
        <span>{new Date(a.updatedAt).toLocaleDateString()}</span>
      </div>
    </button>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg border border-border bg-bg-subtle py-2">
      <div className="text-base font-semibold text-fg">{value}</div>
      <div className="text-[10px] uppercase tracking-wide text-subtle">{label}</div>
    </div>
  );
}

function CreateAdvisoryModal({ onClose, onCreated }: { onClose: () => void; onCreated: (id: string) => void }) {
  const [kind, setKind] = useState<AdvisorySubjectKind>("actor");
  const [value, setValue] = useState("");
  const [tlp, setTlp] = useState<Tlp>("AMBER");
  const [maxSteps, setMaxSteps] = useState(12);
  const spec = SUBJECT_KINDS.find((k) => k.value === kind)!;

  const createMutation = useMutation({
    mutationFn: () => {
      const input: { kind: AdvisorySubjectKind; value?: string; cveIds?: string[]; reportIds?: string[] } = { kind };
      const raw = value.trim();
      if (kind === "vulnerability") input.cveIds = raw.split(/[\s,;]+/).filter(Boolean);
      else if (kind === "reports") input.reportIds = raw.split(/[\s,;]+/).filter(Boolean);
      else input.value = raw;
      return createAdvisory({ data: { input, options: { platforms: [], excludeHighRisk: false, maxSteps }, tlp } });
    },
    onSuccess: (rec) => {
      toast.success(`Advisory ${rec.number} created`);
      onCreated(rec.id);
    },
    onError: (err: Error) => toast.error(err.message || "Could not generate the advisory"),
  });

  const canSubmit = value.trim().length > 0 && !createMutation.isPending;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="fixed inset-0 bg-black/60 backdrop-blur-xs" onClick={onClose} />
      <div className="relative z-10 w-full max-w-lg rounded-xl border border-border bg-bg-card p-6 shadow-2xl animate-in zoom-in-95 duration-150">
        <div className="mb-4 flex items-start justify-between">
          <div>
            <h3 className="text-base font-medium text-fg">New advisory</h3>
            <p className="mt-0.5 text-xs text-subtle">Generated from the library and ATT&CK. You can edit and regenerate it afterwards.</p>
          </div>
          <button onClick={onClose} aria-label="Close" className="rounded-lg p-1 text-subtle hover:bg-bg-subtle hover:text-fg">
            <X className="size-4" />
          </button>
        </div>

        <div className="space-y-4">
          <div>
            <label className="mb-1.5 block text-xs font-medium text-muted">Subject</label>
            <div className="flex flex-wrap gap-1.5">
              {SUBJECT_KINDS.map((k) => (
                <button
                  key={k.value}
                  type="button"
                  onClick={() => setKind(k.value)}
                  className={cn(
                    "rounded-lg border px-2.5 py-1.5 text-xs font-medium transition-colors",
                    kind === k.value ? "border-primary/40 bg-primary/10 text-primary" : "border-border bg-bg-elevated text-muted hover:text-fg",
                  )}
                >
                  {k.label}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="mb-1.5 block text-xs font-medium text-muted">{spec.label}</label>
            <Input autoFocus value={value} onChange={(e) => setValue(e.target.value)} placeholder={spec.placeholder} className="bg-bg-subtle text-sm" onKeyDown={(e) => { if (e.key === "Enter" && canSubmit) createMutation.mutate(); }} />
            <p className="mt-1 text-[11px] text-subtle">{spec.hint}</p>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label htmlFor="new-advisory-tlp" className="mb-1.5 block text-xs font-medium text-muted">TLP</label>
              <Select id="new-advisory-tlp" value={tlp} onValueChange={(v) => setTlp(v as Tlp)} className="w-full">
                {TLPS.map((t) => (
                  <option key={t} value={t}>TLP:{t}</option>
                ))}
              </Select>
            </div>
            <div>
              <label className="mb-1.5 block text-xs font-medium text-muted">Max simulation steps: {maxSteps}</label>
              <input type="range" min={4} max={30} step={1} value={maxSteps} onChange={(e) => setMaxSteps(Number(e.target.value))} className="mt-2 w-full accent-accent" />
            </div>
          </div>
        </div>

        {createMutation.isError && (
          <div className="mt-4 flex items-center gap-2 rounded-lg border border-danger/50 bg-danger/10 p-2.5 text-xs text-danger">
            <AlertCircle className="size-4 shrink-0" />
            <span>{(createMutation.error as Error)?.message}</span>
          </div>
        )}

        <div className="mt-6 flex items-center justify-end gap-2 border-t border-border pt-4">
          <Button size="sm" variant="secondary" onClick={onClose} className="text-xs">Cancel</Button>
          <Button size="sm" variant="primary" disabled={!canSubmit} onClick={() => createMutation.mutate()} className="gap-1.5 text-xs">
            {createMutation.isPending ? <ActivitySpinner size="xs" className="text-white" /> : <Plus className="size-3.5" />}
            {createMutation.isPending ? "Generating…" : "Generate advisory"}
          </Button>
        </div>
      </div>
    </div>
  );
}
