import { useQuery } from "@tanstack/react-query";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { z } from "zod";
import { ArrowUpRight, Bug, FileText, Info, Layers, Route as RouteIcon, Search, ShieldAlert, Target, UserX, Users } from "lucide-react";
import { AppShell } from "@/components/app-shell";
import { ActionButton, SegmentedTabs } from "@/components/layout/page";
import { DetailPageTemplate } from "@/components/templates/page-templates";
import { ActivitySpinner } from "@/components/ui/activity-spinner";
import { EmptyState, PropertyList, StatusChip } from "@/components/ui/primitives";
import { rememberActorName } from "@/components/actors/actor-names";
import { LinkButton } from "@/components/actors/actor-ui";
import { formatDay, purpleLink, searchLink } from "@/components/actors/actor-format";
import { KpiStrip } from "@/components/actors/kpi-strip";
import { ProfileOverview } from "@/components/actors/profile-overview";
import { CampaignsTab, EmulationTab, ReportsTab, SoftwareTab, TechniquesTab } from "@/components/actors/profile-tabs";
import { getActorProfile } from "@/lib/aie/server-actors";

const TABS = [
  { value: "overview", label: "Overview" },
  { value: "techniques", label: "Techniques" },
  { value: "reports", label: "Reports" },
  { value: "campaigns", label: "Campaigns" },
  { value: "software", label: "Software" },
  { value: "emulation", label: "Emulation" },
] as const;
type TabValue = (typeof TABS)[number]["value"];

const searchSchema = z.object({
  tab: z.enum(TABS.map((t) => t.value) as [TabValue, ...TabValue[]]).optional(),
});

// Non-nested route (actors_): renders on its own page at /actors/$actorId.
export const Route = createFileRoute("/actors_/$actorId")({
  validateSearch: (search) => searchSchema.parse(search),
  component: ActorPage,
});

function ActorPage() {
  const { actorId } = Route.useParams();
  const search = Route.useSearch();
  const navigate = useNavigate({ from: "/actors/$actorId" });
  const tab: TabValue = search.tab ?? "overview";
  const setTab = (t: TabValue) =>
    void navigate({ search: (prev) => ({ ...prev, tab: t === "overview" ? undefined : t }), replace: true });

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["actor-profile", actorId],
    queryFn: () => getActorProfile({ data: { actorId } }),
    staleTime: 30_000,
  });

  if (data) rememberActorName(actorId, data.row.name);

  if (isLoading) {
    return (
      <AppShell>
        <div className="flex flex-col items-center justify-center py-24 text-muted">
          <ActivitySpinner size="lg" className="mb-2 text-accent" />
          <p className="text-sm">Loading actor profile…</p>
        </div>
      </AppShell>
    );
  }

  if (!data) {
    return (
      <AppShell>
        <DetailPageTemplate header={{ backTo: "/actors", icon: UserX, iconKind: "actor", title: "Actor not found" }}>
          <EmptyState
            className="rounded-xl border border-border bg-bg-card"
            icon={UserX}
            title={isError ? "Could not load this actor" : "No actor matches this id"}
            description={
              isError
                ? String((error as Error | null)?.message ?? "Unknown error")
                : `“${actorId}” is not an ATT&CK group ID, name or alias, and no library report names an actor with that id.`
            }
            action={
              <div className="flex flex-wrap justify-center gap-2">
                <ActionButton to="/actors">Browse threat actors</ActionButton>
                <LinkButton icon={Search} link={searchLink(actorId)}>
                  Search reports
                </LinkButton>
              </div>
            }
          />
        </DetailPageTemplate>
      </AppShell>
    );
  }

  const { row } = data;
  const observedTech = data.techniques.filter((t) => t.source !== "attack").length;
  const description = data.description?.trim() ?? "";

  return (
    <AppShell>
      <DetailPageTemplate
        header={{
          backTo: "/actors",
          icon: Users,
          iconKind: "actor",
          title: <span className="whitespace-normal">{row.name}</span>,
          description: (
            <span className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1.5">
              {row.attackId ? (
                <a
                  href={data.attackUrl ?? undefined}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 font-mono text-xs text-accent hover:underline"
                >
                  {row.attackId}
                  <ArrowUpRight className="size-3.5" />
                </a>
              ) : (
                <StatusChip tone="warning">Not in ATT&CK</StatusChip>
              )}
              {row.observed ? (
                <StatusChip tone="info" dot>
                  In library
                </StatusChip>
              ) : (
                <span className="text-subtle">Not seen in library reports</span>
              )}
              {row.aliases.length > 0 && (
                <span className="text-muted">
                  <span className="text-subtle">Also known as </span>
                  {row.aliases.join(", ")}
                </span>
              )}
            </span>
          ),
          actions: (
            <>
              <LinkButton icon={Search} link={searchLink(row.name)}>
                Search reports
              </LinkButton>
              <LinkButton variant="primary" icon={RouteIcon} link={purpleLink(row)}>
                Build purple path
              </LinkButton>
            </>
          ),
          tabs: (
            <SegmentedTabs
              ariaLabel="Actor sections"
              items={TABS.map((t) => ({
                value: t.value,
                label: t.label,
                count:
                  t.value === "techniques"
                    ? data.techniques.length
                    : t.value === "reports"
                      ? data.reports.length
                      : t.value === "campaigns"
                        ? data.campaigns.length
                        : t.value === "software"
                          ? data.software.length
                          : undefined,
              }))}
              value={tab}
              onChange={setTab}
            />
          ),
        }}
        properties={
          <>
            <PropertyList
              items={[
                { label: "ATT&CK ID", value: row.attackId ? <span className="font-mono">{row.attackId}</span> : "Not in ATT&CK" },
                { label: "Aliases", value: row.aliases.length },
                { label: "First seen in library", value: formatDay(row.firstSeen) ?? <span className="text-subtle">Not seen</span> },
                { label: "Last seen in library", value: formatDay(row.lastSeen) ?? <span className="text-subtle">Not seen</span> },
                { label: "Publishers", value: row.publishers.length ? row.publishers.join(", ") : <span className="text-subtle">None</span> },
                { label: "New vs ATT&CK", value: `${row.newTechniques} technique${row.newTechniques === 1 ? "" : "s"}` },
                {
                  label: "ATT&CK snapshot",
                  value: data.attackVersion
                    ? `v${data.attackVersion}${data.attackSnapshotDate ? ` · ${formatDay(data.attackSnapshotDate)}` : ""}`
                    : "Unknown",
                },
              ]}
            />
            {!row.inAttack && (
              <div className="flex gap-2.5 text-sm text-muted">
                <Info className="mt-0.5 size-4 shrink-0 text-subtle" />
                <p>
                  ATT&CK has no group with this name or alias. This profile is built only from library reports; if it is a new name for a known
                  group, it will merge once ATT&CK adds the alias.
                </p>
              </div>
            )}
          </>
        }
      >
        {tab === "overview" && (
          <>
            {description ? (
              <section>
                <h2 className="text-xl font-semibold tracking-tight text-fg">About</h2>
                <p className="mt-2 max-w-3xl text-sm leading-6 text-muted">
                  {description}
                  {/[.!?)]$/.test(description) ? "" : "…"}
                  {data.attackUrl && (
                    <>
                      {" "}
                      <a href={data.attackUrl} target="_blank" rel="noreferrer" className="text-accent hover:underline">
                        Read on ATT&CK →
                      </a>
                    </>
                  )}
                </p>
              </section>
            ) : (
              <section className="rounded-xl border border-border bg-bg-card p-5 text-sm text-muted">
                <span className="font-medium text-fg">Not in ATT&CK.</span> No ATT&CK description, attributed techniques, software or
                campaigns exist for this actor; everything below comes from the {row.reportCount} library report
                {row.reportCount === 1 ? "" : "s"} that name it.
              </section>
            )}

            <KpiStrip
              items={[
                { icon: FileText, kind: "advisory", label: "Library reports", value: row.reportCount },
                {
                  icon: Layers,
                  kind: "technique",
                  label: "Observed techniques",
                  value: observedTech,
                  hint: row.newTechniques ? `${row.newTechniques} new vs ATT&CK` : undefined,
                },
                { icon: Layers, kind: "technique", label: "ATT&CK techniques", value: row.attributedTechniques },
                { icon: Bug, kind: "malware", label: "Software", value: row.software },
                { icon: Target, kind: "actor", label: "Campaigns", value: row.campaigns },
                { icon: ShieldAlert, kind: "cve", label: "CVEs", value: data.cves.length },
              ]}
            />

            <ProfileOverview profile={data} onTab={setTab} />
          </>
        )}
        {tab === "techniques" && <TechniquesTab profile={data} />}
        {tab === "reports" && <ReportsTab profile={data} />}
        {tab === "campaigns" && <CampaignsTab profile={data} />}
        {tab === "software" && <SoftwareTab profile={data} />}
        {tab === "emulation" && <EmulationTab profile={data} />}
      </DetailPageTemplate>
    </AppShell>
  );
}
