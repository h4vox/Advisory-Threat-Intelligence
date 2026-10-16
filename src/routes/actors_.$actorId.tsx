import { createFileRoute } from "@tanstack/react-router";
import { AppShell } from "@/components/app-shell";
import { PageHeader } from "@/components/layout/page";

// Placeholder — replaced in phase 9.
export const Route = createFileRoute("/actors_/$actorId")({ component: Page });

function Page() {
  const { actorId } = Route.useParams();
  return (
    <AppShell>
      <PageHeader title={actorId} />
    </AppShell>
  );
}
