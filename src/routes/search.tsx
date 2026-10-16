import { createFileRoute } from "@tanstack/react-router";
import { AppShell } from "@/components/app-shell";
import { PageHeader } from "@/components/layout/page";

// Placeholder — replaced in phase 9.
export const Route = createFileRoute("/search")({ component: Page });

function Page() {
  return (
    <AppShell>
      <PageHeader title="Search" />
    </AppShell>
  );
}
