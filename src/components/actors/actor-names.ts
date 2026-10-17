/**
 * Display names for actor ids seen by the actor pages, so the top-bar breadcrumb can read
 * "Intelligence / Threat actors / Akira" instead of a raw id. The profile page records the name while
 * rendering (idempotent), and AppShell re-renders with it as the page's parent re-renders.
 */
const names = new Map<string, string>();

export function rememberActorName(id: string, name: string) {
  if (id && name) names.set(id.toLowerCase(), name);
}

export function actorCrumbName(id: string): string | undefined {
  return names.get(id.toLowerCase());
}
