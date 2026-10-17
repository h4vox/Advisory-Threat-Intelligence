/**
 * Library hygiene server functions.
 *
 *   runLibraryGate        checks reports not yet checked under the current rules and hides the
 *                         unrelated ones (homepages, listings, webinars, product news, stubs…)
 *   setReportVisibility   an analyst hides reports by hand, or restores hidden ones for good
 *
 * Rules: ./library-gate (pure, unit-tested). Storage: ../mongodb/library-gate-repo.server.
 * Nothing is deleted; hidden reports stay listed in the Library's "Hidden" view with the reason.
 */
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { analystMiddleware } from "./access";
import { runLibraryGatePass, setReportVisibility as setVisibility } from "../mongodb/library-gate-repo.server";

export const runLibraryGate = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .handler(async () => runLibraryGatePass());

export const setReportVisibility = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(z.object({ ids: z.array(z.string().min(1).max(200)).min(1).max(500), action: z.enum(["hide", "restore"]) }))
  .handler(async ({ data, context }) => {
    const by = context.identity.username ?? context.userEmail ?? "an analyst";
    return setVisibility(data.ids, data.action, by);
  });
