/**
 * Library hygiene server functions.
 *
 *   runLibraryGate        checks reports not yet checked under the current rules and hides the
 *                         unrelated ones (homepages, listings, webinars, product news, stubs…)
 *   setReportVisibility   an analyst hides reports by hand, or restores hidden ones for good
 *   getResearchCoverage   visible reports per research category (./research-taxonomy)
 *   labelLibraryResearch  labels reports stored before labelling (or under an older labeller)
 *   dateLibraryReports    re-dates reports stored before the publication-date resolver (or an older one)
 *
 * Rules: ./library-gate (pure, unit-tested). Storage: ../mongodb/library-gate-repo.server.
 * Nothing is deleted; hidden reports stay listed in the Library's "Hidden" view with the reason.
 */
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { analystMiddleware } from "./access";
import { runLibraryGatePass, setReportVisibility as setVisibility } from "../mongodb/library-gate-repo.server";
import { mongoLabelResearchBatch, mongoResearchCoverage } from "../mongodb/research-repo.server";
import { mongoRedateReportsBatch } from "../mongodb/published-date-repo.server";

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

export const getResearchCoverage = createServerFn({ method: "GET" })
  .middleware([analystMiddleware])
  .handler(async () => mongoResearchCoverage());

/** One batch; the caller repeats while `remaining` is above zero. Derived data only. */
export const labelLibraryResearch = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .handler(async () => mongoLabelResearchBatch(200));

/** One batch of the publication-date backfill; the caller repeats while `remaining` is above zero. */
export const dateLibraryReports = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .handler(async () => mongoRedateReportsBatch(25));
