/**
 * Saved Intel Graph investigations: a named trail of focused entities plus the view settings
 * (filters, lens, detail, 2D/3D, hops), per analyst. Stored in MongoDB (aie_graph_views); without
 * MongoDB the page keeps them in the browser instead (`available: false`).
 */
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { analystMiddleware } from "./access";
import { logger } from "./logger";
import { getMongoDb, isMongoConfigured } from "../mongodb/client.server";

const COLLECTION = "aie_graph_views";
const MAX_PER_USER = 200;

export const savedViewStateSchema = z.object({
  trail: z.array(z.string().min(1).max(400)).min(1).max(60),
  pos: z.number().int().min(0).max(59),
  hops: z.union([z.literal(1), z.literal(2)]),
  dimension: z.enum(["2d", "3d"]),
  detail: z.enum(["key", "standard", "wide"]),
  windowValue: z.enum(["all", "30", "90", "365"]),
  filter: z.object({
    types: z.array(z.string().max(40)).max(20),
    minReports: z.number().int().min(1).max(100),
    minConfidence: z.number().min(0).max(1),
    statedOnly: z.boolean(),
    since: z.string().max(40).nullable(),
    tactics: z.array(z.string().max(60)).max(20).optional(),
  }),
  /** Entity labels for the trail, so the list reads well without loading the graph. */
  labels: z.array(z.string().max(200)).max(60),
});
export type SavedViewState = z.infer<typeof savedViewStateSchema>;
export type SavedView = { id: string; name: string; note: string; state: SavedViewState; createdAt: string; updatedAt: string };

export const listGraphViews = createServerFn({ method: "GET" })
  .middleware([analystMiddleware])
  .handler(async ({ context }): Promise<{ available: boolean; views: SavedView[] }> => {
    if (!isMongoConfigured()) return { available: false, views: [] };
    const col = (await getMongoDb()).collection(COLLECTION);
    const docs = await col.find({ userId: context.userId }, { projection: { _id: 0, userId: 0 } }).sort({ updatedAt: -1 }).limit(MAX_PER_USER).toArray();
    return { available: true, views: docs as unknown as SavedView[] };
  });

export const saveGraphView = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(z.object({ id: z.string().max(80).optional(), name: z.string().trim().min(1).max(80), note: z.string().trim().max(500).default(""), state: savedViewStateSchema }))
  .handler(async ({ data, context }): Promise<SavedView> => {
    if (!isMongoConfigured()) throw new Error("Saving on the server needs MongoDB; the view is kept in this browser instead.");
    const col = (await getMongoDb()).collection(COLLECTION);
    const now = new Date().toISOString();
    const id = data.id ?? `gv_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
    const existing = data.id ? await col.findOne({ id, userId: context.userId }, { projection: { createdAt: 1 } }) : null;
    const view: SavedView = { id, name: data.name, note: data.note, state: data.state, createdAt: (existing?.createdAt as string) ?? now, updatedAt: now };
    await col.updateOne({ id, userId: context.userId }, { $set: { ...view, userId: context.userId } }, { upsert: true });
    logger.intel("VIEW", `Saved investigation "${data.name}"`, { steps: data.state.trail.length });
    return view;
  });

export const deleteGraphView = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(z.object({ id: z.string().min(1).max(80) }))
  .handler(async ({ data, context }): Promise<{ ok: boolean }> => {
    if (!isMongoConfigured()) return { ok: false };
    const res = await (await getMongoDb()).collection(COLLECTION).deleteOne({ id: data.id, userId: context.userId });
    logger.intel("VIEW", `Deleted saved investigation ${data.id}`);
    return { ok: res.deletedCount === 1 };
  });
