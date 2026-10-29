/**
 * Hand-offs to the AI Agent from anywhere in the app: a button ("Ask the agent") or dragging an
 * entity onto the AI Agent button / chat. The app shell opens the chat and sends the request.
 * Also: opening the entity context panel for any entity (the shell mounts it once).
 */
import type { DragEvent } from "react";

export const AGENT_ASK_EVENT = "aie-agent-ask";
export const ENTITY_CONTEXT_EVENT = "aie-entity-context";
/** Drag payload type for an entity (JSON: EntityHandoff). */
export const ENTITY_MIME = "application/x-aie-entity";

export type EntityHandoff = {
  /** Graph node id ("actor:G0016") or any name / ID the engine can resolve. */
  ref: string;
  label: string;
  /** Entity type label for the prompt ("threat actor", "technique"…). */
  kind?: string;
  /** Optional: a relationship to explain instead of a single entity. */
  relation?: { from: string; predicate: string; to: string };
};

/** The request the agent receives for an entity or a relationship. */
export function handoffPrompt(e: EntityHandoff): string {
  if (e.relation) {
    return `Explain the relationship "${e.relation.from} ${e.relation.predicate} ${e.relation.to}": use find_connection from "${e.relation.from}" to "${e.relation.to}" and entity_context to show what supports it, how strong it is, and what else connects them. Cite the reports.`;
  }
  return `Investigate ${e.label}${e.kind ? ` (${e.kind})` : ""}: use entity_context for "${e.ref}" to pull everything correlated with it, then tell me what the library knows, its most important relationships, possible hidden links worth checking, and what is missing. Cite the reports.`;
}

export function askAgent(text: string) {
  window.dispatchEvent(new CustomEvent(AGENT_ASK_EVENT, { detail: { text } }));
}

export function askAgentAbout(e: EntityHandoff) {
  askAgent(handoffPrompt(e));
}

export function openEntityContext(ref: string) {
  window.dispatchEvent(new CustomEvent(ENTITY_CONTEXT_EVENT, { detail: { ref } }));
}

/** Props that make an element draggable onto the AI Agent. */
export function entityDragProps(e: EntityHandoff) {
  return {
    draggable: true,
    onDragStart: (ev: DragEvent) => {
      ev.dataTransfer.setData(ENTITY_MIME, JSON.stringify(e));
      ev.dataTransfer.setData("text/plain", e.label);
      ev.dataTransfer.effectAllowed = "copy";
    },
  };
}

/** Reads an entity dropped on an agent drop zone, or null. */
export function readDroppedEntity(ev: DragEvent): EntityHandoff | null {
  const raw = ev.dataTransfer.getData(ENTITY_MIME);
  if (!raw) return null;
  try {
    const e = JSON.parse(raw) as EntityHandoff;
    return typeof e?.ref === "string" && typeof e?.label === "string" ? e : null;
  } catch {
    return null;
  }
}

export const isEntityDrag = (ev: DragEvent) => ev.dataTransfer.types.includes(ENTITY_MIME);
