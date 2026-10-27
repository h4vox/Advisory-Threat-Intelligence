/**
 * Where each MongoDB document goes in PostgreSQL, and how it is made safe to store.
 *
 * Two databases (see docs/db-migration.md):
 *   aie_intel  shared intelligence, the same for every account and every instance:
 *              reports, sources, discovery, ATT&CK / KEV knowledge, crawl history,
 *              advisories and simulation playbooks
 *   aie_app    this instance and its users: accounts, sign-in sessions, settings,
 *              crawler configuration and locks, AI chat sessions, marketplace
 *              integrations (they hold API keys), and anything not recognised
 *
 * Unknown collections and document types are never dropped: they land in
 * aie_app.unclassified_documents, the more private of the two, until they are classified.
 *
 * Pure: no I/O. Unit-tested in routing.test.mjs.
 */
import { createHash } from "node:crypto";

export const INTEL_DB = "aie_intel";
export const APP_DB = "aie_app";

/** The collection the app keeps most documents in, told apart by `docType`. */
export const MAIN_COLLECTION = "threat-intel";

/** docType in the main collection → [database, table]. */
export const DOC_TYPE_ROUTES = {
  report: [INTEL_DB, "reports"],
  source: [INTEL_DB, "sources"],
  discovered_source: [INTEL_DB, "discovered_sources"],
  discovered_resource: [INTEL_DB, "discovered_resources"],
  graph_edge: [INTEL_DB, "graph_edges"],
  kev: [INTEL_DB, "knowledge_objects"],
  attack_technique: [INTEL_DB, "knowledge_objects"],
  emulation_index: [INTEL_DB, "knowledge_objects"],
  crawl_job: [INTEL_DB, "crawl_jobs"],
  crawl_job_item: [INTEL_DB, "crawl_job_items"],
  ingest_event: [INTEL_DB, "ingest_events"],
  collector_fetch_state: [INTEL_DB, "collector_state"],
  collector_source_health: [INTEL_DB, "collector_state"],
  app_settings: [APP_DB, "app_state"],
  crawl_config: [APP_DB, "app_state"],
  crawl_lock: [APP_DB, "app_state"],
  maintenance: [APP_DB, "app_state"],
  agent_chat_session: [APP_DB, "agent_chat_sessions"],
  agent_chat_message: [APP_DB, "agent_chat_messages"],
  marketplace_integration: [APP_DB, "integrations"],
};

/** Dedicated collections → [database, table]. */
export const COLLECTION_ROUTES = {
  aie_users: [APP_DB, "users"],
  aie_sessions: [APP_DB, "auth_sessions"],
  aie_advisories: [INTEL_DB, "advisories"],
  aie_simulation_runs: [INTEL_DB, "simulation_runs"],
};

export const UNCLASSIFIED = [APP_DB, "unclassified_documents"];

/** Every table the schema creates, per database (the schema files define the same list). */
export const TABLES = {
  [INTEL_DB]: [
    "reports",
    "sources",
    "discovered_sources",
    "discovered_resources",
    "graph_edges",
    "knowledge_objects",
    "crawl_jobs",
    "crawl_job_items",
    "ingest_events",
    "collector_state",
    "advisories",
    "simulation_runs",
  ],
  [APP_DB]: ["users", "auth_sessions", "app_state", "agent_chat_sessions", "agent_chat_messages", "integrations", "unclassified_documents"],
};

/**
 * Database and table for one document. `collection` is the source collection name; the main
 * collection is routed by docType, a configured MONGODB_COLLECTION name counts as the main one.
 */
export function routeDocument(collection, doc, mainCollection = MAIN_COLLECTION) {
  if (collection === mainCollection || collection === MAIN_COLLECTION) {
    const route = DOC_TYPE_ROUTES[doc?.docType];
    if (route) return { db: route[0], table: route[1] };
    return { db: UNCLASSIFIED[0], table: UNCLASSIFIED[1] };
  }
  const route = COLLECTION_ROUTES[collection];
  if (route) return { db: route[0], table: route[1] };
  return { db: UNCLASSIFIED[0], table: UNCLASSIFIED[1] };
}

/**
 * PostgreSQL jsonb cannot hold the NUL character (\u0000), which scraped text sometimes contains.
 * Removes it from every string and key; returns the cleaned value and how many were removed.
 * Everything else is kept exactly.
 */
export function stripNul(value) {
  let removed = 0;
  const clean = (v) => {
    if (typeof v === "string") {
      if (!v.includes("\u0000")) return v;
      const out = v.replace(/\u0000/g, "");
      removed += v.length - out.length;
      return out;
    }
    if (Array.isArray(v)) return v.map(clean);
    if (v && typeof v === "object") {
      const o = {};
      for (const [k, x] of Object.entries(v)) o[clean(k)] = clean(x);
      return o;
    }
    return v;
  };
  return { value: clean(value), removed };
}

/** Key order-independent JSON, so the same document always hashes the same. */
export function stableStringify(v) {
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(",")}]`;
  if (v && typeof v === "object") {
    return `{${Object.keys(v)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${stableStringify(v[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(v);
}

export function docSha256(json) {
  return createHash("sha256").update(stableStringify(json)).digest("hex");
}

/** The stable id of a Mongo `_id` in its Extended JSON form ({"$oid": …} or a plain value). */
export function mongoIdString(ejsonId) {
  if (ejsonId && typeof ejsonId === "object") {
    if (typeof ejsonId.$oid === "string") return ejsonId.$oid;
    return stableStringify(ejsonId);
  }
  return String(ejsonId);
}

/** The app's own id for a document: `id` when it has one, otherwise the Mongo `_id`. */
export function appIdOf(json, mongoId) {
  return typeof json?.id === "string" && json.id ? json.id : mongoId;
}

/** Extended JSON date ({"$date": "…"} or {"$date": {"$numberLong": …}}) or a string → ISO string. */
export function isoOf(v) {
  if (!v) return null;
  if (typeof v === "string") return Number.isNaN(Date.parse(v)) ? null : v;
  if (typeof v === "object" && "$date" in v) {
    const d = v.$date;
    if (typeof d === "string") return d;
    if (d && typeof d === "object" && "$numberLong" in d) return new Date(Number(d.$numberLong)).toISOString();
    if (typeof d === "number") return new Date(d).toISOString();
  }
  return null;
}
