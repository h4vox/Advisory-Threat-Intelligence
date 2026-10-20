/**
 * Advisory persistence: AdvisoryRecord documents and their SimulationRun children.
 *
 * MongoDB (when MONGODB_URI is set): dedicated collections `aie_advisories` and
 * `aie_simulation_runs`, each keyed by `id`, stored verbatim (advisory types use ISO date strings
 * and plain nested objects, so they round-trip natively). Reads strip Mongo's `_id`.
 *
 * Local fallback (no MONGODB_URI): the same records as JSON documents in two PGLite/Postgres tables,
 * with a few promoted columns for listing and ordering. The store is a thin key/value layer; the
 * server-function layer does read-modify-write patches and number allocation on top of it.
 */
import { getSql, type Sql } from "@/lib/db";
import { getMongoDb, isMongoConfigured } from "./client.server";
import type { AdvisoryRecord, SimulationRun } from "../aie/advisory/types";

export type AdvisoryStorage = "mongodb" | "local";

export interface AdvisoriesStore {
  readonly kind: AdvisoryStorage;
  allAdvisories(): Promise<AdvisoryRecord[]>;
  getAdvisory(id: string): Promise<AdvisoryRecord | null>;
  saveAdvisory(record: AdvisoryRecord): Promise<void>;
  deleteAdvisory(id: string): Promise<boolean>;
  runsFor(advisoryId: string): Promise<SimulationRun[]>;
  getRun(runId: string): Promise<SimulationRun | null>;
  saveRun(run: SimulationRun): Promise<void>;
  deleteRun(runId: string): Promise<boolean>;
}

const ADVISORIES_COLLECTION = "aie_advisories";
const RUNS_COLLECTION = "aie_simulation_runs";
const NO_ID = { projection: { _id: 0 } } as const;

const g = globalThis as typeof globalThis & {
  __aieAdvisoryTables__?: Promise<Sql>;
  __aieAdvisoryIndexes__?: Promise<void>;
};

// ---------------------------------------------------------------------------
// MongoDB
// ---------------------------------------------------------------------------

async function mongoCollections() {
  const db = await getMongoDb();
  const advisories = db.collection<AdvisoryRecord>(ADVISORIES_COLLECTION);
  const runs = db.collection<SimulationRun>(RUNS_COLLECTION);
  g.__aieAdvisoryIndexes__ ??= Promise.all([
    advisories.createIndex({ id: 1 }, { unique: true, name: "advisory_id_unique" }),
    advisories.createIndex({ number: 1 }, { name: "advisory_number" }),
    runs.createIndex({ id: 1 }, { unique: true, name: "run_id_unique" }),
    runs.createIndex({ advisoryId: 1, number: 1 }, { name: "run_advisory_number" }),
  ]).then(
    () => undefined,
    (err) => console.warn("[advisories] index skipped:", err?.message ?? err),
  );
  await g.__aieAdvisoryIndexes__;
  return { advisories, runs };
}

const mongoStore: AdvisoriesStore = {
  kind: "mongodb",
  async allAdvisories() {
    const { advisories } = await mongoCollections();
    return (await advisories.find({}, NO_ID).sort({ updatedAt: -1 }).toArray()) as AdvisoryRecord[];
  },
  async getAdvisory(id) {
    const { advisories } = await mongoCollections();
    return (await advisories.findOne({ id }, NO_ID)) as AdvisoryRecord | null;
  },
  async saveAdvisory(record) {
    const { advisories } = await mongoCollections();
    await advisories.replaceOne({ id: record.id }, { ...record }, { upsert: true });
  },
  async deleteAdvisory(id) {
    const { advisories, runs } = await mongoCollections();
    const res = await advisories.deleteOne({ id });
    await runs.deleteMany({ advisoryId: id });
    return res.deletedCount > 0;
  },
  async runsFor(advisoryId) {
    const { runs } = await mongoCollections();
    return (await runs.find({ advisoryId }, NO_ID).sort({ number: 1 }).toArray()) as SimulationRun[];
  },
  async getRun(runId) {
    const { runs } = await mongoCollections();
    return (await runs.findOne({ id: runId }, NO_ID)) as SimulationRun | null;
  },
  async saveRun(run) {
    const { runs } = await mongoCollections();
    await runs.replaceOne({ id: run.id }, { ...run }, { upsert: true });
  },
  async deleteRun(runId) {
    const { runs } = await mongoCollections();
    const res = await runs.deleteOne({ id: runId });
    return res.deletedCount > 0;
  },
};

// ---------------------------------------------------------------------------
// Local SQL (PGLite in dev, Postgres when DATABASE_URL is set)
// ---------------------------------------------------------------------------

async function localSql(): Promise<Sql> {
  g.__aieAdvisoryTables__ ??= (async () => {
    const sql = await getSql();
    await sql`create table if not exists aie_advisories (
      id text primary key,
      number text not null,
      status text,
      created_at timestamptz,
      updated_at timestamptz,
      doc text not null
    )`;
    await sql`create table if not exists aie_simulation_runs (
      id text primary key,
      advisory_id text not null,
      number integer not null,
      updated_at timestamptz,
      doc text not null
    )`;
    await sql`create index if not exists aie_simulation_runs_advisory on aie_simulation_runs (advisory_id, number)`;
    return sql;
  })().catch((err) => {
    g.__aieAdvisoryTables__ = undefined;
    throw err;
  });
  return g.__aieAdvisoryTables__;
}

function parseJson<T>(raw: string | null | undefined, fallback: T): T {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

const localStore: AdvisoriesStore = {
  kind: "local",
  async allAdvisories() {
    const sql = await localSql();
    const rows = await sql<{ doc: string }>`select doc from aie_advisories order by updated_at desc nulls last`;
    return rows.map((r) => parseJson<AdvisoryRecord | null>(r.doc, null)).filter((x): x is AdvisoryRecord => x !== null);
  },
  async getAdvisory(id) {
    const sql = await localSql();
    const rows = await sql<{ doc: string }>`select doc from aie_advisories where id = ${id}`;
    return rows[0] ? parseJson<AdvisoryRecord | null>(rows[0].doc, null) : null;
  },
  async saveAdvisory(record) {
    const sql = await localSql();
    const doc = JSON.stringify(record);
    await sql`
      insert into aie_advisories (id, number, status, created_at, updated_at, doc)
      values (${record.id}, ${record.number}, ${record.status}, ${record.createdAt}, ${record.updatedAt}, ${doc})
      on conflict (id) do update set number = excluded.number, status = excluded.status, updated_at = excluded.updated_at, doc = excluded.doc
    `;
  },
  async deleteAdvisory(id) {
    const sql = await localSql();
    await sql`delete from aie_simulation_runs where advisory_id = ${id}`;
    const res = await sql<{ id: string }>`delete from aie_advisories where id = ${id} returning id`;
    return res.length > 0;
  },
  async runsFor(advisoryId) {
    const sql = await localSql();
    const rows = await sql<{ doc: string }>`select doc from aie_simulation_runs where advisory_id = ${advisoryId} order by number asc`;
    return rows.map((r) => parseJson<SimulationRun | null>(r.doc, null)).filter((x): x is SimulationRun => x !== null);
  },
  async getRun(runId) {
    const sql = await localSql();
    const rows = await sql<{ doc: string }>`select doc from aie_simulation_runs where id = ${runId}`;
    return rows[0] ? parseJson<SimulationRun | null>(rows[0].doc, null) : null;
  },
  async saveRun(run) {
    const sql = await localSql();
    const doc = JSON.stringify(run);
    await sql`
      insert into aie_simulation_runs (id, advisory_id, number, updated_at, doc)
      values (${run.id}, ${run.advisoryId}, ${run.number}, ${run.completedAt ?? run.startedAt}, ${doc})
      on conflict (id) do update set advisory_id = excluded.advisory_id, number = excluded.number, updated_at = excluded.updated_at, doc = excluded.doc
    `;
  },
  async deleteRun(runId) {
    const sql = await localSql();
    const res = await sql<{ id: string }>`delete from aie_simulation_runs where id = ${runId} returning id`;
    return res.length > 0;
  },
};

export function getAdvisoriesStore(): AdvisoriesStore {
  return isMongoConfigured() ? mongoStore : localStore;
}
