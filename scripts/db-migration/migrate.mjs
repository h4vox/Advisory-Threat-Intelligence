#!/usr/bin/env node
/**
 * AIE database migration: MongoDB (Atlas) → local PostgreSQL, two databases.
 *
 *   node scripts/db-migration/migrate.mjs <command> [options]
 *
 * Commands (run them in this order, or `all`):
 *   list           databases and collections on the MongoDB source, with counts and sizes
 *   plan           where every document would go (database / table counts); writes nothing
 *   backup         full copy of the source to ./db-backups/<run>/ as gzipped Extended JSON
 *                  (lossless, canonical), with a manifest of counts and checksums
 *   setup          creates the role, the databases aie_intel and aie_app, and their tables
 *   migrate        copies every document into PostgreSQL (from --from-backup, or the source)
 *   verify         checks every document arrived unchanged: counts and a SHA-256 per document
 *   all            backup → setup → migrate (from that backup) → verify
 *   restore-mongo  loads a backup into another MongoDB (for example a local one), unchanged
 *
 * Options:
 *   --from-backup <dir>   read a backup instead of the live source (migrate, verify, restore-mongo)
 *   --out <dir>           where backup writes (default ./db-backups)
 *   --all-databases       backup: every database on the source, each in its own folder (a full
 *                         safety copy); migrate and verify still use MIGRATION_MONGO_DB
 *   --to <mongodb-uri>    restore-mongo target (must differ from the source)
 *
 * Environment (see docs/db-migration.md):
 *   MIGRATION_MONGO_URI        source (required; falls back to the app's MONGODB_URI)
 *   MIGRATION_MONGO_DB         source database (default threat-intel-DB)
 *   MIGRATION_MAIN_COLLECTION  the app's main collection (default threat-intel)
 *   PG_ADMIN_URL               a PostgreSQL superuser connection, used by setup only
 *   AIE_DB_USER / AIE_DB_PASSWORD   the app's database role (created by setup)
 *   AIE_INTEL_DATABASE_URL / AIE_APP_DATABASE_URL   targets; derived from PG_ADMIN_URL's host
 *                              and the role above when not set
 *
 * The source is only ever read. Every write to PostgreSQL is an upsert keyed by the source
 * collection and _id, so any command can be re-run safely and an interrupted run resumes.
 */
import { createReadStream, createWriteStream, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createGunzip, createGzip } from "node:zlib";
import { createInterface } from "node:readline";
import { once } from "node:events";
import { MongoClient, BSON } from "mongodb";
import pg from "pg";
import {
  APP_DB,
  INTEL_DB,
  MAIN_COLLECTION,
  TABLES,
  appIdOf,
  docSha256,
  mongoIdString,
  routeDocument,
  stripNul,
} from "./routing.mjs";

const { EJSON } = BSON;
const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..", "..");


const env = (k, d) => (process.env[k] ?? "").trim() || d;
// The source comes only from the environment: MIGRATION_MONGO_URI, else the app's MONGODB_URI.
const SOURCE_URI = env("MIGRATION_MONGO_URI", env("MONGODB_URI", ""));
const SOURCE_DB = env("MIGRATION_MONGO_DB", "threat-intel-DB");
const MAIN = env("MIGRATION_MAIN_COLLECTION", MAIN_COLLECTION);

const BATCH_ROWS = 200;
const BATCH_BYTES = 8 * 1024 * 1024;

// ── helpers ─────────────────────────────────────────────────────────────────

/** A connection string with its password hidden, for logs and reports. */
export function redact(uri) {
  return String(uri ?? "").replace(/(\/\/[^:/@]+:)[^@]*@/, "$1***@");
}

function args() {
  const [command, ...rest] = process.argv.slice(2);
  const opts = {};
  for (let i = 0; i < rest.length; i++) {
    if (rest[i].startsWith("--")) {
      const key = rest[i].slice(2);
      const next = rest[i + 1];
      if (next && !next.startsWith("--")) {
        opts[key] = next;
        i++;
      } else opts[key] = true;
    }
  }
  return { command, opts };
}

const log = (...a) => console.log(`[db-migration]`, ...a);
const fmtBytes = (n) => (n > 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.round(n / 1024)} KB`);

function pgTargets() {
  const admin = env("PG_ADMIN_URL", "");
  const user = env("AIE_DB_USER", "aie");
  const password = env("AIE_DB_PASSWORD", "");
  const derive = (db) => {
    if (!admin) return "";
    const u = new URL(admin);
    u.username = user;
    u.password = password;
    u.pathname = `/${db}`;
    return u.toString();
  };
  return {
    admin,
    user,
    password,
    [INTEL_DB]: env("AIE_INTEL_DATABASE_URL", derive(INTEL_DB)),
    [APP_DB]: env("AIE_APP_DATABASE_URL", derive(APP_DB)),
  };
}

async function withMongo(uri, fn) {
  const client = new MongoClient(uri, { serverSelectionTimeoutMS: 30_000, readPreference: "secondaryPreferred", retryReads: true });
  await client.connect();
  try {
    return await fn(client);
  } finally {
    await client.close();
  }
}

/** Collections of the source database, the main collection first. */
async function sourceCollections(db) {
  const list = (await db.listCollections({}, { nameOnly: true }).toArray()).map((c) => c.name).filter((n) => !n.startsWith("system."));
  return list.sort((a, b) => (a === MAIN ? -1 : b === MAIN ? 1 : a.localeCompare(b)));
}

/** Every document of the source as {collection, doc} (BSON types), from the live source or a backup. */
async function* sourceDocuments(fromBackup) {
  if (fromBackup) {
    const manifest = JSON.parse(readFileSync(join(fromBackup, "manifest.json"), "utf8"));
    for (const c of manifest.collections) {
      const rl = createInterface({ input: createReadStream(join(fromBackup, c.file)).pipe(createGunzip()), crlfDelay: Infinity });
      for await (const line of rl) {
        if (line) yield { collection: c.name, doc: EJSON.parse(line, { relaxed: false }) };
      }
    }
    return;
  }
  const client = new MongoClient(SOURCE_URI, { serverSelectionTimeoutMS: 30_000, retryReads: true });
  await client.connect();
  try {
    const db = client.db(SOURCE_DB);
    for (const name of await sourceCollections(db)) {
      for await (const doc of db.collection(name).find({}, { batchSize: 200 })) yield { collection: name, doc };
    }
  } finally {
    await client.close();
  }
}

/**
 * Relaxed Extended JSON turns 64-bit integers into JSON numbers, which lose digits above 2^53.
 * Those few keep their exact canonical form ({"$numberLong": "…"}); everything else stays relaxed.
 */
function keepExactLongs(v) {
  if (v && typeof v === "object") {
    if (v._bsontype === "Long") {
      const s = v.toString();
      return Number.isSafeInteger(Number(s)) ? v : { $numberLong: s };
    }
    if (v._bsontype) return v;
    if (Array.isArray(v)) return v.map(keepExactLongs);
    if (v instanceof Date) return v;
    const o = {};
    for (const [k, x] of Object.entries(v)) o[k] = keepExactLongs(x);
    return o;
  }
  return v;
}

/** What a PostgreSQL row holds for one source document. */
export function toRow(collection, doc, main = MAIN) {
  const relaxed = EJSON.serialize(keepExactLongs(doc), { relaxed: true });
  const { value: json, removed } = stripNul(relaxed);
  const mongoId = mongoIdString(json._id);
  const route = routeDocument(collection, json, main);
  return {
    db: route.db,
    table: route.table,
    sourceCollection: collection,
    mongoId,
    id: appIdOf(json, mongoId),
    docType: typeof json.docType === "string" ? json.docType : null,
    json,
    sha: docSha256(json),
    nulRemoved: removed,
  };
}

// ── list / plan ─────────────────────────────────────────────────────────────

async function cmdList() {
  log(`source: ${redact(SOURCE_URI)}`);
  await withMongo(SOURCE_URI, async (client) => {
    const dbs = await client.db().admin().listDatabases().catch(() => ({ databases: [{ name: SOURCE_DB }] }));
    for (const d of dbs.databases) {
      if (["admin", "local", "config"].includes(d.name)) continue;
      console.log(`\n${d.name}${d.sizeOnDisk ? ` (${fmtBytes(d.sizeOnDisk)} on disk)` : ""}${d.name === SOURCE_DB ? "  ← migrated" : ""}`);
      const db = client.db(d.name);
      for (const name of await sourceCollections(db)) {
        const n = await db.collection(name).estimatedDocumentCount();
        console.log(`  ${name.padEnd(32)} ${String(n).padStart(8)} documents`);
      }
    }
  });
}

async function cmdPlan(opts) {
  const counts = new Map();
  let total = 0;
  for await (const { collection, doc } of sourceDocuments(opts["from-backup"])) {
    const r = routeDocument(collection, EJSON.serialize(doc, { relaxed: true }), MAIN);
    const key = `${r.db}.${r.table}`;
    const byType = counts.get(key) ?? new Map();
    const t = `${collection}${doc.docType ? `/${doc.docType}` : ""}`;
    byType.set(t, (byType.get(t) ?? 0) + 1);
    counts.set(key, byType);
    total++;
  }
  console.log(`\nPlan for ${total} documents:`);
  for (const [key, byType] of [...counts].sort()) {
    const n = [...byType.values()].reduce((a, b) => a + b, 0);
    console.log(`  ${key.padEnd(40)} ${String(n).padStart(8)}   ${[...byType].map(([t, c]) => `${t}: ${c}`).join(", ")}`);
  }
  if (counts.has(`${APP_DB}.unclassified_documents`)) console.log("\n  Note: unclassified documents are kept in aie_app.unclassified_documents until they are classified.");
  return { total, counts };
}

// ── backup ──────────────────────────────────────────────────────────────────

async function backupDatabase(client, dbName, dir) {
  mkdirSync(dir, { recursive: true });
  const manifest = { source: redact(SOURCE_URI), database: dbName, mainCollection: MAIN, startedAt: new Date().toISOString(), collections: [] };
  const db = client.db(dbName);
  for (const name of await sourceCollections(db)) {
    const file = `${name.replace(/[^A-Za-z0-9_.-]/g, "_")}.ndjson.gz`;
    const gzip = createGzip({ level: 6 });
    const out = createWriteStream(join(dir, file));
    gzip.pipe(out);
    const hash = createHash("sha256");
    const docTypes = {};
    let count = 0;
    for await (const doc of db.collection(name).find({}, { batchSize: 200 })) {
      const line = EJSON.stringify(doc, { relaxed: false }) + "\n";
      hash.update(line);
      if (!gzip.write(line)) await once(gzip, "drain");
      const t = typeof doc.docType === "string" ? doc.docType : "(none)";
      docTypes[t] = (docTypes[t] ?? 0) + 1;
      count++;
    }
    gzip.end();
    await once(out, "finish");
    // Index definitions travel with the data, so a restored MongoDB has the same indexes.
    const indexes = (await db.collection(name).indexes().catch(() => [])).filter((i) => i.name !== "_id_");
    manifest.collections.push({ name, file, count, docTypes, sha256: hash.digest("hex"), indexes });
    log(`  ${dbName}.${name}: ${count} documents`);
  }
  manifest.finishedAt = new Date().toISOString();
  writeFileSync(join(dir, "manifest.json"), JSON.stringify(manifest, null, 2));
  return manifest;
}

/** Backs up MIGRATION_MONGO_DB (or every database) and returns the folder of MIGRATION_MONGO_DB's copy. */
async function cmdBackup(opts) {
  const run = new Date().toISOString().replace(/[:.]/g, "-");
  const base = resolve(opts.out || join(ROOT, "db-backups"), run);
  log(`backup of ${redact(SOURCE_URI)} → ${base}`);
  let mainDir = base;
  await withMongo(SOURCE_URI, async (client) => {
    if (opts["all-databases"]) {
      // A database user without the listDatabases privilege still backs up the app's database.
      const listed = await client
        .db()
        .admin()
        .listDatabases({ nameOnly: true, authorizedDatabases: true })
        .catch((err) => {
          log(`  cannot list databases (${String(err?.message ?? err).slice(0, 120)}); backing up ${SOURCE_DB} only`);
          return { databases: [{ name: SOURCE_DB }] };
        });
      const names = listed.databases.map((d) => d.name).filter((n) => !["admin", "local", "config"].includes(n));
      for (const name of names) await backupDatabase(client, name, join(base, name));
      mainDir = join(base, SOURCE_DB);
      if (!names.includes(SOURCE_DB)) log(`  note: ${SOURCE_DB} is not on the source`);
    } else {
      await backupDatabase(client, SOURCE_DB, base);
    }
  });
  const manifest = JSON.parse(readFileSync(join(mainDir, "manifest.json"), "utf8"));
  const total = manifest.collections.reduce((n, c) => n + c.count, 0);
  log(`backup complete: ${SOURCE_DB} has ${total} documents in ${manifest.collections.length} collections → ${mainDir}`);
  return mainDir;
}

/** Re-reads a backup and checks every file against its manifest checksum and count. */
async function checkBackup(dir) {
  const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
  for (const c of manifest.collections) {
    const hash = createHash("sha256");
    let count = 0;
    const rl = createInterface({ input: createReadStream(join(dir, c.file)).pipe(createGunzip()), crlfDelay: Infinity });
    for await (const line of rl) {
      if (!line) continue;
      hash.update(line + "\n");
      count++;
    }
    if (count !== c.count || hash.digest("hex") !== c.sha256) throw new Error(`Backup file ${c.file} does not match its manifest (${count} of ${c.count} documents).`);
  }
  log(`backup ${dir} checked: every file matches its manifest`);
  return manifest;
}

// ── setup ───────────────────────────────────────────────────────────────────

const ident = (s) => `"${String(s).replace(/"/g, '""')}"`;
const literal = (s) => `'${String(s).replace(/'/g, "''")}'`;

async function cmdSetup() {
  const t = pgTargets();
  if (!t.admin) throw new Error("PG_ADMIN_URL is not set: a PostgreSQL superuser connection is needed to create the databases.");
  if (!t.password || t.password.length < 16) throw new Error("AIE_DB_PASSWORD must be set to a password of at least 16 characters for the app's database role.");
  const admin = new pg.Client({ connectionString: t.admin });
  await admin.connect();
  try {
    const role = await admin.query("SELECT 1 FROM pg_roles WHERE rolname = $1", [t.user]);
    if (role.rowCount === 0) {
      await admin.query(`CREATE ROLE ${ident(t.user)} LOGIN PASSWORD ${literal(t.password)}`);
      log(`created role ${t.user}`);
    } else {
      await admin.query(`ALTER ROLE ${ident(t.user)} LOGIN PASSWORD ${literal(t.password)}`);
      log(`role ${t.user} exists; password updated`);
    }
    for (const db of [INTEL_DB, APP_DB]) {
      const exists = await admin.query("SELECT 1 FROM pg_database WHERE datname = $1", [db]);
      if (exists.rowCount === 0) {
        await admin.query(`CREATE DATABASE ${ident(db)} OWNER ${ident(t.user)} ENCODING 'UTF8' TEMPLATE template0`);
        log(`created database ${db}`);
      } else log(`database ${db} exists`);
      await admin.query(`REVOKE ALL ON DATABASE ${ident(db)} FROM PUBLIC`);
      await admin.query(`GRANT ALL ON DATABASE ${ident(db)} TO ${ident(t.user)}`);
    }
  } finally {
    await admin.end();
  }
  for (const db of [INTEL_DB, APP_DB]) {
    const c = new pg.Client({ connectionString: t[db] });
    await c.connect();
    try {
      await c.query(readFileSync(join(ROOT, "db", "postgres", "schema", `${db}.sql`), "utf8"));
      log(`schema applied to ${db} (${TABLES[db].length} tables)`);
    } finally {
      await c.end();
    }
  }
}

// ── migrate ─────────────────────────────────────────────────────────────────

async function pgClients() {
  const t = pgTargets();
  const out = {};
  for (const db of [INTEL_DB, APP_DB]) {
    if (!t[db]) throw new Error(`No connection for ${db}: set PG_ADMIN_URL and AIE_DB_PASSWORD, or AIE_${db === INTEL_DB ? "INTEL" : "APP"}_DATABASE_URL.`);
    out[db] = new pg.Client({ connectionString: t[db] });
    await out[db].connect();
  }
  return out;
}

async function flush(client, table, rows) {
  if (!rows.length) return;
  const values = [];
  const params = [];
  rows.forEach((r, i) => {
    const b = i * 7;
    values.push(`($${b + 1}, $${b + 2}, $${b + 3}, $${b + 4}, $${b + 5}::jsonb, $${b + 6}, $${b + 7})`);
    params.push(r.sourceCollection, r.mongoId, r.id, r.docType, JSON.stringify(r.json), r.sha, r.nulRemoved);
  });
  await client.query(
    `INSERT INTO ${ident(table)} (source_collection, mongo_id, id, doc_type, doc, doc_sha256, nul_removed)
     VALUES ${values.join(", ")}
     ON CONFLICT (source_collection, mongo_id) DO UPDATE SET
       id = EXCLUDED.id, doc_type = EXCLUDED.doc_type, doc = EXCLUDED.doc,
       doc_sha256 = EXCLUDED.doc_sha256, nul_removed = EXCLUDED.nul_removed, migrated_at = now()`,
    params,
  );
}

async function recordRun(clients, runId, phase, source, status, summary) {
  for (const c of Object.values(clients)) {
    await c.query(
      `INSERT INTO migration_runs (run_id, phase, source, status, summary, finished_at)
       VALUES ($1, $2, $3, $4, $5::jsonb, CASE WHEN $4 = 'running' THEN NULL ELSE now() END)
       ON CONFLICT (run_id) DO UPDATE SET status = EXCLUDED.status, summary = EXCLUDED.summary, finished_at = EXCLUDED.finished_at`,
      [runId, phase, source, status, JSON.stringify(summary)],
    );
  }
}

async function cmdMigrate(opts) {
  const from = opts["from-backup"];
  const source = from ? `backup ${from}` : `${redact(SOURCE_URI)} / ${SOURCE_DB}`;
  if (from) await checkBackup(from);
  const clients = await pgClients();
  const runId = `migrate-${randomUUID()}`;
  const counts = {};
  let total = 0;
  let nulDocs = 0;
  try {
    await recordRun(clients, runId, "migrate", source, "running", {});
    const pending = new Map(); // "db.table" → {rows, bytes}
    const push = async (row) => {
      const key = `${row.db}.${row.table}`;
      const p = pending.get(key) ?? { db: row.db, table: row.table, rows: [], bytes: 0 };
      p.rows.push(row);
      p.bytes += JSON.stringify(row.json).length;
      pending.set(key, p);
      if (p.rows.length >= BATCH_ROWS || p.bytes >= BATCH_BYTES) {
        await flush(clients[p.db], p.table, p.rows);
        pending.delete(key);
      }
    };
    log(`migrating from ${source}`);
    for await (const { collection, doc } of sourceDocuments(from)) {
      const row = toRow(collection, doc);
      await push(row);
      const key = `${row.db}.${row.table}`;
      counts[key] = (counts[key] ?? 0) + 1;
      if (row.nulRemoved) nulDocs++;
      if (++total % 1000 === 0) log(`  ${total} documents…`);
    }
    for (const p of pending.values()) await flush(clients[p.db], p.table, p.rows);
    const summary = { total, counts, nulDocs };
    await recordRun(clients, runId, "migrate", source, "completed", summary);
    log(`migrated ${total} documents:`);
    for (const [k, n] of Object.entries(counts).sort()) log(`  ${k.padEnd(40)} ${n}`);
    if (nulDocs) log(`  ${nulDocs} document(s) had NUL characters removed (PostgreSQL cannot store them); the backup keeps the originals.`);
    return summary;
  } catch (err) {
    await recordRun(clients, runId, "migrate", source, "failed", { total, counts, error: String(err?.message ?? err) }).catch(() => {});
    throw err;
  } finally {
    for (const c of Object.values(clients)) await c.end();
  }
}

// ── verify ──────────────────────────────────────────────────────────────────

async function cmdVerify(opts) {
  const from = opts["from-backup"];
  const source = from ? `backup ${from}` : `${redact(SOURCE_URI)} / ${SOURCE_DB}`;
  const clients = await pgClients();
  const problems = [];
  const expected = {};
  let checked = 0;
  try {
    // Every source document must be in its table with the same checksum.
    const batch = new Map();
    const check = async (key) => {
      const b = batch.get(key);
      if (!b?.rows.length) return;
      const res = await clients[b.db].query(
        `SELECT source_collection, mongo_id, doc FROM ${ident(b.table)} WHERE (source_collection, mongo_id) IN (SELECT * FROM unnest($1::text[], $2::text[]))`,
        [b.rows.map((r) => r.sourceCollection), b.rows.map((r) => r.mongoId)],
      );
      // The checksum is recomputed from the stored document itself, so any change to it is caught.
      const found = new Map(res.rows.map((r) => [`${r.source_collection}\u0001${r.mongo_id}`, docSha256(r.doc)]));
      for (const r of b.rows) {
        const sha = found.get(`${r.sourceCollection}\u0001${r.mongoId}`);
        if (!sha) problems.push(`missing: ${key} ${r.sourceCollection}/${r.mongoId}`);
        else if (sha !== r.sha) problems.push(`changed: ${key} ${r.sourceCollection}/${r.mongoId}`);
      }
      b.rows = [];
    };
    for await (const { collection, doc } of sourceDocuments(from)) {
      const row = toRow(collection, doc);
      const key = `${row.db}.${row.table}`;
      expected[key] = (expected[key] ?? 0) + 1;
      const b = batch.get(key) ?? { db: row.db, table: row.table, rows: [] };
      b.rows.push(row);
      batch.set(key, b);
      if (b.rows.length >= 100) await check(key);
      checked++;
    }
    for (const key of batch.keys()) await check(key);

    // No table may hold more rows than the source has (left over from an older source, say).
    const tables = {};
    for (const db of [INTEL_DB, APP_DB]) {
      for (const table of TABLES[db]) {
        const n = Number((await clients[db].query(`SELECT count(*)::int AS n FROM ${ident(table)}`)).rows[0].n);
        const key = `${db}.${table}`;
        tables[key] = { postgres: n, source: expected[key] ?? 0 };
        if (n !== (expected[key] ?? 0)) problems.push(`count: ${key} has ${n} rows, the source has ${expected[key] ?? 0}`);
      }
    }
    const ok = problems.length === 0;
    const summary = { ok, checked, tables, problems: problems.slice(0, 200), problemCount: problems.length };
    await recordRun(clients, `verify-${randomUUID()}`, "verify", source, ok ? "completed" : "failed", summary);
    const reportDir = from || join(ROOT, "db-backups");
    mkdirSync(reportDir, { recursive: true });
    writeFileSync(join(reportDir, "verify-report.json"), JSON.stringify({ source, at: new Date().toISOString(), ...summary }, null, 2));
    log(`verified ${checked} documents against PostgreSQL:`);
    for (const [k, v] of Object.entries(tables)) log(`  ${k.padEnd(40)} postgres ${String(v.postgres).padStart(7)}   source ${String(v.source).padStart(7)}${v.postgres === v.source ? "" : "   ✗"}`);
    if (ok) log("VERIFIED: every document is in PostgreSQL, unchanged.");
    else {
      log(`NOT VERIFIED: ${problems.length} problem(s), first ones:`);
      for (const p of problems.slice(0, 20)) log(`  ${p}`);
    }
    return summary;
  } finally {
    for (const c of Object.values(clients)) await c.end();
  }
}

// ── restore-mongo ───────────────────────────────────────────────────────────

async function cmdRestoreMongo(opts) {
  const from = opts["from-backup"];
  const to = opts.to;
  if (!from || !to) throw new Error("restore-mongo needs --from-backup <dir> and --to <mongodb-uri>.");
  if (to.trim() === SOURCE_URI.trim()) throw new Error("The restore target is the source cluster; choose another MongoDB.");
  const manifest = await checkBackup(from);
  const targetDb = opts.db || manifest.database;
  await withMongo(to, async (client) => {
    const db = client.db(targetDb);
    for (const c of manifest.collections) {
      const col = db.collection(c.name);
      let ops = [];
      let n = 0;
      const rl = createInterface({ input: createReadStream(join(from, c.file)).pipe(createGunzip()), crlfDelay: Infinity });
      for await (const line of rl) {
        if (!line) continue;
        const doc = EJSON.parse(line, { relaxed: false });
        ops.push({ replaceOne: { filter: { _id: doc._id }, replacement: doc, upsert: true } });
        if (ops.length >= 500) {
          await col.bulkWrite(ops, { ordered: false });
          n += ops.length;
          ops = [];
        }
      }
      if (ops.length) {
        await col.bulkWrite(ops, { ordered: false });
        n += ops.length;
      }
      const count = await col.countDocuments();
      log(`  ${c.name}: ${n} restored (${count} in target, ${c.count} in backup)${count === c.count ? "" : "  ✗"}`);
      for (const ix of c.indexes ?? []) {
        const { key, v, ns, ...options } = ix;
        await col.createIndex(key, options).catch((err) => log(`    index ${ix.name} not created: ${String(err?.message ?? err).slice(0, 160)}`));
      }
      if (c.indexes?.length) log(`    ${c.indexes.length} index(es) restored`);
    }
  });
  log(`restored into ${redact(to)} / ${targetDb}. The app's indexes are created on its first start.`);
}

// ── main ────────────────────────────────────────────────────────────────────

const COMMANDS = {
  list: cmdList,
  plan: cmdPlan,
  backup: cmdBackup,
  setup: cmdSetup,
  migrate: cmdMigrate,
  verify: cmdVerify,
  "restore-mongo": cmdRestoreMongo,
  async all(opts) {
    const dir = await cmdBackup(opts);
    await checkBackup(dir);
    await cmdSetup();
    await cmdMigrate({ "from-backup": dir });
    const v = await cmdVerify({ "from-backup": dir });
    if (!v.ok) throw new Error("Verification failed; see verify-report.json in the backup folder.");
    log(`ALL DONE. Backup: ${dir}`);
  },
};

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const { command, opts } = args();
  const fn = COMMANDS[command];
  const needsSource = ["list", "backup", "all"].includes(command) || (["plan", "migrate", "verify"].includes(command) && !opts["from-backup"]);
  if (fn && needsSource && !SOURCE_URI) {
    console.error("[db-migration] FAILED: set MIGRATION_MONGO_URI (or MONGODB_URI) to the MongoDB to read from.");
    process.exit(1);
  }
  if (!fn) {
    console.log(readFileSync(fileURLToPath(import.meta.url), "utf8").split("*/")[0].replace(/^#!.*\n\/\*\*?/, "").replace(/^ \* ?/gm, ""));
    process.exit(command ? 1 : 0);
  }
  fn(opts).then(
    () => process.exit(0),
    (err) => {
      console.error(`[db-migration] FAILED: ${err?.message ?? err}`);
      process.exit(1);
    },
  );
}

