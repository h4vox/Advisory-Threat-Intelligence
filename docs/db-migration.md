# Database migration: MongoDB Atlas → local PostgreSQL

Branch: `db-migration`. Tool: `npm run db:migration -- <command>` (scripts/db-migration/migrate.mjs).

## Why

The Atlas free cluster is full (513 MB of 512 MB). Atlas blocks every **write**, so the crawler,
sign-ins, settings and AI sessions fail. **Reads still work**, so all data can be exported now.

Reasons to move to a local PostgreSQL:

- **No storage cap**: the database lives on your own disk and grows with it.
- **One engine for everything**: structured columns, JSON documents (`jsonb`) and full-text search
  (`tsvector`) all in one database, with transactions.
- **The app already speaks SQL**: it has a PostgreSQL path today (`src/lib/db.ts`, `migrations/`).
- **Speed comes from the schema and indexes, not from the engine name.** On one machine with the app
  next to the database, queries skip the round trip to Atlas.

## The two databases

| Database | Holds | Shared by |
|---|---|---|
| `aie_intel` | the intelligence itself: reports, sources, discovery, ATT&CK / KEV knowledge, crawl history, advisories and simulation playbooks | every account and every instance |
| `aie_app` | this instance and its users: accounts, sign-in sessions, settings, crawler configuration and locks, AI chat sessions, marketplace integrations (they hold API keys) | this instance only |

Where each MongoDB document goes (scripts/db-migration/routing.mjs, unit-tested):

| MongoDB | → PostgreSQL | Why there |
|---|---|---|
| `threat-intel` / `report` | `aie_intel.reports` | the library |
| `source`, `discovered_source`, `discovered_resource` | `aie_intel.sources`, `.discovered_sources`, `.discovered_resources` | where intelligence comes from |
| `graph_edge` | `aie_intel.graph_edges` | citation graph between sources |
| `kev`, `attack_technique`, `emulation_index` | `aie_intel.knowledge_objects` | reference knowledge |
| `crawl_job`, `crawl_job_item`, `ingest_event` | `aie_intel.crawl_jobs`, `.crawl_job_items`, `.ingest_events` | how the shared library was built (audit trail) |
| `collector_fetch_state`, `collector_source_health` | `aie_intel.collector_state` | per-source crawl state |
| `aie_advisories`, `aie_simulation_runs` | `aie_intel.advisories`, `.simulation_runs` | playbooks and emulation (see open questions) |
| `aie_users`, `aie_sessions` | `aie_app.users`, `.auth_sessions` | accounts |
| `app_settings`, `crawl_config`, `crawl_lock`, `maintenance` | `aie_app.app_state` | this instance's configuration |
| `agent_chat_session`, `agent_chat_message` | `aie_app.agent_chat_sessions`, `.agent_chat_messages` | AI Analyst conversations |
| `marketplace_integration` | `aie_app.integrations` | contains API keys; the catalog itself is in the code |
| anything else | `aie_app.unclassified_documents` | **never dropped**; kept until classified |

Phase 1 stores each document whole, as `jsonb`, so nothing is lost and nothing is reinterpreted. Every row keeps:

- its source collection and MongoDB `_id`;
- a SHA-256 checksum of the document;
- generated columns for the fields the app filters on, such as `published_at`, `ingested_at`, `status` and `canonical_url`.

## Run the migration (on the server that can reach Atlas)

Prerequisites: Docker, Node 22 and this branch:

```bash
git fetch origin db-migration && git checkout db-migration && npm install
```

1. **Start PostgreSQL** (listens on 127.0.0.1 only):

   ```bash
   export POSTGRES_PASSWORD='<long random superuser password>'
   docker compose -f docker-compose.db.yml up -d
   ```

2. **Set the connection for the tool**:

   ```bash
   export PG_ADMIN_URL="postgres://postgres:${POSTGRES_PASSWORD}@127.0.0.1:5432/postgres"
   export AIE_DB_PASSWORD='<long random password for the app role "aie", 16+ chars>'
   # Source: defaults to the app's Atlas cluster and database threat-intel-DB.
   # export MIGRATION_MONGO_URI='mongodb+srv://…'   MIGRATION_MONGO_DB='threat-intel-DB'
   ```

3. **Look before copying** (reads only):

   ```bash
   npm run db:migration -- list   # databases and collections on Atlas, with counts
   npm run db:migration -- plan   # where every document will go
   ```

4. **Run everything**:

   ```bash
   npm run db:migration -- all --all-databases
   ```

   This runs four steps:

   - **backup:** every Atlas database to `db-backups/<time>/<database>/`, as gzipped canonical
     Extended JSON. The backup is lossless, with a manifest of counts, checksums and index definitions.
   - **setup:** creates the role `aie` and the databases `aie_intel` and `aie_app`, and their tables.
   - **migrate:** copies every document of `threat-intel-DB` from the backup into PostgreSQL.
   - **verify:** re-reads every document and checks it against PostgreSQL. It checks counts per
     table, and a checksum recomputed from each stored row, so any changed, missing or extra row
     fails the run.

   It ends with `VERIFIED: every document is in PostgreSQL, unchanged.` and writes
   `verify-report.json` into the backup folder.

5. **Keep the backup safe.** Copy `db-backups/<time>/` off the machine before you delete anything in
   Atlas. It holds account data, so treat it as sensitive. It is git-ignored.

Every step is safe to repeat. Writes are upserts keyed by collection and `_id`, so an interrupted
run resumes where it stopped. The source is only ever read.

One change is made on the way: PostgreSQL cannot store the NUL character (`\u0000`), which scraped
text sometimes contains. Those characters are removed and counted per row (`nul_removed`); the backup
keeps the originals.

## Unblock the running app today (optional, no code change)

Until the app itself reads from PostgreSQL (phase 2), you can run it on a local MongoDB loaded from
the same backup. The crawler and sign-in work again immediately.

```bash
export AIE_MONGO_PASSWORD='<long random password>'
docker compose -f docker-compose.db.yml --profile interim-mongo up -d
npm run db:migration -- restore-mongo \
  --from-backup db-backups/<time>/threat-intel-DB \
  --to "mongodb://aie:${AIE_MONGO_PASSWORD}@127.0.0.1:27017/?authSource=admin"
# then start the app with
MONGODB_URI="mongodb://aie:${AIE_MONGO_PASSWORD}@127.0.0.1:27017/?authSource=admin"
```

Index definitions are restored too. Rollback is setting `MONGODB_URI` back.

## Exposing the database to other machines

Prefer not to expose it at all. In order of preference:

1. **The app runs on the same host as the database.** Nothing needs to be public; keep the default
   127.0.0.1 binding.
2. **A private network**: WireGuard / Tailscale, or an SSH tunnel
   (`ssh -L 5432:127.0.0.1:5432 server`). The database port stays closed to the internet.
3. **A public port**, only with all of the following:
   - **TLS required.** Mount a certificate and key and start PostgreSQL with
     `-c ssl=on -c ssl_cert_file=… -c ssl_key_file=…`.
   - **TLS-only access rules.** `pg_hba.conf` allows `hostssl … scram-sha-256` for the `aie` role
     and the app's addresses only, and no `host` (non-TLS) lines.
   - **A firewall allow-list.** Only the app servers' IPs may connect.
   - **No remote superuser.** `postgres` connects from localhost only; the app uses the `aie` role.
   - **A non-default port** set through `AIE_PG_PORT`, plus `log_connections=on` (already set), with
     the logs monitored.

   Then set `AIE_PG_BIND=0.0.0.0` and clients use `sslmode=verify-full`.

## After the migration: credentials

When the app runs on PostgreSQL (or on the interim MongoDB) and the backup is safe:

- **Atlas user:** change the `threatintel_app` password in Atlas, or delete the user.
- **This branch:** remove the hard-coded Atlas URI from `src/lib/mongodb/client.server.ts`,
  `.env.example` and `scripts/db-migration/migrate.mjs`.
- **Database passwords:** keep the PostgreSQL passwords in the server's environment only, never in git.

## Phase 2: the app reads and writes PostgreSQL (next)

The app's storage code (`src/lib/mongodb/*`, about 6,000 lines) is ported area by area behind the
same function names. Each area is tested with the existing QA scripts before the next one starts.

1. **Data-access layer:** `src/lib/store/` with two pools (`AIE_INTEL_DATABASE_URL`,
   `AIE_APP_DATABASE_URL`) and the phase 1 tables.
2. **Port in order of risk:**
   1. accounts and sessions
   2. settings and crawl config
   3. AI chat sessions
   4. Library reads (list, report, facets)
   5. search, moving from MongoDB `$text` to PostgreSQL full-text (`tsvector` + GIN)
   6. Library writes: the crawler's persist, library gate, research labels, publication dates, AI review
   7. collector state and crawl jobs
   8. advisories and simulation runs
   9. dashboard aggregates
3. **Normalise the hot fields** into real columns, with constraints such as a unique `(id)` per table.
4. **Cutover:**
   1. Pause the crawler.
   2. Run a final `migrate` + `verify` from the newest backup.
   3. Switch the environment and watch the logs.
   4. Rollback is switching `MONGODB_URI` back.
5. **Remove the MongoDB code and the hard-coded URI**, then rotate credentials.

## Open questions for the categorisation (phase 3)

- **Crawl history:** it is in `aie_intel`, because it explains how the shared library was built.
  If each instance runs its own crawler, move `crawl_jobs` and `crawl_job_items` to `aie_app`.
- **Marketplace:** split it into a shared catalog (`aie_intel`) and per-instance installed
  integrations with their keys (`aie_app`, encrypted).
- **Advisories and simulation runs:** advisories and playbooks stay shared; runs against a specific
  environment may belong to `aie_app`.
- **Dashboard:** computed from `aie_intel` with materialised views refreshed after each crawl.
- **Retention:** stored originals (`originalContent`, `rawHtml`, `pdfBase64`) are most of the size.
  Move them to a `report_originals` table or object storage, so the reports table stays small.
