import { test } from "node:test";
import assert from "node:assert/strict";
import {
  CRAWL_LOCK_FRESH_MS,
  CRAWL_LOCK_ID,
  CRAWL_LOCK_LEASE_MS,
  acquireCrawlLock,
  describeHeldLock,
  releaseCrawlLock,
  renewCrawlLock,
  staleLockReason,
  type CrawlLockCollection,
  type CrawlLockDoc,
  type HolderJobStatus,
} from "./crawl-lock.ts";

/**
 * In-memory stand-in for the lock collection, following MongoDB semantics for the filters the lock uses:
 * equality (null also matches a missing field), $or, $lte, $exists, and an upsert that fails with
 * E11000 when a document with that _id exists but the filter did not match it. Every call yields to the
 * event loop first, so concurrent callers interleave the way they do against a real server.
 */
function memoryCollection(): CrawlLockCollection & { docs: Map<string, CrawlLockDoc> } {
  const docs = new Map<string, CrawlLockDoc>();
  const tick = () => new Promise((r) => setImmediate(r));
  const matchValue = (actual: unknown, expected: unknown): boolean => {
    if (expected && typeof expected === "object" && !(expected instanceof Date)) {
      const ops = expected as Record<string, unknown>;
      if ("$lte" in ops) return actual instanceof Date && actual.getTime() <= (ops.$lte as Date).getTime();
      if ("$exists" in ops) return (actual !== undefined) === ops.$exists;
      throw new Error(`unsupported operator ${Object.keys(ops)}`);
    }
    if (expected === null) return actual === null || actual === undefined;
    if (expected instanceof Date) return actual instanceof Date && actual.getTime() === expected.getTime();
    return actual === expected;
  };
  const matches = (doc: CrawlLockDoc, filter: Record<string, unknown>): boolean =>
    Object.entries(filter).every(([key, expected]) =>
      key === "$or"
        ? (expected as Record<string, unknown>[]).some((f) => matches(doc, f))
        : matchValue((doc as Record<string, unknown>)[key], expected),
    );
  const find = (filter: Record<string, unknown>) => [...docs.values()].find((d) => matches(d, filter)) ?? null;
  return {
    docs,
    async findOneAndUpdate(filter, update, options) {
      await tick();
      const hit = find(filter);
      if (hit) {
        Object.assign(hit, update.$set);
        return { ...hit };
      }
      if (!options.upsert) return null;
      const id = filter._id as string;
      if (docs.has(id)) throw Object.assign(new Error("E11000 duplicate key error"), { code: 11000 });
      const created = { _id: id, ...update.$set } as CrawlLockDoc;
      docs.set(id, created);
      return { ...created };
    },
    async updateOne(filter, update) {
      await tick();
      const hit = find(filter);
      if (hit) Object.assign(hit, update.$set);
      return { matchedCount: hit ? 1 : 0 };
    },
    async findOne(filter) {
      await tick();
      const hit = find(filter);
      return hit ? { ...hit } : null;
    },
  };
}

const T0 = 1_800_000_000_000;
const statusOf = (map: Record<string, HolderJobStatus>) => async (id: string) => map[id] ?? "missing";

function acquire(col: CrawlLockCollection, jobId: string, owner: string, now: number, extra: {
  active?: string[];
  status?: Record<string, HolderJobStatus>;
} = {}) {
  return acquireCrawlLock(col, {
    jobId,
    owner,
    now,
    isLocalActive: (id) => (extra.active ?? []).includes(id),
    holderStatus: statusOf(extra.status ?? {}),
  });
}

test("free lock: first caller takes it, a live holder refuses the next one with its remaining lease", async () => {
  const col = memoryCollection();
  assert.deepEqual(await acquire(col, "job_a", "p1", T0), { ok: true });
  const doc = col.docs.get(CRAWL_LOCK_ID)!;
  assert.equal(doc.jobId, "job_a");
  assert.equal(doc.expiresAt.getTime(), T0 + CRAWL_LOCK_LEASE_MS);

  // job_a is genuinely running in another process (record says running).
  const refused = await acquire(col, "job_b", "p2", T0 + 10_000, { status: { job_a: "running" } });
  assert.deepEqual(refused, { ok: false, heldBy: "job_a", expiresInMs: CRAWL_LOCK_LEASE_MS - 10_000 });
});

test("the reported bug: a cancelled job no longer blocks a new crawl", async () => {
  const col = memoryCollection();
  await acquire(col, "job_eab57", "p1", T0);
  // The operator cancelled it (record "cancelled"); its worker may still be winding down elsewhere.
  const res = await acquire(col, "job_new", "p1b", T0 + 45_000, { status: { job_eab57: "finished" } });
  assert.deepEqual(res, { ok: true, takenOverFrom: { jobId: "job_eab57", reason: "holder_finished" } });
  assert.equal(col.docs.get(CRAWL_LOCK_ID)!.jobId, "job_new");
});

test("a lock this process holds for a job it is not running is stale (dev reload, lost cleanup)", async () => {
  const col = memoryCollection();
  await acquire(col, "job_ghost", "p1", T0);
  const res = await acquire(col, "job_next", "p1", T0 + 5_000, { status: { job_ghost: "running" } });
  assert.equal(res.ok, true);
  assert.equal(res.ok && res.takenOverFrom?.reason, "holder_not_running_here");
  // ...but not while it is running here.
  const col2 = memoryCollection();
  await acquire(col2, "job_live", "p1", T0);
  const refused = await acquire(col2, "job_next", "p1", T0 + 5_000, { active: ["job_live"], status: { job_live: "running" } });
  assert.equal(refused.ok, false);
});

test("a stopped server's lock frees itself when its lease runs out; a renewed lease keeps it", async () => {
  const col = memoryCollection();
  await acquire(col, "job_a", "dead", T0);
  const early = await acquire(col, "job_b", "p2", T0 + CRAWL_LOCK_LEASE_MS - 1, { status: { job_a: "running" } });
  assert.equal(early.ok, false);
  assert.equal(await acquire(col, "job_b", "p2", T0 + CRAWL_LOCK_LEASE_MS, { status: { job_a: "running" } }).then((r) => r.ok), true);

  const col2 = memoryCollection();
  await acquire(col2, "job_a", "p1", T0);
  assert.equal(await renewCrawlLock(col2, { jobId: "job_a", owner: "p1", now: T0 + 90_000 }), true);
  const still = await acquire(col2, "job_b", "p2", T0 + CRAWL_LOCK_LEASE_MS + 1, { status: { job_a: "running" } });
  assert.equal(still.ok, false, "the heartbeat moved the expiry forward");
});

test("missing job record: a fresh lock is respected, an old one is reclaimed", async () => {
  const col = memoryCollection();
  await acquire(col, "job_a", "p1", T0);
  assert.equal((await acquire(col, "job_b", "p2", T0 + 1_000)).ok, false, "record may still be being written");
  const res = await acquire(col, "job_b", "p2", T0 + CRAWL_LOCK_FRESH_MS + 1);
  assert.equal(res.ok && res.takenOverFrom?.reason, "holder_record_missing");
});

test("two starters racing for a free lock or a stale lock: exactly one wins", async () => {
  for (const setup of ["free", "stale"] as const) {
    const col = memoryCollection();
    if (setup === "stale") await acquire(col, "job_old", "p0", T0);
    const ctx = { status: { job_old: "finished" as HolderJobStatus } };
    const results = await Promise.all([
      acquire(col, "job_x", "p1", T0 + 60_000, ctx),
      acquire(col, "job_y", "p2", T0 + 60_000, ctx),
    ]);
    assert.equal(results.filter((r) => r.ok).length, 1, `${setup}: one winner`);
    const winner = results[0].ok ? "job_x" : "job_y";
    assert.equal(col.docs.get(CRAWL_LOCK_ID)!.jobId, winner);
  }
});

test("renew fails once the lock was taken over, so the old job knows to stop", async () => {
  const col = memoryCollection();
  await acquire(col, "job_a", "p1", T0);
  await acquire(col, "job_b", "p2", T0 + 1_000, { status: { job_a: "finished" } });
  assert.equal(await renewCrawlLock(col, { jobId: "job_a", owner: "p1", now: T0 + 30_000 }), false);
  assert.equal(await renewCrawlLock(col, { jobId: "job_b", owner: "p2", now: T0 + 30_000 }), true);
});

test("release: normal end needs the owner; an operator cancel frees it whoever holds it; never another job's lock", async () => {
  const col = memoryCollection();
  await acquire(col, "job_a", "p1", T0);
  assert.equal(await releaseCrawlLock(col, { jobId: "job_a", owner: "p2" }), false);
  assert.equal(await releaseCrawlLock(col, { jobId: "job_other" }), false);
  assert.equal(col.docs.get(CRAWL_LOCK_ID)!.jobId, "job_a");
  assert.equal(await releaseCrawlLock(col, { jobId: "job_a" }), true);
  assert.equal(col.docs.get(CRAWL_LOCK_ID)!.jobId, null);
  assert.deepEqual(await acquire(col, "job_b", "p2", T0 + 1), { ok: true });
});

test("staleLockReason and the refusal text", () => {
  const lock = { owner: "p9", jobId: "job_a", acquiredAt: new Date(T0) };
  assert.equal(staleLockReason(lock, { ownOwner: "p1", localActive: false, holder: "running", now: T0 + 1e6 }), null);
  assert.equal(staleLockReason({ ...lock, jobId: null }, { ownOwner: "p1", localActive: false, holder: "finished", now: T0 }), null);
  assert.equal(describeHeldLock("job_a", 94_200), "job_a; if its server stopped, the slot frees itself within 95 s");
  assert.equal(describeHeldLock("job_a", 0), "job_a");
});
