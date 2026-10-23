/**
 * Cross-process crawl lock (MongoDB): one document, a short lease kept alive by a heartbeat.
 *
 * Before: the lock was taken for the whole job time limit plus five minutes and freed only when the job
 * finished winding down. A job cancelled from the dashboard, or one whose server was restarted, kept
 * blocking every new crawl ("A crawl is already running (job_…)") for up to 25 minutes while the job
 * history already said "Cancelled".
 *
 * Now:
 * - The lease is short (2 min) and the running job renews it every 30 s, so a lock left by a stopped
 *   server frees itself within the lease.
 * - A lock whose job is no longer running (cancelled, finished, failed, interrupted, or its record is
 *   gone) is taken over at once with a compare-and-swap, so two starters can never both win.
 * - A lock held by this process for a job this process is not running is stale by definition.
 *
 * No server-only imports: the collection is injected, so the logic is unit-tested against an in-memory
 * stand-in that follows MongoDB's matching rules for the filters used here.
 */

export const CRAWL_LOCK_ID = "crawl_lock";
/** A holder that stops renewing loses the lock after this long. */
export const CRAWL_LOCK_LEASE_MS = 2 * 60_000;
/** How often a running job renews its lease. */
export const CRAWL_LOCK_HEARTBEAT_MS = 30_000;
/** A lock this young may belong to a job whose record is still being written: never treat it as orphaned. */
export const CRAWL_LOCK_FRESH_MS = 30_000;

export type CrawlLockDoc = {
  _id: string;
  docType: "crawl_lock";
  owner: string | null;
  jobId: string | null;
  acquiredAt?: Date;
  renewedAt?: Date;
  expiresAt: Date;
};

/** The subset of a MongoDB collection the lock uses. */
export type CrawlLockCollection = {
  findOneAndUpdate(
    filter: Record<string, unknown>,
    update: { $set: Partial<CrawlLockDoc> },
    options: { upsert?: boolean; returnDocument: "after" },
  ): Promise<CrawlLockDoc | null>;
  updateOne(filter: Record<string, unknown>, update: { $set: Partial<CrawlLockDoc> }): Promise<{ matchedCount: number }>;
  findOne(filter: Record<string, unknown>): Promise<CrawlLockDoc | null>;
};

/** What the job record of a lock holder says. */
export type HolderJobStatus = "running" | "finished" | "missing";

export type AcquireResult =
  | { ok: true; takenOverFrom?: { jobId: string; reason: StaleLockReason } }
  | { ok: false; heldBy: string | null; expiresInMs: number };

export type StaleLockReason = "holder_not_running_here" | "holder_finished" | "holder_record_missing";

/**
 * Why a held lock no longer protects a running crawl, or null while it does.
 * `localActive`: the holder job is running in this process. `holder`: its job record's status.
 */
export function staleLockReason(
  lock: Pick<CrawlLockDoc, "owner" | "jobId" | "acquiredAt">,
  ctx: { ownOwner: string; localActive: boolean; holder: HolderJobStatus; now: number },
): StaleLockReason | null {
  if (!lock.jobId) return null; // free, not stale: the normal path takes it
  if (ctx.localActive) return null;
  if (lock.owner === ctx.ownOwner) return "holder_not_running_here";
  if (ctx.holder === "finished") return "holder_finished";
  if (ctx.holder === "missing") {
    const age = lock.acquiredAt ? ctx.now - new Date(lock.acquiredAt).getTime() : Infinity;
    return age > CRAWL_LOCK_FRESH_MS ? "holder_record_missing" : null;
  }
  return null;
}

function isDuplicateKey(err: unknown): boolean {
  return (err as { code?: number } | null)?.code === 11000;
}

/**
 * Takes the lock for `jobId`. Free or expired: taken. Held by a job that is no longer running: taken
 * over (compare-and-swap on the holder). Otherwise refused with the holder and its remaining lease.
 */
export async function acquireCrawlLock(
  col: CrawlLockCollection,
  opts: {
    jobId: string;
    owner: string;
    now?: number;
    leaseMs?: number;
    isLocalActive: (jobId: string) => boolean;
    holderStatus: (jobId: string) => Promise<HolderJobStatus>;
  },
): Promise<AcquireResult> {
  const now = new Date(opts.now ?? Date.now());
  const leaseMs = opts.leaseMs ?? CRAWL_LOCK_LEASE_MS;
  const fields: Partial<CrawlLockDoc> = {
    docType: "crawl_lock",
    owner: opts.owner,
    jobId: opts.jobId,
    acquiredAt: now,
    renewedAt: now,
    expiresAt: new Date(now.getTime() + leaseMs),
  };

  // Two rounds: a free lock can be taken by someone else between our read and our write.
  for (let round = 0; round < 2; round++) {
    try {
      const res = await col.findOneAndUpdate(
        { _id: CRAWL_LOCK_ID, $or: [{ jobId: null }, { expiresAt: { $lte: now } }, { expiresAt: { $exists: false } }] },
        { $set: fields },
        { upsert: true, returnDocument: "after" },
      );
      if (res && res.jobId === opts.jobId) return { ok: true };
    } catch (err) {
      if (!isDuplicateKey(err)) throw err; // E11000: the document exists and is held
    }

    const held = await col.findOne({ _id: CRAWL_LOCK_ID });
    if (!held || !held.jobId || new Date(held.expiresAt).getTime() <= now.getTime()) continue; // freed meanwhile

    const reason = staleLockReason(held, {
      ownOwner: opts.owner,
      localActive: opts.isLocalActive(held.jobId),
      holder: await opts.holderStatus(held.jobId),
      now: now.getTime(),
    });
    if (!reason) {
      return { ok: false, heldBy: held.jobId, expiresInMs: Math.max(0, new Date(held.expiresAt).getTime() - now.getTime()) };
    }
    // Compare-and-swap on the exact holder: of two concurrent starters, only one matches.
    const taken = await col.findOneAndUpdate(
      { _id: CRAWL_LOCK_ID, jobId: held.jobId, owner: held.owner },
      { $set: fields },
      { returnDocument: "after" },
    );
    if (taken && taken.jobId === opts.jobId) return { ok: true, takenOverFrom: { jobId: held.jobId, reason } };
  }

  const held = await col.findOne({ _id: CRAWL_LOCK_ID });
  return {
    ok: false,
    heldBy: held?.jobId ?? null,
    expiresInMs: held ? Math.max(0, new Date(held.expiresAt).getTime() - (opts.now ?? Date.now())) : 0,
  };
}

/** Extends the lease. False when the lock is no longer this job's (it was taken over): the job must stop. */
export async function renewCrawlLock(
  col: CrawlLockCollection,
  opts: { jobId: string; owner: string; now?: number; leaseMs?: number },
): Promise<boolean> {
  const now = new Date(opts.now ?? Date.now());
  const res = await col.updateOne(
    { _id: CRAWL_LOCK_ID, owner: opts.owner, jobId: opts.jobId },
    { $set: { renewedAt: now, expiresAt: new Date(now.getTime() + (opts.leaseMs ?? CRAWL_LOCK_LEASE_MS)) } },
  );
  return res.matchedCount > 0;
}

/**
 * Frees the lock if `jobId` holds it. With `owner`, only that holder's lock (a job ending normally);
 * without, whoever holds it for that job (an operator cancel: the job is over wherever it runs).
 */
export async function releaseCrawlLock(col: CrawlLockCollection, opts: { jobId: string; owner?: string }): Promise<boolean> {
  const filter: Record<string, unknown> = { _id: CRAWL_LOCK_ID, jobId: opts.jobId };
  if (opts.owner) filter.owner = opts.owner;
  const res = await col.updateOne(filter, { $set: { owner: null, jobId: null, expiresAt: new Date(0) } });
  return res.matchedCount > 0;
}

/** User-facing refusal, e.g. "job_ab12…; if its server stopped, it frees itself within 95 s". */
export function describeHeldLock(heldBy: string | null, expiresInMs: number): string {
  const secs = Math.ceil(expiresInMs / 1000);
  const id = heldBy ?? "another job";
  return secs > 0 ? `${id}; if its server stopped, the slot frees itself within ${secs} s` : id;
}
