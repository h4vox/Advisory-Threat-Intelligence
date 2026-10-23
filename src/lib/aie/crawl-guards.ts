/**
 * Guards that keep one stuck request from hanging the crawler. Pure and unit-tested.
 *
 * A crawl runs inside the server process. Before these guards, a single awaited call that never
 * settled (an AI request, a PDF parse, a stalled socket) held its worker forever. The job then waited
 * on that worker after its time limit, never released its "running" slot, and blocked every later
 * scheduled or manual crawl ("A crawl is already running") until the server restarted.
 */

/** A job still registered this long past its time limit is hung. Healthy jobs end within ~1 min of it. */
export const HUNG_JOB_GRACE_MS = 3 * 60_000;
/** A cancelled job that has not stopped after this long is released anyway. */
export const CANCEL_GRACE_MS = 90_000;
/** After the time limit or a cancel, in-flight workers get this long before the job finalizes without them. */
export const WORKER_DRAIN_GRACE_MS = 60_000;

export type Settled<T> = { status: "fulfilled"; value: T } | { status: "rejected"; reason: unknown } | { status: "timeout" };

/** Waits for `promise`, but no longer than `ms`. Never rejects, and the timer is always cleared. */
export async function settleWithin<T>(promise: Promise<T>, ms: number): Promise<Settled<T>> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race<Settled<T>>([
      promise.then(
        (value) => ({ status: "fulfilled", value }),
        (reason: unknown) => ({ status: "rejected", reason }),
      ),
      new Promise<Settled<T>>((resolve) => {
        timer = setTimeout(() => resolve({ status: "timeout" }), ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Budget for one article: room for an AI evaluation with its retries (three agent timeouts) plus the
 * fetch, PDF and database work, but never unbounded. 90 s minimum, 5 min maximum.
 */
export function itemTimeoutMs(agentTimeoutSeconds?: number | null): number {
  const agentMs = (agentTimeoutSeconds && agentTimeoutSeconds > 0 ? agentTimeoutSeconds : 45) * 1000;
  return Math.min(Math.max(agentMs * 3 + 60_000, 90_000), 5 * 60_000);
}

export type TrackedJob = { startedAt: number; maxRunMs: number; cancelledAt?: number };

/** Why an in-memory job can no longer be running normally, or null while it is healthy. */
export function hungJobReason(job: TrackedJob, now: number): "over_time" | "stuck_cancel" | null {
  if (now - job.startedAt > job.maxRunMs + HUNG_JOB_GRACE_MS) return "over_time";
  if (job.cancelledAt !== undefined && now - job.cancelledAt > CANCEL_GRACE_MS) return "stuck_cancel";
  return null;
}
