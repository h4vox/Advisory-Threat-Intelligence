import { test } from "node:test";
import assert from "node:assert/strict";
import { CANCEL_GRACE_MS, HUNG_JOB_GRACE_MS, hungJobReason, itemTimeoutMs, settleWithin } from "./crawl-guards.ts";

test("settleWithin: resolves, rejects and times out without throwing", async () => {
  assert.deepEqual(await settleWithin(Promise.resolve(7), 1000), { status: "fulfilled", value: 7 });
  const rejected = await settleWithin(Promise.reject(new Error("boom")), 1000);
  assert.equal(rejected.status, "rejected");
  // A promise that never settles is abandoned once the budget is spent.
  const started = Date.now();
  const hung = await settleWithin(new Promise(() => {}), 40);
  assert.deepEqual(hung, { status: "timeout" });
  assert.ok(Date.now() - started < 1000, "returns promptly after the budget");
});

test("settleWithin: clears its timer so a finished job does not keep the process alive", async () => {
  const before = process.getActiveResourcesInfo().filter((r) => r === "Timeout").length;
  await settleWithin(Promise.resolve(1), 60_000);
  const after = process.getActiveResourcesInfo().filter((r) => r === "Timeout").length;
  assert.equal(after, before);
});

test("itemTimeoutMs: room for an AI evaluation and its retries, never unbounded", () => {
  assert.equal(itemTimeoutMs(45), 195_000); // 3 x 45 s + 60 s
  assert.equal(itemTimeoutMs(undefined), 195_000); // default agent timeout
  assert.equal(itemTimeoutMs(5), 90_000); // floor
  assert.equal(itemTimeoutMs(600), 300_000); // ceiling
});

test("hungJobReason: healthy, over its limit, or cancelled but never stopping", () => {
  const start = 1_000_000;
  const job = { startedAt: start, maxRunMs: 20 * 60_000 };
  // Running inside its limit, and in the grace after it (the worker drain): healthy.
  assert.equal(hungJobReason(job, start + 19 * 60_000), null);
  assert.equal(hungJobReason(job, start + 20 * 60_000 + HUNG_JOB_GRACE_MS - 1), null);
  // Still registered past limit + grace: hung (e.g. the 2 h 19 m "20 min" job).
  assert.equal(hungJobReason(job, start + 20 * 60_000 + HUNG_JOB_GRACE_MS + 1), "over_time");
  // An operator cancel that never drains is released after its own grace.
  const cancelled = { ...job, cancelledAt: start + 60_000 };
  assert.equal(hungJobReason(cancelled, start + 60_000 + CANCEL_GRACE_MS - 1), null);
  assert.equal(hungJobReason(cancelled, start + 60_000 + CANCEL_GRACE_MS + 1), "stuck_cancel");
});
