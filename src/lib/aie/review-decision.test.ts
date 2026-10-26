import { test } from "node:test";
import assert from "node:assert/strict";
import { decideReviewAction, type ReviewSignals } from "./review-decision.ts";

const bare: ReviewSignals = { iocCount: 0, cves: 0, techniques: 0, attackChainSteps: 0, entities: 0, qualityScore: 0.3, depthPass: false, wordCount: 120 };
const rich: ReviewSignals = { ...bare, iocCount: 12, techniques: 5, depthPass: true, qualityScore: 0.8 };
const notUseful = (confidence: number) => ({ verdict: "not_useful" as const, confidence, reasons: ["Webinar announcement"] });

test("no AI answer changes nothing", () => {
  assert.equal(decideReviewAction(null, bare, null).action, "unchanged");
});

test("useful keeps; unsure flags", () => {
  assert.equal(decideReviewAction({ verdict: "useful", confidence: 0.9, reasons: [] }, bare, null).action, "keep");
  assert.equal(decideReviewAction({ verdict: "unsure", confidence: 0.9, reasons: [] }, rich, null).action, "flag");
});

test("not useful but with evidence of value: flagged, never hidden", () => {
  const d = decideReviewAction(notUseful(0.99), rich, null, true);
  assert.equal(d.action, "flag");
  assert.ok(d.protectedBy.includes("12 indicators"));
  assert.match(d.reason, /Kept for an analyst/);
  // Each signal protects on its own.
  for (const s of [{ iocCount: 2 }, { cves: 1 }, { techniques: 1 }, { attackChainSteps: 1 }, { entities: 2 }, { depthPass: true }, { qualityScore: 0.7 }, { structured: true }]) {
    assert.equal(decideReviewAction(notUseful(0.99), { ...bare, ...s }, null, true).action, "flag", JSON.stringify(s));
  }
});

test("not useful without evidence: hidden only when the AI is confident and hiding is allowed", () => {
  assert.equal(decideReviewAction(notUseful(0.84), bare, null, true).action, "flag");
  const d = decideReviewAction(notUseful(0.9), bare, null, true);
  assert.equal(d.action, "hide");
  assert.match(d.reason, /Restore it from Hidden/);
  // Hiding off (the default): flagged instead.
  const off = decideReviewAction(notUseful(0.99), bare, null);
  assert.equal(off.action, "flag");
  assert.match(off.reason, /Settings/);
});

test("reports hidden by the rules or an analyst are never changed by the review", () => {
  assert.equal(decideReviewAction({ verdict: "useful", confidence: 1, reasons: [] }, rich, "rules").action, "unchanged");
  assert.equal(decideReviewAction({ verdict: "useful", confidence: 1, reasons: [] }, rich, "analyst").action, "unchanged");
});

test("reports the earlier AI audit hid come back when useful or carrying evidence", () => {
  assert.equal(decideReviewAction(notUseful(0.95), rich, "ai").action, "restore_and_flag");
  assert.equal(decideReviewAction({ verdict: "useful", confidence: 0.6, reasons: [] }, bare, "ai").action, "restore_and_flag");
  assert.equal(decideReviewAction(notUseful(0.95), bare, "ai").action, "unchanged");
});

test("an analyst's keep stands: never re-flagged or hidden", () => {
  const d = decideReviewAction(notUseful(0.99), { ...bare, analystKeep: true }, null, true);
  assert.equal(d.action, "keep");
  assert.match(d.reason, /Kept by an analyst/);
});
