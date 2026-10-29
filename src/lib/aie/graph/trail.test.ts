import { test } from "node:test";
import assert from "node:assert/strict";
import { EMPTY_TRAIL, back, canBack, canForward, currentStep, forward, jump, restore, visit } from "./trail.ts";

test("visiting builds a trail; back and forward keep every step", () => {
  let t = visit(visit(visit(visit(EMPTY_TRAIL, "APT29"), "Government"), "Cobalt Strike"), "T1059");
  assert.deepEqual(t.steps, ["APT29", "Government", "Cobalt Strike", "T1059"]);
  t = jump(t, 1);
  assert.equal(currentStep(t), "Government");
  assert.equal(t.steps.length, 4, "going back removes nothing");
  assert.ok(canForward(t) && canBack(t));
  t = forward(forward(t));
  assert.equal(currentStep(t), "T1059");
  assert.equal(currentStep(back(t)), "Cobalt Strike");
});

test("a new focus from an earlier step replaces the later steps", () => {
  let t = visit(visit(visit(EMPTY_TRAIL, "A"), "B"), "C");
  t = visit(jump(t, 0), "D");
  assert.deepEqual(t.steps, ["A", "D"]);
  assert.equal(t.pos, 1);
  assert.equal(visit(t, "D"), t, "focusing the current step changes nothing");
});

test("restore keeps the position in range", () => {
  assert.deepEqual(restore(["A", "B"], 9), { steps: ["A", "B"], pos: 1 });
  assert.deepEqual(restore([], 0), EMPTY_TRAIL);
});
