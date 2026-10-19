import { test } from "node:test";
import assert from "node:assert/strict";
import { resolveActiveModel, stripProviderPrefix } from "./active-model.ts";
import { sanitizeAgyModel } from "./agent-framework/types.ts";

test("stripProviderPrefix removes a 'Provider: model' prefix without normalising", () => {
  assert.equal(stripProviderPrefix("OpenAI API: gpt-4o"), "gpt-4o");
  assert.equal(stripProviderPrefix("gpt-4o"), "gpt-4o");
  assert.equal(stripProviderPrefix(""), "");
  assert.equal(stripProviderPrefix(undefined), "");
  assert.equal(stripProviderPrefix(null), "");
});

test("resolveActiveModel keeps a REST provider's own model verbatim", () => {
  assert.equal(
    resolveActiveModel({ providerId: "openai_api", selectedModel: "gpt-4o" }),
    "gpt-4o",
  );
  // A display-prefixed stored value is stripped, not AGY-normalised.
  assert.equal(
    resolveActiveModel({ providerId: "openai_api", selectedModel: "OpenAI API: gpt-4o-mini" }),
    "gpt-4o-mini",
  );
  // A custom model id survives (no coercion to a sandbox model).
  assert.equal(
    resolveActiveModel({ providerId: "openrouter", selectedModel: "anthropic/claude-3.5-sonnet" }),
    "anthropic/claude-3.5-sonnet",
  );
});

test("resolveActiveModel falls back to the REST provider's default model", () => {
  assert.equal(resolveActiveModel({ providerId: "openai_api" }), "gpt-4o");
  assert.equal(resolveActiveModel({ providerId: "openrouter", selectedModel: "" }), "openai/gpt-4o-mini");
  assert.equal(resolveActiveModel({ providerId: "deepseek" }), "deepseek-chat");
});

test("resolveActiveModel normalises the AGY agent model", () => {
  // Non-REST provider → AGY sandbox normalisation (never a raw REST id).
  assert.equal(
    resolveActiveModel({ providerId: "agy_agent", agentModel: "gpt-4o" }),
    sanitizeAgyModel("gpt-4o"),
  );
  assert.equal(
    resolveActiveModel({ providerId: "agy_agent", agentModel: undefined }),
    sanitizeAgyModel(undefined),
  );
});
