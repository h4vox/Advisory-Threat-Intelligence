import { test } from "node:test";
import assert from "node:assert/strict";
import { REST_PROVIDER_META, getProviderAdapter, isRestApiProvider } from "./index.ts";
import { OpenAiCompatibleAdapter } from "./openai-compatible.ts";

test("every REST provider has an adapter and is recognised; AGY is not a REST provider", () => {
  for (const id of ["gemini_api", "claude_api", "openai_api", "openrouter", "xai", "deepseek"]) {
    assert.equal(isRestApiProvider(id), true, id);
    const adapter = getProviderAdapter(id);
    assert.ok(adapter && typeof adapter.generate === "function" && typeof adapter.testConnection === "function", id);
  }
  assert.equal(isRestApiProvider("agy_agent"), false);
  assert.equal(getProviderAdapter("agy_agent"), null);
});

test("model patterns recognise each provider's models and reject foreign ones", () => {
  const m = REST_PROVIDER_META;
  assert.match("gemini-2.5-flash", m.gemini_api.modelPattern);
  assert.match("claude-3-7-sonnet", m.claude_api.modelPattern);
  assert.match("gpt-4o", m.openai_api.modelPattern);
  assert.match("o3-mini", m.openai_api.modelPattern);
  assert.match("grok-2-latest", m.xai.modelPattern);
  assert.match("deepseek-chat", m.deepseek.modelPattern);
  // OpenRouter uses the vendor/model form.
  assert.match("openai/gpt-4o", m.openrouter.modelPattern);
  assert.match("anthropic/claude-3.7-sonnet", m.openrouter.modelPattern);
  assert.doesNotMatch("gemini-2.5-flash", m.openrouter.modelPattern); // no slash → not an OpenRouter id
  assert.doesNotMatch("claude-3-7-sonnet", m.openai_api.modelPattern);
  assert.doesNotMatch("gpt-4o", m.claude_api.modelPattern);
});

test("every provider has a default model", () => {
  for (const meta of Object.values(REST_PROVIDER_META)) {
    assert.ok(meta.defaultModel.length > 0, meta.id);
  }
});

test("a custom endpoint is refused unless it is on the host allowlist", async () => {
  const adapter = new OpenAiCompatibleAdapter({ id: "custom", name: "Custom", baseUrl: "https://api.openai.com/v1", defaultModel: "gpt-4o", allowCustomEndpoint: true });
  const gen = await adapter.generate({ prompt: "hi", apiKey: "k", endpointUrl: "https://evil.example.com/v1" });
  assert.equal(gen.success, false);
  assert.match(gen.error ?? "", /approved provider host list/);
  const probe = await adapter.testConnection("k", { endpointUrl: "http://169.254.169.254/v1" });
  assert.equal(probe.success, false);
  assert.equal(probe.status, "error");
});

test("missing key short-circuits without a network call", async () => {
  const adapter = new OpenAiCompatibleAdapter({ id: "xai", name: "xAI", baseUrl: "https://api.x.ai/v1", defaultModel: "grok-2-latest", envKeys: ["__AIE_TEST_UNSET_KEY__"] });
  const probe = await adapter.testConnection(undefined, {});
  assert.equal(probe.success, false);
  assert.equal(probe.status, "invalid_key");
  assert.equal(probe.modelTested, "grok-2-latest");
});
