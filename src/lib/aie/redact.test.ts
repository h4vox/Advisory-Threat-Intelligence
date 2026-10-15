import { test } from "node:test";
import assert from "node:assert/strict";
import { isAllowedProviderEndpoint, redactIntegration } from "./redact.ts";

test("redactIntegration strips secrets and exposes only hints", () => {
  const out = redactIntegration({
    id: "openai_api",
    config: { apiKey: "sk-live-1234567890abcd", authToken: "tok", oauthCodeVerifier: "v", selectedModel: "m" },
  } as never);
  const cfg = out.config as Record<string, unknown>;
  assert.equal(cfg.apiKey, undefined);
  assert.equal(cfg.authToken, undefined);
  assert.equal(cfg.oauthCodeVerifier, undefined);
  assert.equal(cfg.selectedModel, "m");
  assert.equal(cfg.hasApiKey, true);
  assert.equal(cfg.apiKeyHint, "…abcd");
  assert.equal(cfg.hasAuthToken, true);
});

test("provider endpoints must be https on an approved host", () => {
  assert.equal(isAllowedProviderEndpoint("https://api.openai.com/v1"), true);
  assert.equal(isAllowedProviderEndpoint("http://api.openai.com/v1"), false);
  assert.equal(isAllowedProviderEndpoint("https://attacker.example/v1"), false);
  assert.equal(isAllowedProviderEndpoint("https://user:pw@api.openai.com/v1"), false);
  assert.equal(isAllowedProviderEndpoint("not a url"), false);
});
