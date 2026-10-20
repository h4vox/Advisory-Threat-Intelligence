import { test } from "node:test";
import assert from "node:assert/strict";
import { isAllowedProviderEndpoint, isSafeWebhookUrl, redactIntegration } from "./redact.ts";

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

test("redactIntegration strips the webhook URL and exposes only hasWebhook", () => {
  const out = redactIntegration({ id: "slack_webhook", config: { webhookUrl: "https://hooks.slack.com/services/T/B/x" } } as never);
  const cfg = out.config as Record<string, unknown>;
  assert.equal(cfg.webhookUrl, undefined);
  assert.equal(cfg.hasWebhook, true);
});

test("messaging webhooks must be https on a public host (SSRF guard)", () => {
  assert.equal(isSafeWebhookUrl("https://hooks.slack.com/services/T/B/x"), true);
  assert.equal(isSafeWebhookUrl("https://discord.com/api/webhooks/1/x"), true);
  // Non-https and embedded credentials are rejected.
  assert.equal(isSafeWebhookUrl("http://hooks.slack.com/x"), false);
  assert.equal(isSafeWebhookUrl("https://user:pw@example.com/x"), false);
  // Loopback / private / link-local / metadata / CGNAT are rejected.
  assert.equal(isSafeWebhookUrl("https://localhost/x"), false);
  assert.equal(isSafeWebhookUrl("https://127.0.0.1/x"), false);
  assert.equal(isSafeWebhookUrl("https://10.0.0.5/x"), false);
  assert.equal(isSafeWebhookUrl("https://192.168.1.10/x"), false);
  assert.equal(isSafeWebhookUrl("https://172.16.0.1/x"), false);
  assert.equal(isSafeWebhookUrl("https://169.254.169.254/latest/meta-data"), false);
  assert.equal(isSafeWebhookUrl("https://100.64.0.1/x"), false);
  assert.equal(isSafeWebhookUrl("https://internal.service.local/x"), false);
  assert.equal(isSafeWebhookUrl("not a url"), false);
});
