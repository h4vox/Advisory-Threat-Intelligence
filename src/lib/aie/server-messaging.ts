/**
 * Messaging dispatch for marketplace messaging integrations (Slack, Microsoft Teams, Discord and a
 * generic JSON webhook). A configured webhook URL is read server-side (decrypted) and the message is
 * POSTed in the provider's expected shape. The destination is re-validated with isSafeWebhookUrl at
 * send time so a stored URL can never be used to reach an internal service (SSRF defence in depth).
 */
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { analystMiddleware } from "./access";
import { isSafeWebhookUrl } from "./redact";
import { mongoGetMarketplaceIntegrations } from "../mongodb/repository.server";

/** Per-provider body shape for a plain-text message. Unknown ids fall back to the common `{ text }`. */
const BODY_FORMAT: Record<string, (text: string) => Record<string, unknown>> = {
  slack_webhook: (text) => ({ text }),
  teams_webhook: (text) => ({ text }),
  discord_webhook: (text) => ({ content: text }),
  webhook_generic: (text) => ({ text, source: "AIE" }),
};

export type SendMessageResult = { ok: boolean; status: number; message: string };

async function postWebhook(url: string, body: Record<string, unknown>): Promise<SendMessageResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    const ok = res.ok;
    return { ok, status: res.status, message: ok ? "Message delivered." : `Provider responded ${res.status}.` };
  } catch (err) {
    const msg = err instanceof Error && err.name === "AbortError" ? "The provider did not respond within 8s." : err instanceof Error ? err.message : "Request failed.";
    return { ok: false, status: 0, message: msg };
  } finally {
    clearTimeout(timer);
  }
}

export const sendTestMessage = createServerFn({ method: "POST" })
  .middleware([analystMiddleware])
  .validator(z.object({ id: z.string().min(1).max(100), text: z.string().trim().max(2000).optional() }))
  .handler(async ({ data, context }): Promise<SendMessageResult> => {
    const integrations = await mongoGetMarketplaceIntegrations();
    const integration = integrations.find((x) => x.id === data.id);
    if (!integration) throw new Error(`Integration ${data.id} not found.`);
    if (integration.category !== "Messaging") throw new Error(`${integration.name} is not a messaging integration.`);
    const url = typeof integration.config?.webhookUrl === "string" ? integration.config.webhookUrl : "";
    if (!url) throw new Error(`Configure a webhook URL for ${integration.name} first.`);
    if (!isSafeWebhookUrl(url)) throw new Error("The stored webhook URL is not a valid public https endpoint.");

    const by = context.identity.username ?? context.userEmail ?? "an analyst";
    const text = data.text?.trim() || `✅ AIE test message from ${by} — ${integration.name} is connected.`;
    const format = BODY_FORMAT[integration.id] ?? ((t: string) => ({ text: t }));
    return postWebhook(url, format(text));
  });
