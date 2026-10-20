import type { IntegrationItem, MarketplaceState } from "./marketplace-types.ts";

/**
 * Secrets never leave the server. Integrations sent to the browser carry only
 * `hasApiKey` / `apiKeyHint` (last 4) / `hasAuthToken` in place of the values.
 */

// `webhook` is secret because messaging webhook URLs embed a per-channel token in the path.
const SECRET_KEY_PATTERN = /(api[-_]?key|token|secret|password|verifier|credential|webhook)/i;

export function isSecretConfigKey(key: string): boolean {
  return SECRET_KEY_PATTERN.test(key);
}

function hint(value: unknown): string | undefined {
  if (typeof value !== "string" || value.length < 8) return undefined;
  return `…${value.slice(-4)}`;
}

export function redactIntegration(item: IntegrationItem): IntegrationItem {
  if (!item.config) return item;
  const config: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(item.config)) {
    if (!isSecretConfigKey(key)) config[key] = value;
  }
  config.hasApiKey = Boolean(item.config.apiKey);
  config.apiKeyHint = hint(item.config.apiKey);
  config.hasAuthToken = Boolean(item.config.authToken);
  config.hasWebhook = Boolean(item.config.webhookUrl);
  return { ...item, config: config as IntegrationItem["config"] };
}

export function redactMarketplaceState(state: MarketplaceState): MarketplaceState {
  return { ...state, integrations: state.integrations.map(redactIntegration) };
}

/** Hosts a configured provider endpoint may point at. Extend via AIE_ALLOWED_LLM_HOSTS. */
const DEFAULT_LLM_HOSTS = ["api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com", "openrouter.ai", "api.x.ai", "api.deepseek.com"];

export function isAllowedProviderEndpoint(raw: string): boolean {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.protocol !== "https:" || url.username || url.password) return false;
  const extra = (process.env.AIE_ALLOWED_LLM_HOSTS ?? "")
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
  return [...DEFAULT_LLM_HOSTS, ...extra].includes(url.hostname.toLowerCase());
}

/**
 * A messaging webhook URL must be https on a public host. Blocks loopback, private, link-local and
 * cloud-metadata targets so a configured webhook cannot be pointed at internal services (SSRF).
 * Not a substitute for egress controls, but defence in depth for an analyst-configured destination.
 */
export function isSafeWebhookUrl(raw: string): boolean {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.protocol !== "https:" || url.username || url.password) return false;
  const host = url.hostname.toLowerCase();
  if (host === "localhost" || host.endsWith(".local") || host.endsWith(".internal") || host.endsWith(".localhost")) return false;
  const v4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const a = Number(v4[1]);
    const b = Number(v4[2]);
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 192 && b === 168) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 169 && b === 254) return false; // link-local incl. 169.254.169.254 metadata
    if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT
  }
  if (host === "::1" || host === "[::1]" || host.startsWith("fe80") || host.startsWith("fc") || host.startsWith("fd")) return false;
  return true;
}
