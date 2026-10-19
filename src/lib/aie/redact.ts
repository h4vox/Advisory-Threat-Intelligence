import type { IntegrationItem, MarketplaceState } from "./marketplace-types.ts";

/**
 * Secrets never leave the server. Integrations sent to the browser carry only
 * `hasApiKey` / `apiKeyHint` (last 4) / `hasAuthToken` in place of the values.
 */

const SECRET_KEY_PATTERN = /(api[-_]?key|token|secret|password|verifier|credential)/i;

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
