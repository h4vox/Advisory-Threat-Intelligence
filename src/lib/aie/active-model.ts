/**
 * Active-model resolution shared by the marketplace state, the AI manager and the settings UI.
 *
 * The app stores two kinds of "active model":
 *  - AGY sandbox agent → `AppSettings.agentModel`, always normalised to a valid sandbox model.
 *  - REST / direct-API providers (OpenAI, Claude, Gemini, OpenRouter, xAI, DeepSeek, …) → the
 *    provider's own model id, kept verbatim on the integration's `config.selectedModel`. These must
 *    never be run through the AGY normaliser, or e.g. `gpt-4o` would be rewritten to a sandbox model.
 *
 * `resolveActiveModel` returns the correct model string for whichever provider is active, so a single
 * place decides it for display and for dispatch.
 */
import { REST_PROVIDER_META, isRestApiProvider } from "./providers/index.ts";
import { sanitizeAgyModel } from "./agent-framework/types.ts";

/** Remove a "Provider: model" display prefix without any AGY normalisation. */
export function stripProviderPrefix(model?: string | null): string {
  if (!model) return "";
  const i = model.indexOf(":");
  return (i >= 0 ? model.slice(i + 1) : model).trim();
}

/**
 * The model string to show and use for the currently active provider.
 * REST/API providers keep their own model; the AGY agent path is normalised.
 */
export function resolveActiveModel(opts: {
  providerId: string;
  agentModel?: string | null;
  /** The active integration's `config.selectedModel`, if any. */
  selectedModel?: string | null;
}): string {
  if (isRestApiProvider(opts.providerId)) {
    return stripProviderPrefix(opts.selectedModel) || REST_PROVIDER_META[opts.providerId]?.defaultModel || "";
  }
  return sanitizeAgyModel(opts.agentModel ?? undefined);
}
