/**
 * Multi-provider AI registry & dispatcher.
 *
 * Every entry here is a direct REST provider — one HTTPS call per request, no container. `REST_PROVIDER_META`
 * is the single source of truth (base URL, default model, env keys, how to recognise a model id); the
 * adapters, `ai-manager` and the marketplace registry all read from it so a new provider is added in one place.
 */

import type { AIProviderAdapter } from "./types.ts";
import { GeminiRestAdapter } from "./gemini-rest.ts";
import { ClaudeRestAdapter } from "./claude-rest.ts";
import { OpenAiRestAdapter } from "./openai-rest.ts";
import { OpenAiCompatibleAdapter } from "./openai-compatible.ts";

export * from "./types.ts";
export * from "./gemini-rest.ts";
export * from "./claude-rest.ts";
export * from "./openai-rest.ts";
export * from "./openai-compatible.ts";

export type RestProviderMeta = {
  id: string;
  /** Recognises a bare model id (prefix already stripped) that belongs to this provider. */
  modelPattern: RegExp;
  defaultModel: string;
  /** Environment variables to read the key from, in order. */
  envKeys: string[];
};

/** OpenAI-compatible providers share one adapter; only the base URL / default model / key differ. */
const OPENAI_COMPATIBLE = {
  openrouter: {
    name: "OpenRouter",
    baseUrl: "https://openrouter.ai/api/v1",
    defaultModel: "openai/gpt-4o-mini",
    envKeys: ["OPENROUTER_API_KEY"],
    headers: { "HTTP-Referer": "https://github.com/h4vox/Advisory-Threat-Intelligence", "X-Title": "AIE" },
    // vendor/model form, e.g. "openai/gpt-4o", "anthropic/claude-3.7-sonnet", "x-ai/grok-2".
    modelPattern: /^[\w.-]+\/[\w.:-]+$/,
  },
  xai: {
    name: "xAI Grok",
    baseUrl: "https://api.x.ai/v1",
    defaultModel: "grok-2-latest",
    envKeys: ["XAI_API_KEY"],
    modelPattern: /^grok[-\w.]*$/i,
  },
  deepseek: {
    name: "DeepSeek",
    baseUrl: "https://api.deepseek.com/v1",
    defaultModel: "deepseek-chat",
    envKeys: ["DEEPSEEK_API_KEY"],
    modelPattern: /^deepseek[-\w.]*$/i,
  },
} as const;

const geminiAdapter = new GeminiRestAdapter();
const claudeAdapter = new ClaudeRestAdapter();
const openAiAdapter = new OpenAiRestAdapter();

const compatibleAdapters: Record<string, OpenAiCompatibleAdapter> = Object.fromEntries(
  Object.entries(OPENAI_COMPATIBLE).map(([id, c]) => [id, new OpenAiCompatibleAdapter({ id, name: c.name, baseUrl: c.baseUrl, defaultModel: c.defaultModel, envKeys: [...c.envKeys], headers: (c as { headers?: Record<string, string> }).headers })]),
);

const ADAPTERS: Record<string, AIProviderAdapter> = {
  gemini_api: geminiAdapter,
  claude_api: claudeAdapter,
  openai_api: openAiAdapter,
  codex_agent: openAiAdapter,
  ...compatibleAdapters,
};

/** Model recognition and defaults per REST provider, consumed by ai-manager. */
export const REST_PROVIDER_META: Record<string, RestProviderMeta> = {
  gemini_api: { id: "gemini_api", modelPattern: /^gemini[-\w.]*$/i, defaultModel: "gemini-2.5-flash", envKeys: ["GEMINI_API_KEY"] },
  claude_api: { id: "claude_api", modelPattern: /^claude[-\w.]*$/i, defaultModel: "claude-3-7-sonnet", envKeys: ["ANTHROPIC_API_KEY"] },
  openai_api: { id: "openai_api", modelPattern: /^(gpt|o\d|chatgpt|codex)[-\w.]*$/i, defaultModel: "gpt-4o", envKeys: ["OPENAI_API_KEY"] },
  codex_agent: { id: "codex_agent", modelPattern: /^(gpt|o\d|chatgpt|codex)[-\w.]*$/i, defaultModel: "gpt-4o", envKeys: ["OPENAI_API_KEY"] },
  ...Object.fromEntries(Object.entries(OPENAI_COMPATIBLE).map(([id, c]) => [id, { id, modelPattern: c.modelPattern, defaultModel: c.defaultModel, envKeys: [...c.envKeys] }])),
};

export function getProviderAdapter(providerId: string): AIProviderAdapter | null {
  return ADAPTERS[providerId] || null;
}

export function isRestApiProvider(providerId: string): boolean {
  return providerId in ADAPTERS;
}
