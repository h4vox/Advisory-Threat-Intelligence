/**
 * Multi-Provider AI Registry & Dispatcher
 */

import type { AIProviderAdapter } from "./types";
import { GeminiRestAdapter } from "./gemini-rest";
import { ClaudeRestAdapter } from "./claude-rest";
import { OpenAiRestAdapter } from "./openai-rest";

export * from "./types";
export * from "./gemini-rest";
export * from "./claude-rest";
export * from "./openai-rest";

const geminiAdapter = new GeminiRestAdapter();
const claudeAdapter = new ClaudeRestAdapter();
const openAiAdapter = new OpenAiRestAdapter();

const ADAPTERS: Record<string, AIProviderAdapter> = {
  gemini_api: geminiAdapter,
  claude_api: claudeAdapter,
  openai_api: openAiAdapter,
  codex_agent: openAiAdapter,
};

export function getProviderAdapter(providerId: string): AIProviderAdapter | null {
  return ADAPTERS[providerId] || null;
}

export function isRestApiProvider(providerId: string): boolean {
  return providerId === "gemini_api" || providerId === "claude_api" || providerId === "openai_api" || providerId === "codex_agent";
}
