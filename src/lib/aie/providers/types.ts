/**
 * Multi-Provider AI Architecture Types
 *
 * Defines unified interfaces for direct REST APIs (Google Gemini, Anthropic Claude,
 * OpenAI-compatible / local LLMs) and local CLI agents (Antigravity AGY).
 */

export type AIProviderId =
  | "agy_agent"
  | "gemini_api"
  | "claude_api"
  | "openai_api"
  | "claude_code_agent"
  | "codex_agent";

export interface LLMMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface LLMGenerateOptions {
  prompt: string | LLMMessage[];
  systemInstruction?: string;
  model?: string;
  temperature?: number;
  maxTokens?: number;
  responseFormat?: "text" | "json";
  timeoutMs?: number;
  apiKey?: string;
  endpointUrl?: string;
}

export interface LLMTokenUsage {
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
}

export interface LLMGenerateResult {
  success: boolean;
  text: string;
  model: string;
  providerId: AIProviderId | string;
  latencyMs: number;
  tokens?: LLMTokenUsage;
  error?: string;
  rawResponse?: any;
}

export interface ProviderConnectionTestResult {
  success: boolean;
  providerId: string;
  providerName: string;
  status: "healthy" | "unreachable" | "invalid_key" | "rate_limited" | "error";
  latencyMs: number;
  message: string;
  modelTested?: string;
  testedAt: string;
  details?: Record<string, any>;
  logs: string[];
}

export interface AIProviderAdapter {
  id: AIProviderId | string;
  name: string;
  testConnection(apiKey?: string, config?: Record<string, any>): Promise<ProviderConnectionTestResult>;
  generate(options: LLMGenerateOptions): Promise<LLMGenerateResult>;
}
