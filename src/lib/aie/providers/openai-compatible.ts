/**
 * OpenAI-compatible REST adapter (configurable).
 *
 * Most hosted providers speak the OpenAI Chat Completions API: OpenRouter, xAI (Grok), DeepSeek,
 * Together, Groq, local servers (Ollama, vLLM) and OpenAI itself. One parameterized adapter serves
 * them all — only the base URL, default model and auth key differ. This is the direct, fast path:
 * a single HTTPS round trip per call, no container, no CLI.
 *
 * Fixed-host providers (OpenRouter / xAI / DeepSeek) set their base URL here, so a request never
 * reaches an arbitrary host. A provider that allows a user-supplied `endpointUrl` must pass
 * `allowCustomEndpoint` and the URL is checked against the host allowlist (see redact.ts).
 */
import { isAllowedProviderEndpoint } from "../redact.ts";
import type {
  AIProviderAdapter,
  LLMGenerateOptions,
  LLMGenerateResult,
  LLMMessage,
  ProviderConnectionTestResult,
} from "./types.ts";

export type OpenAiCompatibleConfig = {
  id: string;
  name: string;
  /** Base URL up to and including `/v1` (no trailing `/chat/completions`). */
  baseUrl: string;
  defaultModel: string;
  /** Environment variables to read the key from, in order. */
  envKeys?: string[];
  /** Extra request headers (e.g. OpenRouter's HTTP-Referer / X-Title). */
  headers?: Record<string, string>;
  /** Allow a per-install `endpointUrl` override (checked against the allowlist). */
  allowCustomEndpoint?: boolean;
};

function ts(): string {
  const n = new Date();
  const p = (x: number, s = 2) => x.toString().padStart(s, "0");
  return `[${n.getFullYear()}-${p(n.getMonth() + 1)}-${p(n.getDate())} ${p(n.getHours())}:${p(n.getMinutes())}:${p(n.getSeconds())}.${p(n.getMilliseconds(), 3)}]`;
}

export class OpenAiCompatibleAdapter implements AIProviderAdapter {
  readonly id: string;
  readonly name: string;
  private readonly cfg: OpenAiCompatibleConfig;

  constructor(cfg: OpenAiCompatibleConfig) {
    this.id = cfg.id;
    this.name = cfg.name;
    this.cfg = cfg;
  }

  private model(requested?: string): string {
    const clean = (requested ?? "").trim();
    if (!clean) return this.cfg.defaultModel;
    // Strip a "Provider: " display prefix, but keep OpenRouter "vendor/model" slashes.
    const afterColon = clean.includes(": ") ? clean.slice(clean.indexOf(": ") + 2).trim() : clean;
    return afterColon || this.cfg.defaultModel;
  }

  private resolveBase(endpointUrl?: string): string {
    if (endpointUrl && this.cfg.allowCustomEndpoint) {
      if (!isAllowedProviderEndpoint(endpointUrl)) {
        throw new Error("Endpoint is not on the approved provider host list (set AIE_ALLOWED_LLM_HOSTS).");
      }
      return endpointUrl.replace(/\/+$/, "");
    }
    return this.cfg.baseUrl.replace(/\/+$/, "");
  }

  private key(apiKey?: string, config?: Record<string, unknown>): string | undefined {
    const fromConfig = typeof config?.apiKey === "string" ? (config.apiKey as string) : undefined;
    const fromEnv = (this.cfg.envKeys ?? []).map((k) => process.env[k]?.trim()).find(Boolean);
    return apiKey || fromConfig || fromEnv || undefined;
  }

  private authHeaders(key?: string): Record<string, string> {
    return { "Content-Type": "application/json", ...(this.cfg.headers ?? {}), ...(key ? { Authorization: `Bearer ${key}` } : {}) };
  }

  private isLocal(base: string): boolean {
    return base.includes("localhost") || base.includes("127.0.0.1");
  }

  async testConnection(apiKey?: string, config?: Record<string, unknown>): Promise<ProviderConnectionTestResult> {
    const start = Date.now();
    const logs: string[] = [];
    const log = (level: string, msg: string) => logs.push(`${ts()} [${level.padEnd(5)}] [${this.id.toUpperCase()}] ${msg}`);
    let base: string;
    try {
      base = this.resolveBase(typeof config?.endpointUrl === "string" ? (config.endpointUrl as string) : undefined);
    } catch (err) {
      return { success: false, providerId: this.id, providerName: this.name, status: "error", latencyMs: 0, message: err instanceof Error ? err.message : "Bad endpoint", testedAt: new Date().toISOString(), logs };
    }
    const key = this.key(apiKey, config);
    const model = this.model(typeof config?.selectedModel === "string" ? (config.selectedModel as string) : undefined);
    log("INFO", `Checking ${this.name} at ${base} (${model})…`);
    if (!key && !this.isLocal(base)) {
      return { success: false, providerId: this.id, providerName: this.name, status: "invalid_key", latencyMs: Date.now() - start, message: "Add an API key to connect.", modelTested: model, testedAt: new Date().toISOString(), logs };
    }
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 12000);
      const res = await fetch(`${base}/chat/completions`, {
        method: "POST",
        headers: this.authHeaders(key),
        body: JSON.stringify({ model, messages: [{ role: "user", content: "Reply with the single word OK." }], max_tokens: 10, temperature: 0 }),
        signal: controller.signal,
      });
      clearTimeout(timer);
      const latencyMs = Date.now() - start;
      if (!res.ok) {
        const body = await res.text();
        let msg = body;
        try {
          msg = JSON.parse(body)?.error?.message || body;
        } catch {
          /* non-JSON error body */
        }
        log("ERROR", `HTTP ${res.status}: ${msg}`);
        return {
          success: false,
          providerId: this.id,
          providerName: this.name,
          status: res.status === 401 || res.status === 403 ? "invalid_key" : res.status === 429 ? "rate_limited" : "error",
          latencyMs,
          message: `${res.status === 401 || res.status === 403 ? "The API key was rejected" : res.status === 429 ? "Rate limited" : `Error ${res.status}`}: ${String(msg).slice(0, 200)}`,
          modelTested: model,
          testedAt: new Date().toISOString(),
          logs,
        };
      }
      const data = await res.json();
      log("INFO", `Connected in ${latencyMs}ms.`);
      return { success: true, providerId: this.id, providerName: this.name, status: "healthy", latencyMs, message: `Connected to ${this.name} (${model}) in ${latencyMs}ms.`, modelTested: model, testedAt: new Date().toISOString(), details: { model, tokenUsage: data?.usage }, logs };
    } catch (err) {
      const e = err as { name?: string; message?: string };
      const msg = e.name === "AbortError" ? "Timed out after 12s" : e.message || "Network error";
      log("ERROR", msg);
      return { success: false, providerId: this.id, providerName: this.name, status: "unreachable", latencyMs: Date.now() - start, message: `Could not reach ${this.name}: ${msg}`, modelTested: model, testedAt: new Date().toISOString(), logs };
    }
  }

  async generate(options: LLMGenerateOptions): Promise<LLMGenerateResult> {
    const start = Date.now();
    const model = this.model(options.model);
    let base: string;
    try {
      base = this.resolveBase(options.endpointUrl);
    } catch (err) {
      return { success: false, text: "", model, providerId: this.id, latencyMs: 0, error: err instanceof Error ? err.message : "Bad endpoint" };
    }
    const key = this.key(options.apiKey);
    const timeoutMs = options.timeoutMs || 45000;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      const stop = () => controller.abort();
      if (options.signal?.aborted) controller.abort();
      else options.signal?.addEventListener("abort", stop, { once: true });
      const messages: LLMMessage[] = [];
      if (options.systemInstruction) messages.push({ role: "system", content: options.systemInstruction });
      if (typeof options.prompt === "string") messages.push({ role: "user", content: options.prompt });
      else if (Array.isArray(options.prompt)) messages.push(...options.prompt);

      const body: Record<string, unknown> = { model, messages, temperature: options.temperature ?? 0.2, max_tokens: options.maxTokens ?? 4096 };
      if (options.responseFormat === "json") body.response_format = { type: "json_object" };

      const res = await fetch(`${base}/chat/completions`, { method: "POST", headers: this.authHeaders(key), body: JSON.stringify(body), signal: controller.signal });
      clearTimeout(timer);
      const latencyMs = Date.now() - start;
      if (!res.ok) {
        const errText = await res.text();
        return { success: false, text: "", model, providerId: this.id, latencyMs, error: `API error (HTTP ${res.status}): ${errText.slice(0, 300)}` };
      }
      const data = await res.json();
      const text = data?.choices?.[0]?.message?.content || "";
      const usage = data?.usage;
      return {
        success: true,
        text,
        model,
        providerId: this.id,
        latencyMs,
        tokens: usage ? { inputTokens: usage.prompt_tokens || 0, outputTokens: usage.completion_tokens || 0, totalTokens: usage.total_tokens || 0 } : undefined,
        rawResponse: data,
      };
    } catch (err) {
      const e = err as { name?: string; message?: string };
      return { success: false, text: "", model, providerId: this.id, latencyMs: Date.now() - start, error: options.signal?.aborted ? "Stopped" : e.name === "AbortError" ? `Timed out after ${timeoutMs}ms` : e.message || "Unknown API error" };
    }
  }
}
