/**
 * OpenAI & Local LLM REST API Direct Adapter
 *
 * High-speed native HTTPS client for OpenAI-compatible APIs (OpenAI, Azure OpenAI,
 * Ollama, vLLM, and self-hosted air-gapped models).
 */

import type {
  AIProviderAdapter,
  LLMGenerateOptions,
  LLMGenerateResult,
  LLMMessage,
  ProviderConnectionTestResult,
} from "./types";

const DEFAULT_OPENAI_URL = "https://api.openai.com/v1";
const DEFAULT_MODEL = "gpt-4o";

function getTimestamp(): string {
  const now = new Date();
  const pad = (n: number, s = 2) => n.toString().padStart(s, "0");
  return `[${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}.${pad(now.getMilliseconds(), 3)}]`;
}

function normalizeModel(model?: string): string {
  if (!model) return DEFAULT_MODEL;
  let clean = model.trim();
  if (clean.includes(":")) {
    clean = clean.split(":").pop()?.trim() || DEFAULT_MODEL;
  }
  return clean;
}

export class OpenAiRestAdapter implements AIProviderAdapter {
  id = "openai_api";
  name = "OpenAI & Local LLM API";

  async testConnection(apiKey?: string, config?: Record<string, any>): Promise<ProviderConnectionTestResult> {
    const startTime = Date.now();
    const effectiveKey = apiKey || config?.apiKey || process.env.OPENAI_API_KEY;
    const baseUrl = config?.endpointUrl || process.env.OPENAI_BASE_URL || DEFAULT_OPENAI_URL;
    const modelToTest = normalizeModel(config?.selectedModel);
    const logs: string[] = [];

    const addLog = (level: string, msg: string) => {
      logs.push(`${getTimestamp()} [${level.padEnd(5)}] [OPENAI-REST] ${msg}`);
    };

    addLog("INFO", `Initiating live connection to OpenAI-compatible endpoint: ${baseUrl}...`);

    if (!effectiveKey && !baseUrl.includes("localhost") && !baseUrl.includes("127.0.0.1")) {
      addLog("ERROR", "No API key provided. Set OPENAI_API_KEY or configure API key in Marketplace.");
      return {
        success: false,
        providerId: this.id,
        providerName: this.name,
        status: "invalid_key",
        latencyMs: Date.now() - startTime,
        message: "API key missing. Please provide a valid OpenAI API key or use a local unauthenticated endpoint.",
        modelTested: modelToTest,
        testedAt: new Date().toISOString(),
        logs,
      };
    }

    addLog("EXEC", `Dispatching live probe to verify model '${modelToTest}' reachability...`);

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 12000);

      const response = await fetch(`${baseUrl.replace(/\/+$/, "")}/chat/completions`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(effectiveKey ? { Authorization: `Bearer ${effectiveKey}` } : {}),
        },
        body: JSON.stringify({
          model: modelToTest,
          messages: [{ role: "user", content: "Ping: Respond with single word 'OK'." }],
          max_tokens: 10,
          temperature: 0,
        }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);
      const latencyMs = Date.now() - startTime;

      if (!response.ok) {
        const errorBody = await response.text();
        let parsedErr: any;
        try {
          parsedErr = JSON.parse(errorBody);
        } catch {}

        const errMsg = parsedErr?.error?.message || errorBody || `HTTP ${response.status}`;
        addLog("ERROR", `API returned HTTP ${response.status}: ${errMsg}`);

        return {
          success: false,
          providerId: this.id,
          providerName: this.name,
          status: response.status === 401 ? "invalid_key" : response.status === 429 ? "rate_limited" : "error",
          latencyMs,
          message: `API Error (${response.status}): ${errMsg}`,
          modelTested: modelToTest,
          testedAt: new Date().toISOString(),
          logs,
        };
      }

      const data = await response.json();
      const reply = data?.choices?.[0]?.message?.content?.trim() || "";
      addLog("INFO", `Probe SUCCESSFUL. Latency: ${latencyMs}ms. Response: "${reply}"`);

      return {
        success: true,
        providerId: this.id,
        providerName: this.name,
        status: "healthy",
        latencyMs,
        message: `Successfully connected to endpoint (${modelToTest}). Round-trip latency: ${latencyMs}ms.`,
        modelTested: modelToTest,
        testedAt: new Date().toISOString(),
        details: {
          model: modelToTest,
          tokenUsage: data?.usage,
        },
        logs,
      };
    } catch (err: any) {
      const latencyMs = Date.now() - startTime;
      const isAbort = err.name === "AbortError";
      const msg = isAbort ? "Request timed out after 12s" : err.message || "Network error connecting to endpoint";
      addLog("ERROR", `Connection failure: ${msg}`);

      return {
        success: false,
        providerId: this.id,
        providerName: this.name,
        status: "unreachable",
        latencyMs,
        message: `Connection failed: ${msg}`,
        modelTested: modelToTest,
        testedAt: new Date().toISOString(),
        logs,
      };
    }
  }

  async generate(options: LLMGenerateOptions): Promise<LLMGenerateResult> {
    const startTime = Date.now();
    const effectiveKey = options.apiKey || process.env.OPENAI_API_KEY;
    const baseUrl = options.endpointUrl || process.env.OPENAI_BASE_URL || DEFAULT_OPENAI_URL;
    const model = normalizeModel(options.model);
    const timeoutMs = options.timeoutMs || 45000;

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);

      const messages: LLMMessage[] = [];

      if (options.systemInstruction) {
        messages.push({ role: "system", content: options.systemInstruction });
      }

      if (typeof options.prompt === "string") {
        messages.push({ role: "user", content: options.prompt });
      } else if (Array.isArray(options.prompt)) {
        messages.push(...options.prompt);
      }

      const requestBody: Record<string, any> = {
        model,
        messages,
        temperature: options.temperature ?? 0.2,
        max_tokens: options.maxTokens ?? 4096,
      };

      if (options.responseFormat === "json") {
        requestBody.response_format = { type: "json_object" };
      }

      const response = await fetch(`${baseUrl.replace(/\/+$/, "")}/chat/completions`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(effectiveKey ? { Authorization: `Bearer ${effectiveKey}` } : {}),
        },
        body: JSON.stringify(requestBody),
        signal: controller.signal,
      });

      clearTimeout(timer);
      const latencyMs = Date.now() - startTime;

      if (!response.ok) {
        const errorText = await response.text();
        return {
          success: false,
          text: "",
          model,
          providerId: this.id,
          latencyMs,
          error: `API error (HTTP ${response.status}): ${errorText.slice(0, 300)}`,
        };
      }

      const data = await response.json();
      const text = data?.choices?.[0]?.message?.content || "";
      const usage = data?.usage;

      return {
        success: true,
        text,
        model,
        providerId: this.id,
        latencyMs,
        tokens: usage
          ? {
              inputTokens: usage.prompt_tokens || 0,
              outputTokens: usage.completion_tokens || 0,
              totalTokens: usage.total_tokens || 0,
            }
          : undefined,
        rawResponse: data,
      };
    } catch (err: any) {
      return {
        success: false,
        text: "",
        model,
        providerId: this.id,
        latencyMs: Date.now() - startTime,
        error: err.name === "AbortError" ? `API timed out after ${timeoutMs}ms` : err.message || "Unknown API error",
      };
    }
  }
}
