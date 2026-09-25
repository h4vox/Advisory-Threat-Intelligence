/**
 * Google Gemini REST API Direct Adapter
 *
 * High-speed native HTTPS client for Google Gemini Generative Language APIs.
 * Supports zero-binary serverless execution, structured JSON mode, system instructions,
 * and live credential testing.
 */

import type {
  AIProviderAdapter,
  LLMGenerateOptions,
  LLMGenerateResult,
  LLMMessage,
  ProviderConnectionTestResult,
} from "./types";

const GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta";
const DEFAULT_MODEL = "gemini-2.5-flash";

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
  // Standardize common Gemini model aliases
  if (clean === "gemini-3.8-flash-low" || clean === "gemini-flash" || clean === "gemini-2.5-flash") {
    return "gemini-2.5-flash";
  }
  if (clean === "gemini-3.8-pro" || clean === "gemini-pro" || clean === "gemini-2.5-pro") {
    return "gemini-2.5-pro";
  }
  return clean;
}

export class GeminiRestAdapter implements AIProviderAdapter {
  id = "gemini_api";
  name = "Google Gemini API";

  /**
   * Performs an authentic HTTPS reachability and credential probe against Google AI Studio
   */
  async testConnection(apiKey?: string, config?: Record<string, any>): Promise<ProviderConnectionTestResult> {
    const startTime = Date.now();
    const effectiveKey = apiKey || config?.apiKey || process.env.GEMINI_API_KEY;
    const modelToTest = normalizeModel(config?.selectedModel);
    const logs: string[] = [];

    const addLog = (level: string, msg: string) => {
      logs.push(`${getTimestamp()} [${level.padEnd(5)}] [GEMINI-REST] ${msg}`);
    };

    addLog("INFO", "Initiating live HTTPS TLSv1.3 connection to Google AI Studio APIs...");
    addLog("DEBUG", `Target Endpoint: ${GEMINI_BASE_URL}/models/${modelToTest}:generateContent`);

    if (!effectiveKey) {
      addLog("ERROR", "No API key provided. Set GEMINI_API_KEY or configure API key in Marketplace.");
      return {
        success: false,
        providerId: this.id,
        providerName: this.name,
        status: "invalid_key",
        latencyMs: Date.now() - startTime,
        message: "Google Gemini API key missing. Please provide a valid Gemini API key.",
        modelTested: modelToTest,
        testedAt: new Date().toISOString(),
        logs,
      };
    }

    addLog("AUTH", `API key detected (prefix: ${effectiveKey.slice(0, 6)}...${effectiveKey.slice(-4)})`);
    addLog("EXEC", `Dispatching live lightweight probe to verify quota & authentication...`);

    try {
      const url = `${GEMINI_BASE_URL}/models/${modelToTest}:generateContent?key=${encodeURIComponent(effectiveKey)}`;
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 12000);

      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [{ parts: [{ text: "Ping: Respond with single word 'OK'." }] }],
          generationConfig: {
            temperature: 0,
            maxOutputTokens: 10,
          },
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
        addLog("ERROR", `Google AI Studio returned HTTP ${response.status}: ${errMsg}`);

        const isAuthError = response.status === 400 && errMsg.includes("API key not valid") || response.status === 403;
        const isQuotaError = response.status === 429;

        return {
          success: false,
          providerId: this.id,
          providerName: this.name,
          status: isAuthError ? "invalid_key" : isQuotaError ? "rate_limited" : "error",
          latencyMs,
          message: `Google Gemini API Error (${response.status}): ${errMsg}`,
          modelTested: modelToTest,
          testedAt: new Date().toISOString(),
          details: parsedErr?.error || { status: response.status },
          logs,
        };
      }

      const data = await response.json();
      const reply = data?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || "";
      addLog("INFO", `Authentication & Model probe SUCCESSFUL. Latency: ${latencyMs}ms. Response: "${reply}"`);
      addLog("INFO", `Model '${modelToTest}' verified active and ready for CTI operations.`);

      return {
        success: true,
        providerId: this.id,
        providerName: this.name,
        status: "healthy",
        latencyMs,
        message: `Successfully connected to Google Gemini API (${modelToTest}). Round-trip latency: ${latencyMs}ms.`,
        modelTested: modelToTest,
        testedAt: new Date().toISOString(),
        details: {
          model: modelToTest,
          tokenUsage: data?.usageMetadata,
        },
        logs,
      };
    } catch (err: any) {
      const latencyMs = Date.now() - startTime;
      const isAbort = err.name === "AbortError";
      const msg = isAbort ? "Request timed out after 12s" : err.message || "Network error connecting to Gemini API";
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

  /**
   * Generates text or structured JSON from Google Gemini
   */
  async generate(options: LLMGenerateOptions): Promise<LLMGenerateResult> {
    const startTime = Date.now();
    const effectiveKey = options.apiKey || process.env.GEMINI_API_KEY;
    const model = normalizeModel(options.model);
    const timeoutMs = options.timeoutMs || 45000;

    if (!effectiveKey) {
      return {
        success: false,
        text: "",
        model,
        providerId: this.id,
        latencyMs: Date.now() - startTime,
        error: "Missing Google Gemini API key.",
      };
    }

    try {
      const url = `${GEMINI_BASE_URL}/models/${model}:generateContent?key=${encodeURIComponent(effectiveKey)}`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);

      // Build contents payload
      const contents: Array<{ role: string; parts: Array<{ text: string }> }> = [];

      if (typeof options.prompt === "string") {
        contents.push({
          role: "user",
          parts: [{ text: options.prompt }],
        });
      } else if (Array.isArray(options.prompt)) {
        for (const msg of options.prompt) {
          contents.push({
            role: msg.role === "assistant" ? "model" : "user",
            parts: [{ text: msg.content }],
          });
        }
      }

      const requestBody: Record<string, any> = {
        contents,
        generationConfig: {
          temperature: options.temperature ?? 0.2,
          maxOutputTokens: options.maxTokens ?? 4096,
        },
      };

      if (options.systemInstruction) {
        requestBody.system_instruction = {
          parts: [{ text: options.systemInstruction }],
        };
      }

      if (options.responseFormat === "json") {
        requestBody.generationConfig.responseMimeType = "application/json";
      }

      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
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
          error: `Gemini API error (HTTP ${response.status}): ${errorText.slice(0, 300)}`,
        };
      }

      const data = await response.json();
      const text = data?.candidates?.[0]?.content?.parts?.[0]?.text || "";
      const usage = data?.usageMetadata;

      return {
        success: true,
        text,
        model,
        providerId: this.id,
        latencyMs,
        tokens: usage
          ? {
              inputTokens: usage.promptTokenCount || 0,
              outputTokens: usage.candidatesTokenCount || 0,
              totalTokens: usage.totalTokenCount || 0,
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
        error: err.name === "AbortError" ? `Gemini API timed out after ${timeoutMs}ms` : err.message || "Unknown Gemini API error",
      };
    }
  }
}
