/**
 * Anthropic Claude REST API Direct Adapter
 *
 * High-speed native HTTPS client for Anthropic Claude Messages API.
 * Supports zero-binary serverless execution, system instructions,
 * deep reasoning with Claude 3.7 Sonnet & 3.5 Haiku, and live credential testing.
 */

import type {
  AIProviderAdapter,
  LLMGenerateOptions,
  LLMGenerateResult,
  ProviderConnectionTestResult,
} from "./types";

const CLAUDE_BASE_URL = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION = "2023-06-01";
const DEFAULT_MODEL = "claude-3-7-sonnet-20250219";

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
  if (clean === "claude-3-7-sonnet" || clean === "claude-3-7") {
    return "claude-3-7-sonnet-20250219";
  }
  if (clean === "claude-3-5-haiku" || clean === "claude-haiku") {
    return "claude-3-5-haiku-20241022";
  }
  if (clean === "claude-3-5-sonnet") {
    return "claude-3-5-sonnet-20241022";
  }
  return clean;
}

export class ClaudeRestAdapter implements AIProviderAdapter {
  id = "claude_api";
  name = "Anthropic Claude API";

  /**
   * Performs an authentic HTTPS reachability and credential probe against Anthropic Console API
   */
  async testConnection(apiKey?: string, config?: Record<string, any>): Promise<ProviderConnectionTestResult> {
    const startTime = Date.now();
    const effectiveKey = apiKey || config?.apiKey || process.env.ANTHROPIC_API_KEY;
    const modelToTest = normalizeModel(config?.selectedModel);
    const logs: string[] = [];

    const addLog = (level: string, msg: string) => {
      logs.push(`${getTimestamp()} [${level.padEnd(5)}] [CLAUDE-REST] ${msg}`);
    };

    addLog("INFO", "Initiating live HTTPS TLSv1.3 connection to Anthropic Messages API...");
    addLog("DEBUG", `Target Endpoint: ${CLAUDE_BASE_URL} (API Version: ${ANTHROPIC_VERSION})`);

    if (!effectiveKey) {
      addLog("ERROR", "No API key provided. Set ANTHROPIC_API_KEY or configure API key in Marketplace.");
      return {
        success: false,
        providerId: this.id,
        providerName: this.name,
        status: "invalid_key",
        latencyMs: Date.now() - startTime,
        message: "Anthropic Claude API key missing. Please provide a valid Anthropic API key.",
        modelTested: modelToTest,
        testedAt: new Date().toISOString(),
        logs,
      };
    }

    addLog("AUTH", `API key detected (prefix: ${effectiveKey.slice(0, 10)}...${effectiveKey.slice(-4)})`);
    addLog("EXEC", `Dispatching live lightweight probe to verify authentication & model '${modelToTest}'...`);

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 12000);

      const response = await fetch(CLAUDE_BASE_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": effectiveKey,
          "anthropic-version": ANTHROPIC_VERSION,
        },
        body: JSON.stringify({
          model: modelToTest,
          max_tokens: 10,
          messages: [{ role: "user", content: "Ping: Respond with single word 'OK'." }],
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
        addLog("ERROR", `Anthropic API returned HTTP ${response.status}: ${errMsg}`);

        const isAuthError = response.status === 401 || response.status === 403;
        const isQuotaError = response.status === 429;

        return {
          success: false,
          providerId: this.id,
          providerName: this.name,
          status: isAuthError ? "invalid_key" : isQuotaError ? "rate_limited" : "error",
          latencyMs,
          message: `Anthropic Claude API Error (${response.status}): ${errMsg}`,
          modelTested: modelToTest,
          testedAt: new Date().toISOString(),
          details: parsedErr?.error || { status: response.status },
          logs,
        };
      }

      const data = await response.json();
      const reply = data?.content?.[0]?.text?.trim() || "";
      addLog("INFO", `Authentication & Model probe SUCCESSFUL. Latency: ${latencyMs}ms. Response: "${reply}"`);
      addLog("INFO", `Model '${modelToTest}' verified active and ready for CTI operations.`);

      return {
        success: true,
        providerId: this.id,
        providerName: this.name,
        status: "healthy",
        latencyMs,
        message: `Successfully connected to Anthropic Claude API (${modelToTest}). Round-trip latency: ${latencyMs}ms.`,
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
      const msg = isAbort ? "Request timed out after 12s" : err.message || "Network error connecting to Claude API";
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
   * Generates text from Anthropic Claude
   */
  async generate(options: LLMGenerateOptions): Promise<LLMGenerateResult> {
    const startTime = Date.now();
    const effectiveKey = options.apiKey || process.env.ANTHROPIC_API_KEY;
    const model = normalizeModel(options.model);
    const timeoutMs = options.timeoutMs || 45000;

    if (!effectiveKey) {
      return {
        success: false,
        text: "",
        model,
        providerId: this.id,
        latencyMs: Date.now() - startTime,
        error: "Missing Anthropic Claude API key.",
      };
    }

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);

      // Build messages array
      const messages: Array<{ role: "user" | "assistant"; content: string }> = [];

      if (typeof options.prompt === "string") {
        messages.push({
          role: "user",
          content: options.prompt,
        });
      } else if (Array.isArray(options.prompt)) {
        for (const msg of options.prompt) {
          if (msg.role === "system") continue;
          messages.push({
            role: msg.role === "assistant" ? "assistant" : "user",
            content: msg.content,
          });
        }
      }

      // Append JSON schema instruction if requested
      let systemInstruction = options.systemInstruction || "";
      if (options.responseFormat === "json" && !systemInstruction.toLowerCase().includes("json")) {
        systemInstruction = `${systemInstruction}\nYou MUST output valid pure JSON only. Do NOT wrap output in markdown code blocks.`.trim();
      }

      const requestBody: Record<string, any> = {
        model,
        max_tokens: options.maxTokens ?? 4096,
        temperature: options.temperature ?? 0.2,
        messages,
      };

      if (systemInstruction) {
        requestBody.system = systemInstruction;
      }

      const response = await fetch(CLAUDE_BASE_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": effectiveKey,
          "anthropic-version": ANTHROPIC_VERSION,
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
          error: `Claude API error (HTTP ${response.status}): ${errorText.slice(0, 300)}`,
        };
      }

      const data = await response.json();
      const text = data?.content?.[0]?.text || "";
      const usage = data?.usage;

      return {
        success: true,
        text,
        model,
        providerId: this.id,
        latencyMs,
        tokens: usage
          ? {
              inputTokens: usage.input_tokens || 0,
              outputTokens: usage.output_tokens || 0,
              totalTokens: (usage.input_tokens || 0) + (usage.output_tokens || 0),
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
        error: err.name === "AbortError" ? `Claude API timed out after ${timeoutMs}ms` : err.message || "Unknown Claude API error",
      };
    }
  }
}
