/**
 * Containerized CLI Agent Driver
 *
 * Implements the AgentDriver contract for containerized CLI agents.
 * Strictly operates within the dedicated Docker container sandbox (`aie-agent-sandbox`)
 * using the isolated vault volume (`aie-agent-vault`).
 * Zero host system binary or credential dependencies.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { AgentAuthOption, AgentDriver } from "./types";
import {
  AGY_AVAILABLE_MODELS,
  DEFAULT_AGY_MODEL,
  sanitizeAgyModel,
} from "./types";
import {
  generateAgyOAuthSession,
  exchangeOAuthCodeForToken,
} from "../marketplace-registry";
import {
  AGENT_CONTAINER_NAME,
  injectContainerOAuthToken,
  checkContainerOAuthToken,
  ensureAgentSandboxRunning,
  invalidateSandboxCache,
  removeContainerOAuthToken,
  runAgentPromptInSandbox,
} from "../agent-sandbox";
import { warmAgentService } from "../warm-agent-service";

const execFileAsync = promisify(execFile);
const CONTAINER_NAME = AGENT_CONTAINER_NAME;

export class ContainerizedCliAgentDriver implements AgentDriver {
  readonly id = "agy_agent";
  readonly name = "Autonomous AI Agent Engine";
  readonly providerLabel = "Google Gemini / Container Sandbox";
  readonly description =
    "Containerized autonomous threat intelligence agent running inside an isolated Docker sandbox with Google OAuth 2.0 and Vertex AI authentication.";

  readonly supportedAuthMethods: AgentAuthOption[] = [
    {
      id: "google_oauth",
      name: "Google OAuth 2.0",
      description: "Interactive single sign-on with your Google account via PKCE authorization portal.",
      type: "oauth",
      isRecommended: true,
    },
    {
      id: "vertex_api",
      name: "Vertex AI / Gemini API Key",
      description: "Direct API credential configuration for Google Cloud Vertex AI or Google AI Studio.",
      type: "api_key",
      isRecommended: false,
    },
  ];

  readonly defaultAuthMethod = "google_oauth";

  readonly supportedModels: string[] = AGY_AVAILABLE_MODELS.map((m) => m.id);

  readonly defaultModel = DEFAULT_AGY_MODEL;

  // PKCE verifier for the current authorization attempt. Server-side only;
  // the orchestrator also persists it as config.oauthCodeVerifier (redacted
  // before reaching the browser). Never taken from the client.
  private activeCodeVerifier: string | null = null;

  /**
   * Step 1: Ensure execution sandbox container is running with retry backoff
   */
  async startEnvironment(): Promise<{ success: boolean; error?: string }> {
    const maxRetries = 3;
    let lastError: string | undefined;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      invalidateSandboxCache();
      const res = await ensureAgentSandboxRunning();
      if (res.success) return { success: true };
      lastError = res.message;
      if (!res.status.dockerAvailable) break;
      if (attempt < maxRetries) {
        await new Promise((r) => setTimeout(r, 1200 * attempt));
      }
    }

    return {
      success: false,
      error: lastError || "Container sandbox failed to start after multiple attempts.",
    };
  }

  /**
   * Step 2 & 3: Validate agent binary inside container
   */
  async ensureInstalled(): Promise<{ success: boolean; version?: string; error?: string }> {
    try {
      const { stdout } = await execFileAsync("docker", ["exec", CONTAINER_NAME, "agy", "--version"], {
        timeout: 8000,
      });
      const version = stdout.trim();
      if (version) {
        return { success: true, version };
      }
      return { success: false, error: "Agent binary returned empty response." };
    } catch (err: any) {
      return {
        success: false,
        error: "Agent binary not ready inside container. Ensure container image is built.",
      };
    }
  }

  /**
   * Step 4: Boot agent process verification
   */
  async startAgentProcess(): Promise<{ success: boolean; error?: string }> {
    try {
      const { stdout } = await execFileAsync("docker", ["exec", CONTAINER_NAME, "which", "agy"], {
        timeout: 5000,
      });
      if (stdout.trim().includes("agy")) {
        return { success: true };
      }
      return { success: false, error: "Agent executable not located in system path." };
    } catch (err: any) {
      return {
        success: false,
        error: "Agent process initialization failed inside sandbox.",
      };
    }
  }

  /**
   * Step 5 & 6: Generate authentication session / link
   */
  async generateAuthSession(methodId: string): Promise<{
    authUrl: string;
    state?: string;
    codeVerifier?: string;
    error?: string;
  }> {
    if (methodId === "google_oauth") {
      const session = generateAgyOAuthSession();
      this.activeCodeVerifier = session.codeVerifier;
      return {
        authUrl: session.authUrl,
        state: session.state,
        codeVerifier: session.codeVerifier,
      };
    }

    if (methodId === "vertex_api") {
      return {
        authUrl: "https://console.cloud.google.com/apis/credentials",
        state: "vertex_manual_key",
      };
    }

    return {
      authUrl: "",
      error: `Unsupported authentication method: ${methodId}`,
    };
  }

  /**
   * Step 8: Submit code or API key to finalize authentication
   */
  async submitAuthCode(
    codeOrKey: string,
    options?: { codeVerifier?: string; methodId?: string }
  ): Promise<{ success: boolean; error?: string }> {
    const trimmed = (codeOrKey || "").trim();
    if (!trimmed) {
      return { success: false, error: "Authorization credential cannot be empty." };
    }

    const methodId = options?.methodId || this.defaultAuthMethod;

    // Google OAuth authorization code (4/0... or a callback URL containing code=)
    if (methodId === "google_oauth" || trimmed.startsWith("4/") || trimmed.includes("code=")) {
      // options.codeVerifier is supplied by the orchestrator from server-side
      // state (config.oauthCodeVerifier), never from the client request.
      const verifier = options?.codeVerifier || this.activeCodeVerifier;
      if (!verifier) {
        return {
          success: false,
          error: "No pending authorization session. Generate a new sign-in link and try again.",
        };
      }
      const exchangeRes = await exchangeOAuthCodeForToken(trimmed, verifier);
      if (!exchangeRes.success || !exchangeRes.token) {
        // Never store the raw authorization code as a credential.
        return {
          success: false,
          error: exchangeRes.error || "Failed to exchange authorization code with Google OAuth.",
        };
      }

      const injectRes = injectContainerOAuthToken(exchangeRes.token);
      if (!injectRes.success) {
        return { success: false, error: injectRes.message };
      }
      this.activeCodeVerifier = null;
      return { success: true };
    }

    // Vertex AI / Gemini API key (or a JSON credential payload)
    if (methodId === "vertex_api") {
      let payload: any;
      try {
        payload = JSON.parse(trimmed);
      } catch {
        payload = {
          token: {
            access_token: trimmed,
            token_type: "Bearer",
            refresh_token: "",
            expiry: new Date(Date.now() + 86400000).toISOString(),
          },
          auth_method: "vertex",
        };
      }
      const injectRes = injectContainerOAuthToken(payload);
      return { success: injectRes.success, error: injectRes.success ? undefined : injectRes.message };
    }

    return { success: false, error: `Unsupported authentication method: ${methodId}` };
  }

  /**
   * Step 9: Validate connection with a lightweight probe
   */
  async testConnection(): Promise<{
    success: boolean;
    latencyMs?: number;
    version?: string;
    error?: string;
  }> {
    const startTime = Date.now();
    try {
      // First verify binary and version
      const { stdout: vOut } = await execFileAsync("docker", ["exec", CONTAINER_NAME, "agy", "--version"], {
        timeout: 6000,
      });
      const version = vOut.trim();

      // Check credentials file in vault
      const tokenStatus = checkContainerOAuthToken();
      if (!tokenStatus.exists) {
        return {
          success: false,
          latencyMs: Date.now() - startTime,
          version,
          error: "Agent is installed but requires authentication.",
        };
      }

      // Dispatch a tiny probe (print mode, stdin, no tools) to verify inference
      const probe = await runAgentPromptInSandbox("Reply with the single word: pong", {
        timeoutMs: 20000,
        category: "auth",
      });
      if (!probe.success && /auth/i.test(probe.error || "")) {
        return {
          success: false,
          latencyMs: Date.now() - startTime,
          version,
          error: "Authentication expired or invalid. Please re-authenticate.",
        };
      }

      const latencyMs = Date.now() - startTime;
      return {
        success: true,
        latencyMs,
        version,
      };
    } catch (err: any) {
      return {
        success: false,
        latencyMs: Date.now() - startTime,
        error: err?.message || "Connection to agent container failed.",
      };
    }
  }

  /**
   * Check if credentials currently exist in container vault
   */
  async checkCredentials(): Promise<{
    hasCredentials: boolean;
    tokenPreview?: string;
    expiry?: string;
  }> {
    const status = checkContainerOAuthToken();
    return {
      hasCredentials: status.exists,
      tokenPreview: status.tokenPreview,
      expiry: status.expiry,
    };
  }

  /**
   * Execute prompt or inference via warm container agent session
   */
  async executeInference(
    prompt: string,
    model?: string
  ): Promise<{ text: string; latencyMs: number; error?: string }> {
    const targetModel = sanitizeAgyModel(model || this.defaultModel);
    const result = await warmAgentService.executePrompt(prompt, { model: targetModel });
    return {
      text: result.text,
      latencyMs: result.latencyMs,
      error: result.error,
    };
  }

  /**
   * Reset credentials and container vault
   */
  async reset(): Promise<{ success: boolean; error?: string }> {
    this.activeCodeVerifier = null;
    return removeContainerOAuthToken();
  }
}
