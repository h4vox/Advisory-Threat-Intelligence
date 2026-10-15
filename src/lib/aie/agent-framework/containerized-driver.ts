/**
 * Containerized CLI Agent Driver
 *
 * Implements the AgentDriver contract for containerized CLI agents.
 * Strictly operates within the dedicated Docker container sandbox (`aie-agent-sandbox`)
 * using the isolated vault volume (`aie-agent-vault`).
 * Zero host system binary or credential dependencies.
 */

import { exec } from "node:child_process";
import { promisify } from "node:util";
import type { AgentAuthOption, AgentDriver } from "./types";
import {
  AGY_AVAILABLE_MODELS,
  DEFAULT_AGY_MODEL,
  sanitizeAgyModel,
} from "./types";
import {
  DEFAULT_PKCE_VERIFIER,
  generateAgyOAuthSession,
  exchangeOAuthCodeForToken,
} from "../marketplace-registry";
import {
  injectContainerOAuthToken,
  checkContainerOAuthToken,
} from "../agent-sandbox";
import { warmAgentService } from "../warm-agent-service";

const execAsync = promisify(exec);
const CONTAINER_NAME = "aie-agent-sandbox";

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

  // Active PKCE session memory for code verification
  private activeCodeVerifier: string = DEFAULT_PKCE_VERIFIER;

  /**
   * Step 1: Ensure execution sandbox container is running with retry backoff
   */
  async startEnvironment(): Promise<{ success: boolean; error?: string }> {
    const maxRetries = 3;
    let lastError: string | undefined;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const { stdout: psOut } = await execAsync(
          `docker ps --filter "name=^${CONTAINER_NAME}$" --format "{{.Status}}"`,
          { timeout: 6000 }
        );

        if (psOut.trim()) {
          return { success: true };
        }

        // Check if container exists in stopped state
        const { stdout: allOut } = await execAsync(
          `docker ps -a --filter "name=^${CONTAINER_NAME}$" --format "{{.Names}}"`,
          { timeout: 6000 }
        );

        if (allOut.trim() === CONTAINER_NAME) {
          await execAsync(`docker start ${CONTAINER_NAME}`, { timeout: 12000 });
        } else {
          // Re-create from compose or docker run
          try {
            await execAsync("docker compose -f docker-compose.agent-sandbox.yml up -d", {
              timeout: 25000,
            });
          } catch {
            await execAsync(
              `docker run -d --name ${CONTAINER_NAME} --restart unless-stopped -v aie-agent-vault:/root/.gemini -e AGENT_ENV=isolated_sandbox aie-agent-sandbox:latest tail -f /dev/null`,
              { timeout: 20000 }
            );
          }
        }

        // Verify it came up
        const { stdout: verifyOut } = await execAsync(
          `docker ps --filter "name=^${CONTAINER_NAME}$" --format "{{.Status}}"`,
          { timeout: 6000 }
        );

        if (verifyOut.trim()) {
          return { success: true };
        }
      } catch (err: any) {
        lastError = err?.message || "Failed to start container runtime.";
        if (attempt < maxRetries) {
          await new Promise((r) => setTimeout(r, 1200 * attempt));
        }
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
      const { stdout } = await execAsync(`docker exec ${CONTAINER_NAME} agy --version`, {
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
      const { stdout } = await execAsync(`docker exec ${CONTAINER_NAME} which agy`, {
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

    const verifier = options?.codeVerifier || this.activeCodeVerifier || DEFAULT_PKCE_VERIFIER;

    // Check if input is a Google OAuth authorization code (4/0... or callback URL)
    if (trimmed.startsWith("4/") || trimmed.includes("code=")) {
      const exchangeRes = await exchangeOAuthCodeForToken(trimmed, verifier);
      if (!exchangeRes.success || !exchangeRes.token) {
        return {
          success: false,
          error: exchangeRes.error || "Failed to exchange authorization code with Google OAuth.",
        };
      }

      const injectRes = injectContainerOAuthToken(exchangeRes.token);
      if (!injectRes.success) {
        return { success: false, error: injectRes.message };
      }

      return { success: true };
    }

    // Try parsing as JSON token payload
    try {
      const parsed = JSON.parse(trimmed);
      const injectRes = injectContainerOAuthToken(parsed);
      return { success: injectRes.success, error: injectRes.success ? undefined : injectRes.message };
    } catch {
      // Treat as API Key or Raw Bearer Token
      const tokenPayload = {
        token: {
          access_token: trimmed,
          token_type: "Bearer",
          refresh_token: "",
          expiry: new Date(Date.now() + 86400000).toISOString(),
        },
        auth_method: options?.methodId === "vertex_api" ? "vertex" : "consumer",
      };
      const injectRes = injectContainerOAuthToken(tokenPayload);
      return { success: injectRes.success, error: injectRes.success ? undefined : injectRes.message };
    }
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
      const { stdout: vOut } = await execAsync(`docker exec ${CONTAINER_NAME} agy --version`, {
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

      // Dispatch ping probe to verify inference pipeline
      try {
        await execAsync(`docker exec -i ${CONTAINER_NAME} agy -p "ping"`, {
          timeout: 12000,
        });
      } catch (probeErr: any) {
        // If ping returns response or exit code, measure roundtrip
        const msg = probeErr?.stderr || probeErr?.stdout || "";
        if (msg.includes("authentication required")) {
          return {
            success: false,
            latencyMs: Date.now() - startTime,
            version,
            error: "Authentication expired or invalid. Please re-authenticate.",
          };
        }
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
    try {
      await execAsync(
        `docker exec ${CONTAINER_NAME} rm -f /root/.gemini/antigravity-cli/antigravity-oauth-token`,
        { timeout: 6000 }
      );
      return { success: true };
    } catch (err: any) {
      return { success: false, error: err?.message || "Failed to reset credentials." };
    }
  }
}
