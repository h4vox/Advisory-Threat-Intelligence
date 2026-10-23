/**
 * Containerized CLI Agent Driver (Antigravity CLI, `agy`)
 *
 * Implements the AgentDriver contract inside the dedicated Docker sandbox (`aie-agent-sandbox`).
 * The image installs the CLI from Google's official installer; the container keeps the agent's home on
 * the `aie-agent-home` volume, where the CLI saves its own sign-in. Sign-in is the CLI's own Google
 * OAuth flow, driven through a pseudo-terminal (../agy-login.server): AIE relays the link and the code
 * and never handles Google tokens. No host binaries or host credentials are used.
 */

import type { AgentAuthOption, AgentDriver, AgentSignInProgress } from "./types";
import { AGY_AVAILABLE_MODELS, DEFAULT_AGY_MODEL, sanitizeAgyModel } from "./types";
import type { AgyLoginSnapshot } from "../agy-login";
import {
  cancelAgyLogin,
  getAgyLoginSnapshot,
  onAgyLoginChange,
  startAgyLogin,
  submitAgyLoginCode,
  verifyAgentAnswers,
} from "../agy-login.server";
import {
  agyVersionInContainer,
  buildAgentImage,
  dockerReachable,
  ensureAgentHomeWritable,
  imageExists,
  inspectContainer,
  removeAgentContainerAndHome,
  startAgentContainer,
} from "../agent-container.server";
import { warmAgentService } from "../warm-agent-service";

/** How long startSignIn waits for the CLI to show its link (or report it is signed in). */
const SIGN_IN_LINK_WAIT_MS = 45_000;

function toProgress(s: AgyLoginSnapshot): AgentSignInProgress {
  return { state: s.state, authUrl: s.authUrl, message: s.message, transcript: s.transcript, alreadySignedIn: s.alreadySignedIn };
}

export class ContainerizedCliAgentDriver implements AgentDriver {
  readonly id = "agy_agent";
  readonly name = "Antigravity Agent (AGY)";
  readonly providerLabel = "Google Antigravity CLI · Docker sandbox";
  readonly description =
    "The Antigravity CLI running in an isolated Docker sandbox, signed in with your Google account through the CLI's own sign-in.";

  readonly supportedAuthMethods: AgentAuthOption[] = [
    {
      id: "google_oauth",
      name: "Google account",
      description: "Sign in with Google through the Antigravity CLI's own sign-in. The CLI keeps the sign-in inside the sandbox.",
      type: "oauth",
      isRecommended: true,
    },
  ];

  readonly defaultAuthMethod = "google_oauth";
  readonly supportedModels: string[] = AGY_AVAILABLE_MODELS.map((m) => m.id);
  readonly defaultModel = DEFAULT_AGY_MODEL;

  /** Docker answers, and the sandbox image exists (built on first install). */
  async startEnvironment(onProgress?: (message: string) => void): Promise<{ success: boolean; error?: string }> {
    const docker = await dockerReachable();
    if (!docker.ok) {
      return { success: false, error: `${docker.detail}. The agent runs only inside its Docker sandbox; install or start Docker, then try again.` };
    }
    if (await imageExists()) return { success: true };
    onProgress?.("Building the agent sandbox image. The first build downloads the Antigravity CLI and can take a few minutes…");
    const built = await buildAgentImage();
    return built.ok ? { success: true } : { success: false, error: built.detail };
  }

  /**
   * The real CLI is in the image. An image holding only the fallback shim (built while the installer
   * could not be reached) is rebuilt once; if the CLI is still missing, the build's warning is reported.
   */
  async ensureInstalled(onProgress?: (message: string) => void): Promise<{ success: boolean; version?: string; error?: string }> {
    const started = await startAgentContainer();
    if (!started.ok) return { success: false, error: started.detail };
    let version = await agyVersionInContainer();
    if (version) return { success: true, version };

    onProgress?.("The sandbox has no Antigravity CLI yet. Rebuilding the image to install it (a few minutes)…");
    const built = await buildAgentImage();
    if (!built.ok) return { success: false, error: built.detail };
    const recreated = await startAgentContainer({ recreate: true });
    if (!recreated.ok) return { success: false, error: recreated.detail };
    version = await agyVersionInContainer();
    if (version) return { success: true, version };
    return {
      success: false,
      error:
        version === null
          ? "The agent container is not answering. Check Docker and try again."
          : `The Antigravity CLI could not be installed in the sandbox image: ${built.detail === "built" ? "the official installer did not produce a working agy binary" : built.detail}. Check that this machine can reach antigravity.google, then try again.`,
    };
  }

  /** The container runs the current image with the agent's home on its persistent volume. */
  async startAgentProcess(): Promise<{ success: boolean; error?: string }> {
    const info = await inspectContainer();
    // Containers from older versions kept the home on tmpfs, which loses the CLI's sign-in on restart.
    const res = info.exists && info.running && info.homeOnVolume ? { ok: true, detail: "running" } : await startAgentContainer({ recreate: info.exists && !info.homeOnVolume });
    if (!res.ok) return { success: false, error: res.detail };
    if (!(await agyVersionInContainer())) return { success: false, error: "The Antigravity CLI does not start inside the sandbox." };
    // The CLI keeps its settings and sign-in in ~/.gemini: the home volume must be writable.
    const home = await ensureAgentHomeWritable();
    return home.ok ? { success: true } : { success: false, error: home.detail };
  }

  /**
   * Starts the CLI's sign-in. A CLI that already answers a prompt is signed in, so no terminal is
   * needed; otherwise the CLI runs in a pseudo-terminal and picks "Google OAuth", and this resolves
   * once its sign-in link is on screen.
   */
  async startSignIn(_methodId: string): Promise<AgentSignInProgress> {
    const current = getAgyLoginSnapshot();
    if (current && (current.state === "awaiting_code" || current.state === "signing_in" || current.state === "verifying")) return toProgress(current);

    const probe = await verifyAgentAnswers();
    if (probe.ok) {
      return { state: "signed_in", authUrl: null, message: "Already signed in. The agent is ready.", transcript: "", alreadySignedIn: true };
    }

    await startAgyLogin({ restart: true });
    const end = Date.now() + SIGN_IN_LINK_WAIT_MS;
    for (;;) {
      const snap = getAgyLoginSnapshot();
      if (!snap) break;
      if (snap.state === "awaiting_code" || snap.state === "signed_in" || snap.state === "failed" || snap.state === "cancelled") return toProgress(snap);
      if (Date.now() > end) {
        cancelAgyLogin();
        const tailLines = snap.transcript.trim().split("\n").filter(Boolean).slice(-3).join(" · ");
        return {
          state: "failed",
          authUrl: null,
          message: `The Antigravity CLI did not show its sign-in link within ${SIGN_IN_LINK_WAIT_MS / 1000} s.${tailLines ? ` Last output: ${tailLines}` : ""}`,
          transcript: snap.transcript,
          alreadySignedIn: false,
        };
      }
      await new Promise((r) => setTimeout(r, 250));
    }
    return { state: "failed", authUrl: null, message: "The sign-in did not start.", transcript: "", alreadySignedIn: false };
  }

  getSignIn(): AgentSignInProgress | null {
    const snap = getAgyLoginSnapshot();
    return snap ? toProgress(snap) : null;
  }

  submitSignInCode(code: string): { success: boolean; error?: string } {
    const res = submitAgyLoginCode(code);
    return res.ok ? { success: true } : { success: false, error: res.error };
  }

  cancelSignIn(): void {
    cancelAgyLogin();
  }

  onSignInChange(listener: (progress: AgentSignInProgress) => void): () => void {
    return onAgyLoginChange((snap) => listener(toProgress(snap)));
  }

  /** A real prompt through the agent (print mode, no tools). */
  async testConnection(): Promise<{ success: boolean; latencyMs?: number; version?: string; error?: string }> {
    const version = (await agyVersionInContainer()) || undefined;
    if (!version) return { success: false, error: "The Antigravity CLI is not available in the sandbox." };
    const res = await verifyAgentAnswers();
    return res.ok
      ? { success: true, latencyMs: res.latencyMs, version }
      : { success: false, latencyMs: res.latencyMs, version, error: res.detail === "the CLI is not signed in" ? "The agent is not signed in. Sign in again." : `The agent did not answer: ${res.detail}` };
  }

  async executeInference(prompt: string, model?: string): Promise<{ text: string; latencyMs: number; error?: string }> {
    const result = await warmAgentService.executePrompt(prompt, { model: sanitizeAgyModel(model || this.defaultModel) });
    return { text: result.text, latencyMs: result.latencyMs, error: result.error };
  }

  async reset(): Promise<{ success: boolean; error?: string }> {
    cancelAgyLogin();
    warmAgentService.destroyProcess("agent_reset");
    const res = await removeAgentContainerAndHome();
    return res.ok ? { success: true } : { success: false, error: res.detail };
  }
}
