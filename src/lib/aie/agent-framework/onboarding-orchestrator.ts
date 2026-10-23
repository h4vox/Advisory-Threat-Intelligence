/**
 * Agent Framework - Onboarding Orchestrator
 *
 * Runs the 10-step agent onboarding:
 *  1. Starting agent environment       (Docker answers; the sandbox image exists, built if missing)
 *  2. Installing agent                 (the real agent CLI is in the image; a shim-only image is rebuilt)
 *  3. Agent installation completed
 *  4. Starting agent                   (the container runs with the agent's home on its volume)
 *  5. Selecting authentication method  (Google sign-in in the agent CLI)
 *  6. Generating authentication link   (the CLI prints its own sign-in link)
 *  7. Waiting for authentication       (the user opens the link and pastes Google's code back)
 *  8. Authentication successful        (the CLI accepted the code and saved its sign-in)
 *  9. Testing agent connection         (a real prompt answered)
 * 10. Agent onboarding completed
 *
 * Steps 1-6 run in the background (one run per agent per process) and save their progress, so the
 * UI polls the status instead of holding a request open through a several-minute image build. The
 * sign-in finishes on its own: the driver reports the CLI's state changes, and a successful sign-in
 * completes steps 8-10. The UI never sees Docker internals, tokens or the authorization code.
 */

import type { AgentDriver, AgentOnboardingStatus, AgentOnboardingStepId, AgentSignInProgress } from "./types";
import { ONBOARDING_STEPS } from "./types";
import { getAgentDriver } from "./registry";
import {
  mongoGetAppSettings,
  mongoUpdateAppSettings,
  mongoGetMarketplaceIntegrations,
  mongoSaveMarketplaceIntegration,
} from "../../mongodb/repository.server";
import type { IntegrationItem } from "../marketplace-types";
import { invalidateAgyProbe } from "../agent-sandbox";
import { warmAgentService } from "../warm-agent-service";

type HistoryEntry = AgentOnboardingStatus["history"][number];
type SavedState = Record<string, unknown> & {
  onboardingStep?: AgentOnboardingStepId;
  onboardingState?: AgentOnboardingStatus["state"];
  onboardingMessage?: string;
  onboardingHistory?: HistoryEntry[];
  lastError?: string;
  agentVersion?: string;
  lastLatencyMs?: number;
  signedInAt?: string;
  lastUpdated?: string;
};

const IN_FLIGHT_SIGN_IN = new Set<AgentSignInProgress["state"]>(["starting", "choosing_method", "awaiting_code", "signing_in", "verifying"]);

type OrchestratorGlobals = typeof globalThis & {
  __aieOnboardingRuns?: Map<string, Promise<void>>;
  __aieOnboardingUnsubscribe?: Map<string, () => void>;
  __aieOnboardingSaves?: Map<string, Promise<void>>;
};
const og = globalThis as OrchestratorGlobals;
/** Background runs of steps 1-6, per agent. On globalThis so a dev reload cannot start a second one. */
const runs: Map<string, Promise<void>> = (og.__aieOnboardingRuns ??= new Map());
const unsubscribes: Map<string, () => void> = (og.__aieOnboardingUnsubscribe ??= new Map());
/** Integration writes replace the whole config: one at a time per agent, so progress updates never overwrite each other. */
const saveChains: Map<string, Promise<void>> = (og.__aieOnboardingSaves ??= new Map());

const now = () => new Date().toISOString();
const stepDef = (id: AgentOnboardingStepId) => ONBOARDING_STEPS.find((s) => s.id === id);

function historyEntry(step: AgentOnboardingStepId, status: HistoryEntry["status"]): HistoryEntry | null {
  const def = stepDef(step);
  return def ? { step, stepNumber: def.stepNumber, title: def.title, timestamp: now(), status } : null;
}

export class AgentOnboardingOrchestrator {
  private subscribed = new Set<string>();

  private driver(agentId: string): AgentDriver {
    const driver = getAgentDriver(agentId);
    if (!driver) throw new Error(`Agent driver with ID "${agentId}" not found.`);
    if (!this.subscribed.has(agentId)) {
      this.subscribed.add(agentId);
      this.subscribe(driver);
    }
    return driver;
  }

  /** One listener per agent per process: finishes or fails the onboarding when the CLI's sign-in ends. */
  private subscribe(driver: AgentDriver) {
    unsubscribes.get(driver.id)?.(); // a dev reload replaces the previous module's listener
    unsubscribes.set(
      driver.id,
      driver.onSignInChange((progress) => {
        if (progress.state === "signed_in") void this.completeSignIn(driver, progress).catch((err) => console.warn("[onboarding] completing sign-in failed:", err));
        else if (progress.state === "failed") void this.save(driver.id, { onboardingStep: "waiting_for_auth", onboardingState: "error", lastError: progress.message, onboardingMessage: progress.message });
        else if (progress.state === "awaiting_code") void this.save(driver.id, { onboardingStep: "waiting_for_auth", onboardingState: "waiting_input", lastError: undefined, onboardingMessage: stepDef("waiting_for_auth")?.description });
      }),
    );
  }

  async getStatus(agentId = "agy_agent", options: { canManage?: boolean } = {}): Promise<AgentOnboardingStatus> {
    const driver = this.driver(agentId);
    const [integration, appSettings] = await Promise.all([this.integration(agentId), mongoGetAppSettings()]);
    const saved: SavedState = (integration?.config as SavedState) || {};
    const signIn = driver.getSignIn();
    const running = runs.has(agentId);

    let currentStep: AgentOnboardingStepId = saved.onboardingStep || "starting_environment";
    let state: AgentOnboardingStatus["state"] = saved.onboardingState || "idle";
    let message = saved.onboardingMessage || stepDef(currentStep)?.description || "Ready to install the agent.";
    let error = state === "error" ? saved.lastError : undefined;
    let authUrl: string | undefined;

    if (running) {
      // A setup run is active: whatever was saved before it started no longer applies.
      if (state !== "in_progress") {
        currentStep = "starting_environment";
        message = stepDef(currentStep)?.description || message;
      }
      state = "in_progress";
      error = undefined;
    } else if (integration?.status === "installed" && saved.signedInAt && currentStep === "agent_onboarding_completed") {
      state = "success";
      message = saved.onboardingMessage || "The agent is signed in and ready.";
    } else if (currentStep === "waiting_for_auth" && !running) {
      if (signIn && IN_FLIGHT_SIGN_IN.has(signIn.state)) {
        state = signIn.state === "awaiting_code" ? "waiting_input" : "in_progress";
        message = signIn.message;
        authUrl = signIn.authUrl ?? undefined;
        error = undefined;
      } else if (signIn?.state === "signed_in") {
        state = "in_progress";
        message = "Signed in. Finishing setup…";
      } else if (state !== "error") {
        // The terminal that waited for the code is gone (the server restarted, or the link expired).
        state = "error";
        error = message = "The sign-in was interrupted. Start sign-in again to get a new link.";
      }
    } else if (state === "in_progress" && !running) {
      state = "error";
      error = message = "Setup was interrupted (the server restarted). Start again.";
    }

    const step = currentStep === "error" ? undefined : stepDef(currentStep);
    return {
      agentId: driver.id,
      agentName: driver.name,
      providerLabel: driver.providerLabel,
      currentStep,
      stepNumber: step?.stepNumber ?? 1,
      totalSteps: ONBOARDING_STEPS.length,
      state,
      message,
      authUrl,
      selectedAuthMethod: driver.defaultAuthMethod,
      supportedAuthMethods: driver.supportedAuthMethods,
      supportedModels: driver.supportedModels,
      activeModel: (() => {
        const raw = (appSettings?.agentModel || "").replace(/^AGY:\s*/i, "").trim();
        return driver.supportedModels.includes(raw) ? raw : driver.defaultModel;
      })(),
      latencyMs: saved.lastLatencyMs,
      version: saved.agentVersion,
      error,
      signIn: signIn
        ? { state: signIn.state, message: signIn.message, transcript: options.canManage ? signIn.transcript : undefined }
        : undefined,
      canManage: Boolean(options.canManage),
      updatedAt: saved.lastUpdated || now(),
      history: saved.onboardingHistory || [],
    };
  }

  /**
   * Starts steps 1-6 in the background (or joins the run in progress) and returns the status at once.
   * Steps already satisfied (image built, container running, CLI signed in) pass in seconds.
   */
  async startOrAdvance(agentId = "agy_agent", authMethodId?: string): Promise<AgentOnboardingStatus> {
    const driver = this.driver(agentId);
    if (!runs.has(agentId)) {
      // Registered before the first await, so a second click joins this run instead of starting another.
      let marked: Promise<void> = Promise.resolve();
      const run = (async () => {
        marked = this.save(agentId, {
          onboardingStep: "starting_environment",
          onboardingState: "in_progress",
          onboardingMessage: stepDef("starting_environment")?.description,
          onboardingHistory: [],
          lastError: undefined,
        });
        await marked;
        await this.runSetup(driver, authMethodId || driver.defaultAuthMethod);
      })()
        .catch((err) => console.warn("[onboarding] setup run failed:", err))
        .finally(() => runs.delete(agentId));
      runs.set(agentId, run);
      await marked.catch(() => {});
    }
    return this.getStatus(agentId, { canManage: true });
  }

  private async runSetup(driver: AgentDriver, methodId: string): Promise<void> {
    const history: HistoryEntry[] = [];
    let current: AgentOnboardingStepId = "starting_environment";
    const enter = async (step: AgentOnboardingStepId, message?: string) => {
      current = step;
      const entry = historyEntry(step, "in_progress");
      if (entry) history.push(entry);
      await this.save(driver.id, { onboardingStep: step, onboardingState: "in_progress", onboardingMessage: message || stepDef(step)?.description, onboardingHistory: history });
    };
    const done = (step: AgentOnboardingStepId) => {
      const entry = historyEntry(step, "completed");
      if (entry) history.push(entry);
    };
    const note = (message: string) => void this.save(driver.id, { onboardingMessage: message });

    try {
      await enter("starting_environment");
      const env = await driver.startEnvironment(note);
      if (!env.success) throw new Error(env.error || "The agent environment did not start.");
      done("starting_environment");

      await enter("installing_agent");
      const install = await driver.ensureInstalled(note);
      if (!install.success) throw new Error(install.error || "The agent could not be installed.");
      done("installing_agent");
      done("installation_completed");
      await this.save(driver.id, { agentVersion: install.version });

      await enter("starting_agent");
      const started = await driver.startAgentProcess();
      if (!started.success) throw new Error(started.error || "The agent did not start.");
      done("starting_agent");
      done("selecting_auth_method");

      await enter("generating_auth_link", "Starting the agent's Google sign-in…");
      const signIn = await driver.startSignIn(methodId);
      if (signIn.state === "failed" || signIn.state === "cancelled") throw new Error(signIn.message);
      done("generating_auth_link");
      if (signIn.state === "signed_in") {
        // Already signed in (a saved sign-in in the sandbox): no code needed.
        await this.save(driver.id, { onboardingHistory: history });
        await this.completeSignIn(driver, signIn);
        return;
      }
      const waiting = historyEntry("waiting_for_auth", "in_progress");
      if (waiting) history.push(waiting);
      await this.save(driver.id, {
        onboardingStep: "waiting_for_auth",
        onboardingState: "waiting_input",
        onboardingMessage: stepDef("waiting_for_auth")?.description,
        onboardingHistory: history,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const failed = historyEntry(current, "error");
      if (failed) history.push(failed);
      await this.save(driver.id, { onboardingStep: current, onboardingState: "error", lastError: message, onboardingMessage: message, onboardingHistory: history });
    }
  }

  /** Step 7: types the code into the CLI. The CLI's verdict arrives through the sign-in listener. */
  async submitAuthCode(agentId = "agy_agent", code: string): Promise<AgentOnboardingStatus> {
    const driver = this.driver(agentId);
    const res = driver.submitSignInCode(code);
    if (!res.success) {
      const status = await this.getStatus(agentId, { canManage: true });
      return { ...status, error: res.error, message: res.error || status.message, state: status.state === "waiting_input" ? "waiting_input" : status.state };
    }
    await this.save(agentId, { onboardingStep: "waiting_for_auth", onboardingState: "in_progress", onboardingMessage: "Signing in…", lastError: undefined });
    return this.getStatus(agentId, { canManage: true });
  }

  /** Steps 8-10 after the CLI signed in (its verifier already had the agent answer a real prompt). */
  private async completeSignIn(driver: AgentDriver, progress: AgentSignInProgress): Promise<void> {
    const integration = await this.integration(driver.id);
    const saved: SavedState = (integration?.config as SavedState) || {};
    const history = [...(saved.onboardingHistory || [])];
    for (const step of ["waiting_for_auth", "authentication_successful", "testing_agent_connection", "agent_onboarding_completed"] as const) {
      const entry = historyEntry(step, "completed");
      if (entry) history.push(entry);
    }
    const test = await driver.testConnection();
    if (!test.success) {
      await this.save(driver.id, {
        onboardingStep: "testing_agent_connection",
        onboardingState: "error",
        lastError: test.error,
        onboardingMessage: test.error,
        onboardingHistory: history,
      });
      return;
    }
    await this.update(driver.id, (item) => ({
        ...item,
        status: "installed",
        config: {
          ...item.config,
          onboardingStep: "agent_onboarding_completed",
          onboardingState: "success",
          onboardingMessage: progress.alreadySignedIn ? "Already signed in. The agent is ready." : "Signed in. The agent is ready.",
          onboardingHistory: history,
          isConfigured: true,
          signedInAt: now(),
          lastTestedAt: now(),
          lastLatencyMs: test.latencyMs,
          agentVersion: test.version || saved.agentVersion,
          lastError: undefined,
          lastUpdated: now(),
        },
      }));
    const settings = await mongoGetAppSettings();
    const model = (settings?.agentModel || "").replace(/^AGY:\s*/i, "").trim();
    await mongoUpdateAppSettings({
      activeAgentProvider: driver.id,
      agentModel: driver.supportedModels.includes(model) ? model : driver.defaultModel,
    });
    invalidateAgyProbe();
    // Keep one agent process warm so the first prompt does not pay the CLI's start-up time.
    void warmAgentService.prewarm(driver.supportedModels.includes(model) ? model : driver.defaultModel).catch(() => {});
  }

  /** Abandons a sign-in that waits for a code. */
  async cancelSignIn(agentId = "agy_agent"): Promise<AgentOnboardingStatus> {
    const driver = this.driver(agentId);
    driver.cancelSignIn();
    await this.save(agentId, { onboardingStep: "starting_environment", onboardingState: "idle", onboardingMessage: "Sign-in cancelled.", lastError: undefined });
    return this.getStatus(agentId, { canManage: true });
  }

  /** A real prompt through the agent. */
  async testConnection(agentId = "agy_agent"): Promise<{ success: boolean; latencyMs?: number; version?: string; message: string; error?: string }> {
    const driver = this.driver(agentId);
    const res = await driver.testConnection();
    if (res.success) {
      await this.save(agentId, { lastLatencyMs: res.latencyMs, lastTestedAt: now() });
      return { success: true, latencyMs: res.latencyMs, version: res.version, message: `The agent answered in ${res.latencyMs} ms.` };
    }
    return { success: false, latencyMs: res.latencyMs, message: res.error || "Connection test failed.", error: res.error };
  }

  /** Signs out completely: removes the sandbox and the agent's saved sign-in, and resets the onboarding. */
  async reset(agentId = "agy_agent"): Promise<{ success: boolean; message: string }> {
    const driver = this.driver(agentId);
    const res = await driver.reset();
    await this.update(agentId, (item) => ({
        ...item,
        status: "not_installed",
        config: {
          ...item.config,
          onboardingStep: "starting_environment",
          onboardingState: "idle",
          onboardingMessage: undefined,
          onboardingHistory: [],
          isConfigured: false,
          signedInAt: undefined,
          authUrl: undefined,
          authState: undefined,
          codeVerifier: undefined,
          oauthCodeVerifier: undefined,
          lastError: undefined,
          lastUpdated: now(),
        },
      }));
    return res.success
      ? { success: true, message: "Signed out. The agent sandbox and its saved sign-in were removed." }
      : { success: false, message: res.error || "The sandbox could not be removed completely." };
  }

  private async integration(agentId: string) {
    const integrations = await mongoGetMarketplaceIntegrations();
    return integrations.find((x) => x.id === agentId);
  }

  /** Read-modify-write of the agent's integration, serialized per agent. */
  private update(agentId: string, mutate: (item: IntegrationItem) => IntegrationItem): Promise<void> {
    const next = (saveChains.get(agentId) ?? Promise.resolve())
      .catch(() => {})
      .then(async () => {
        const integration = await this.integration(agentId);
        if (integration) await mongoSaveMarketplaceIntegration(mutate(integration));
      });
    saveChains.set(agentId, next);
    return next;
  }

  private save(agentId: string, update: SavedState): Promise<void> {
    return this.update(agentId, (item) => ({ ...item, config: { ...item.config, ...update, lastUpdated: now() } }));
  }
}

export const agentOnboardingOrchestrator = new AgentOnboardingOrchestrator();
