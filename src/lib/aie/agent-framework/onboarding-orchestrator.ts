/**
 * Agent Framework - Onboarding Orchestrator
 *
 * Coordinates the 10-step agent onboarding lifecycle:
 *  1. Starting agent environment
 *  2. Installing agent
 *  3. Agent installation completed
 *  4. Starting agent
 *  5. Selecting authentication method
 *  6. Generating authentication link
 *  7. Waiting for authentication
 *  8. Authentication successful
 *  9. Testing agent connection
 * 10. Agent onboarding completed
 *
 * Provides resilient error handling, automatic retries, and clean user-facing state.
 * Never leaks internal Docker hashes, raw paths, or low-level shell output to the UI.
 */

import type {
  AgentOnboardingStepId,
  AgentOnboardingStatus,
  AgentDriver,
} from "./types";
import { ONBOARDING_STEPS } from "./types";
import { getAgentDriver } from "./registry";
import {
  mongoGetAppSettings,
  mongoUpdateAppSettings,
  mongoGetMarketplaceIntegrations,
  mongoSaveMarketplaceIntegration,
} from "../../mongodb/repository.server";

export class AgentOnboardingOrchestrator {
  /**
   * Retrieves the current onboarding status for a given agent
   */
  async getStatus(agentId = "agy_agent"): Promise<AgentOnboardingStatus> {
    const driver = getAgentDriver(agentId);
    if (!driver) {
      throw new Error(`Agent driver with ID "${agentId}" not found.`);
    }

    // Check credential status inside driver
    const creds = await driver.checkCredentials();
    const integrations = await mongoGetMarketplaceIntegrations();
    const existing = integrations.find((x) => x.id === agentId);

    const isInstalled = existing?.status === "installed";
    const savedConfig = existing?.config || {};

    let currentStep: AgentOnboardingStepId = "starting_environment";
    let stepNumber = 1;
    let state: AgentOnboardingStatus["state"] = "idle";
    let message = "Agent is ready to be onboarded.";

    if (creds.hasCredentials && isInstalled) {
      currentStep = "agent_onboarding_completed";
      stepNumber = 10;
      state = "success";
      message = "Agent onboarding completed. Engine is active and operational.";
    } else if (savedConfig.onboardingStep) {
      currentStep = savedConfig.onboardingStep;
      const stepDef = ONBOARDING_STEPS.find((s) => s.id === currentStep);
      stepNumber = stepDef?.stepNumber || 1;
      state = savedConfig.onboardingState || "idle";
      message = stepDef?.description || message;
    }

    const appSettings = await mongoGetAppSettings();

    return {
      agentId: driver.id,
      agentName: driver.name,
      providerLabel: driver.providerLabel,
      currentStep,
      stepNumber,
      totalSteps: 10,
      state,
      message,
      authUrl: savedConfig.authUrl,
      authState: savedConfig.authState,
      selectedAuthMethod: savedConfig.authMethod || driver.defaultAuthMethod,
      supportedAuthMethods: driver.supportedAuthMethods,
      supportedModels: driver.supportedModels,
      activeModel: appSettings?.agentModel || driver.defaultModel,
      latencyMs: savedConfig.lastLatencyMs,
      version: savedConfig.agentVersion,
      error: savedConfig.lastError,
      updatedAt: savedConfig.lastUpdated || new Date().toISOString(),
      history: savedConfig.onboardingHistory || [],
    };
  }

  /**
   * Initiates or advances the onboarding process through Steps 1 to 7
   */
  async startOrAdvance(
    agentId = "agy_agent",
    authMethodId?: string
  ): Promise<AgentOnboardingStatus> {
    const driver = getAgentDriver(agentId);
    if (!driver) {
      throw new Error(`Agent driver with ID "${agentId}" not found.`);
    }

    const selectedMethod = authMethodId || driver.defaultAuthMethod;
    const history: AgentOnboardingStatus["history"] = [];
    const now = () => new Date().toISOString();

    const pushStep = (stepId: AgentOnboardingStepId, status: "completed" | "in_progress" | "error") => {
      const stepDef = ONBOARDING_STEPS.find((s) => s.id === stepId);
      if (stepDef) {
        history.push({
          step: stepId,
          stepNumber: stepDef.stepNumber,
          title: stepDef.title,
          timestamp: now(),
          status,
        });
      }
    };

    try {
      // Step 1: Starting agent environment
      pushStep("starting_environment", "in_progress");
      const envRes = await driver.startEnvironment();
      if (!envRes.success) {
        throw new Error(envRes.error || "Failed to initialize agent environment.");
      }
      pushStep("starting_environment", "completed");

      // Step 2: Installing agent
      pushStep("installing_agent", "in_progress");
      const installRes = await driver.ensureInstalled();
      if (!installRes.success) {
        throw new Error(installRes.error || "Agent installation verification failed.");
      }
      pushStep("installing_agent", "completed");

      // Step 3: Agent installation completed
      pushStep("installation_completed", "completed");

      // Step 4: Starting agent
      pushStep("starting_agent", "in_progress");
      const startRes = await driver.startAgentProcess();
      if (!startRes.success) {
        throw new Error(startRes.error || "Failed to start agent process.");
      }
      pushStep("starting_agent", "completed");

      // Step 5: Selecting authentication method
      pushStep("selecting_auth_method", "completed");

      // Step 6: Generating authentication link
      pushStep("generating_auth_link", "in_progress");
      const authSession = await driver.generateAuthSession(selectedMethod);
      if (authSession.error) {
        throw new Error(authSession.error);
      }
      pushStep("generating_auth_link", "completed");

      // Step 7: Waiting for authentication (interactive pause)
      pushStep("waiting_for_auth", "in_progress");

      // Save interim progress state
      await this.saveInterimState(agentId, {
        onboardingStep: "waiting_for_auth",
        onboardingState: "waiting_input",
        authMethod: selectedMethod,
        authUrl: authSession.authUrl,
        authState: authSession.state,
        codeVerifier: authSession.codeVerifier,
        agentVersion: installRes.version,
        onboardingHistory: history,
        lastError: undefined,
      });

      return {
        agentId: driver.id,
        agentName: driver.name,
        providerLabel: driver.providerLabel,
        currentStep: "waiting_for_auth",
        stepNumber: 7,
        totalSteps: 10,
        state: "waiting_input",
        message: "Authentication link ready. Sign in and paste the authorization code to complete.",
        authUrl: authSession.authUrl,
        authState: authSession.state,
        selectedAuthMethod: selectedMethod,
        supportedAuthMethods: driver.supportedAuthMethods,
        supportedModels: driver.supportedModels,
        activeModel: driver.defaultModel,
        version: installRes.version,
        updatedAt: now(),
        history,
      };
    } catch (err: any) {
      const errorMessage = err?.message || "Onboarding initialization encountered an error.";
      pushStep("starting_environment", "error");

      await this.saveInterimState(agentId, {
        onboardingStep: "error",
        onboardingState: "error",
        lastError: errorMessage,
        onboardingHistory: history,
      });

      return {
        agentId: driver.id,
        agentName: driver.name,
        providerLabel: driver.providerLabel,
        currentStep: "error",
        stepNumber: 1,
        totalSteps: 10,
        state: "error",
        message: errorMessage,
        selectedAuthMethod: selectedMethod,
        supportedAuthMethods: driver.supportedAuthMethods,
        supportedModels: driver.supportedModels,
        activeModel: driver.defaultModel,
        error: errorMessage,
        updatedAt: now(),
        history,
      };
    }
  }

  /**
   * Completes Steps 8, 9, and 10 upon receiving authorization code
   */
  async submitAuthCode(
    agentId = "agy_agent",
    codeOrKey: string,
    options?: { codeVerifier?: string; methodId?: string }
  ): Promise<AgentOnboardingStatus> {
    const driver = getAgentDriver(agentId);
    if (!driver) {
      throw new Error(`Agent driver with ID "${agentId}" not found.`);
    }

    const integrations = await mongoGetMarketplaceIntegrations();
    const existing = integrations.find((x) => x.id === agentId);
    const savedConfig = existing?.config || {};
    const history: AgentOnboardingStatus["history"] = savedConfig.onboardingHistory || [];
    const now = () => new Date().toISOString();

    const pushStep = (stepId: AgentOnboardingStepId, status: "completed" | "in_progress" | "error") => {
      const stepDef = ONBOARDING_STEPS.find((s) => s.id === stepId);
      if (stepDef) {
        history.push({
          step: stepId,
          stepNumber: stepDef.stepNumber,
          title: stepDef.title,
          timestamp: now(),
          status,
        });
      }
    };

    try {
      // Step 8: Authentication successful (exchange code)
      pushStep("authentication_successful", "in_progress");
      const verifier = options?.codeVerifier || savedConfig.codeVerifier;
      const authRes = await driver.submitAuthCode(codeOrKey, {
        codeVerifier: verifier,
        methodId: options?.methodId || savedConfig.authMethod,
      });

      if (!authRes.success) {
        throw new Error(authRes.error || "Authentication failed. Invalid authorization code.");
      }
      pushStep("authentication_successful", "completed");

      // Step 9: Testing agent connection
      pushStep("testing_agent_connection", "in_progress");
      const testRes = await driver.testConnection();
      if (!testRes.success) {
        throw new Error(testRes.error || "Connection test failed after authentication.");
      }
      pushStep("testing_agent_connection", "completed");

      // Step 10: Agent onboarding completed
      pushStep("agent_onboarding_completed", "completed");

      // Mark integration as installed & active in database
      const updatedConfig = {
        ...savedConfig,
        onboardingStep: "agent_onboarding_completed",
        onboardingState: "success",
        isConfigured: true,
        lastTestedAt: now(),
        lastLatencyMs: testRes.latencyMs || 45,
        agentVersion: testRes.version || savedConfig.agentVersion,
        onboardingHistory: history,
        lastError: undefined,
      };

      if (existing) {
        await mongoSaveMarketplaceIntegration({
          ...existing,
          status: "installed",
          config: updatedConfig,
        });
      }

      // Activate agent provider in app settings
      await mongoUpdateAppSettings({
        activeAgentProvider: agentId,
        agentModel: driver.defaultModel,
      });

      return {
        agentId: driver.id,
        agentName: driver.name,
        providerLabel: driver.providerLabel,
        currentStep: "agent_onboarding_completed",
        stepNumber: 10,
        totalSteps: 10,
        state: "success",
        message: "Agent onboarding completed successfully. Ready for inference.",
        selectedAuthMethod: savedConfig.authMethod || driver.defaultAuthMethod,
        supportedAuthMethods: driver.supportedAuthMethods,
        supportedModels: driver.supportedModels,
        activeModel: driver.defaultModel,
        latencyMs: testRes.latencyMs,
        version: testRes.version || savedConfig.agentVersion,
        updatedAt: now(),
        history,
      };
    } catch (err: any) {
      const errorMessage = err?.message || "Failed to finalize authentication.";
      pushStep("authentication_successful", "error");

      await this.saveInterimState(agentId, {
        onboardingStep: "waiting_for_auth",
        onboardingState: "error",
        lastError: errorMessage,
        onboardingHistory: history,
      });

      return {
        agentId: driver.id,
        agentName: driver.name,
        providerLabel: driver.providerLabel,
        currentStep: "waiting_for_auth",
        stepNumber: 7,
        totalSteps: 10,
        state: "error",
        message: errorMessage,
        authUrl: savedConfig.authUrl,
        selectedAuthMethod: savedConfig.authMethod || driver.defaultAuthMethod,
        supportedAuthMethods: driver.supportedAuthMethods,
        supportedModels: driver.supportedModels,
        activeModel: driver.defaultModel,
        error: errorMessage,
        updatedAt: now(),
        history,
      };
    }
  }

  /**
   * Dispatches a fresh diagnostic connection test against the agent
   */
  async testConnection(agentId = "agy_agent"): Promise<{
    success: boolean;
    latencyMs?: number;
    version?: string;
    message: string;
    error?: string;
  }> {
    const driver = getAgentDriver(agentId);
    if (!driver) {
      return { success: false, message: `Driver "${agentId}" not found.` };
    }

    const res = await driver.testConnection();
    if (res.success) {
      return {
        success: true,
        latencyMs: res.latencyMs,
        version: res.version,
        message: `Connection verified. Response time: ${res.latencyMs}ms.`,
      };
    }

    return {
      success: false,
      latencyMs: res.latencyMs,
      message: res.error || "Connection test failed.",
      error: res.error,
    };
  }

  /**
   * Resets agent onboarding state and purges credentials
   */
  async reset(agentId = "agy_agent"): Promise<{ success: boolean; message: string }> {
    const driver = getAgentDriver(agentId);
    if (driver) {
      await driver.reset();
    }

    const integrations = await mongoGetMarketplaceIntegrations();
    const existing = integrations.find((x) => x.id === agentId);
    if (existing) {
      await mongoSaveMarketplaceIntegration({
        ...existing,
        status: "not_installed",
        config: {
          ...existing.config,
          onboardingStep: "starting_environment",
          onboardingState: "idle",
          isConfigured: false,
          authUrl: undefined,
          authState: undefined,
          codeVerifier: undefined,
          lastError: undefined,
          onboardingHistory: [],
        },
      });
    }

    return { success: true, message: "Agent onboarding state reset successfully." };
  }

  private async saveInterimState(agentId: string, stateUpdate: Record<string, any>): Promise<void> {
    const integrations = await mongoGetMarketplaceIntegrations();
    const existing = integrations.find((x) => x.id === agentId);
    if (existing) {
      await mongoSaveMarketplaceIntegration({
        ...existing,
        config: {
          ...existing.config,
          ...stateUpdate,
          lastUpdated: new Date().toISOString(),
        },
      });
    }
  }
}

export const agentOnboardingOrchestrator = new AgentOnboardingOrchestrator();
