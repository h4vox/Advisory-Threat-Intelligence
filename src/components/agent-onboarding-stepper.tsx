import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Check,
  CheckCircle2,
  ExternalLink,
  RefreshCw,
  Shield,
  AlertCircle,
  Zap,
  RotateCcw,
  Sparkles,
  ChevronDown,
  Layers,
  Key,
  Terminal,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { StatusChip } from "@/components/ui/primitives";
import { ActivitySpinner } from "@/components/ui/activity-spinner";
import { cn } from "@/lib/cn";
import {
  getAgentOnboardingStatus,
  advanceAgentOnboarding,
  submitAgentOnboardingCode,
  testAgentOnboardingConnection,
  resetAgentOnboarding,
  setActiveAgentProvider,
} from "@/lib/aie/server";
import {
  ONBOARDING_STEPS,
  type AgentOnboardingStepId,
} from "@/lib/aie/agent-framework";
import {
  AGY_AVAILABLE_MODELS,
  DEFAULT_AGY_MODEL,
  sanitizeAgyModel,
} from "@/lib/aie/agent-framework/types";

interface AgentOnboardingStepperProps {
  agentId?: string;
  onCompleted?: () => void;
  className?: string;
}

export function AgentOnboardingStepper({
  agentId = "agy_agent",
  onCompleted,
  className,
}: AgentOnboardingStepperProps) {
  const queryClient = useQueryClient();
  const [authCodeInput, setAuthCodeInput] = useState("");
  const [selectedMethodId, setSelectedMethodId] = useState("google_oauth");
  const [selectedModel, setSelectedModel] = useState<string | null>(null);

  // Query live onboarding status
  const { data: status, isLoading } = useQuery({
    queryKey: ["agent_onboarding_status", agentId],
    queryFn: () => getAgentOnboardingStatus({ data: { agentId } }),
    refetchInterval: (query) => {
      const current = query.state.data?.currentStep;
      if (
        current &&
        [
          "starting_environment",
          "installing_agent",
          "starting_agent",
          "generating_auth_link",
          "testing_agent_connection",
        ].includes(current)
      ) {
        return 2000;
      }
      return 15000;
    },
  });

  const isCompleted = status?.currentStep === "agent_onboarding_completed";
  const isWaitingForAuth = status?.currentStep === "waiting_for_auth";
  const isError = status?.state === "error" || status?.currentStep === "error";

  // Dropdown collapse toggle: default open if auth needed or in progress, collapsed if completed
  const [isDropdownOpen, setIsDropdownOpen] = useState(!isCompleted || isWaitingForAuth);

  // Advance mutation
  const advanceMutation = useMutation({
    mutationFn: (methodId?: string) =>
      advanceAgentOnboarding({ data: { agentId, authMethod: methodId || selectedMethodId } }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["agent_onboarding_status", agentId] });
      queryClient.invalidateQueries({ queryKey: ["marketplace_state"] });
      queryClient.invalidateQueries({ queryKey: ["app_settings"] });
    },
  });

  // Submit code mutation
  const submitCodeMutation = useMutation({
    mutationFn: (code: string) =>
      submitAgentOnboardingCode({
        data: {
          agentId,
          code,
          methodId: selectedMethodId,
        },
      }),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ["agent_onboarding_status", agentId] });
      queryClient.invalidateQueries({ queryKey: ["marketplace_state"] });
      queryClient.invalidateQueries({ queryKey: ["app_settings"] });
      setAuthCodeInput("");
      if (res.currentStep === "agent_onboarding_completed") {
        onCompleted?.();
      }
    },
  });

  // Test connection mutation
  const testConnectionMutation = useMutation({
    mutationFn: () => testAgentOnboardingConnection({ data: { agentId } }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["agent_onboarding_status", agentId] });
    },
  });

  // Reset onboarding mutation
  const resetMutation = useMutation({
    mutationFn: () => resetAgentOnboarding({ data: { agentId } }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["agent_onboarding_status", agentId] });
      queryClient.invalidateQueries({ queryKey: ["marketplace_state"] });
      setAuthCodeInput("");
      setIsDropdownOpen(true);
    },
  });

  // Switch model mutation
  const setModelMutation = useMutation({
    mutationFn: (model: string) => setActiveAgentProvider({ data: { id: agentId, model } }),
    onSuccess: (res) => {
      setSelectedModel(res.activeModel);
      queryClient.invalidateQueries({ queryKey: ["marketplace_state"] });
      queryClient.invalidateQueries({ queryKey: ["app_settings"] });
    },
  });

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center p-8 space-y-3 text-subtle">
        <ActivitySpinner size="lg" className="text-accent" />
        <p className="text-xs">Connecting to autonomous agent service...</p>
      </div>
    );
  }

  const getStepStatus = (step: (typeof ONBOARDING_STEPS)[number]) => {
    if (isCompleted) return "completed";
    if (status?.currentStep === step.id) {
      return isError ? "error" : "in_progress";
    }
    const currentIdx = ONBOARDING_STEPS.findIndex((s) => s.id === status?.currentStep);
    const thisIdx = ONBOARDING_STEPS.findIndex((s) => s.id === step.id);
    if (currentIdx > thisIdx) return "completed";
    return "pending";
  };

  const activeModelDisplay = sanitizeAgyModel(selectedModel || status?.activeModel);

  return (
    <div className={cn("space-y-4 text-fg", className)}>
      {/* Executive Overview Header Card */}
      <div className="flex flex-col justify-between gap-3 rounded-xl border border-border bg-bg-card p-4 sm:flex-row sm:items-center">
        <div>
          <div className="flex items-center gap-2 flex-wrap">
            <h3 className="text-sm font-medium text-fg">
              {status?.agentName || "Autonomous Threat Intelligence Agent"}
            </h3>
            {isCompleted ? (
              <StatusChip tone="success" dot>
                Operational · vault synchronized
              </StatusChip>
            ) : isWaitingForAuth ? (
              <StatusChip tone="warning" dot>
                Authentication required (step 7 of 10)
              </StatusChip>
            ) : (
              <StatusChip>Onboarding step {status?.stepNumber || 1} of 10</StatusChip>
            )}

            {isCompleted && (
              <span className="font-mono text-[11px] text-muted">{activeModelDisplay}</span>
            )}
          </div>
          <p className="text-xs text-subtle mt-0.5">
            Dedicated container sandbox · zero host dependencies · PKCE S256 guarded
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {/* Dropdown Toggle Button */}
          <Button
            size="sm"
            variant="secondary"
            onClick={() => setIsDropdownOpen((prev) => !prev)}
            className="h-8 cursor-pointer gap-1.5 rounded-lg text-xs"
          >
            <Layers className="size-3.5" strokeWidth={1.75} />
            <span>{isDropdownOpen ? "Collapse pipeline" : "Inspect pipeline steps (10)"}</span>
            <ChevronDown
              className={cn("size-3.5 transition-transform duration-200", isDropdownOpen && "rotate-180")}
            />
          </Button>

          {isCompleted && (
            <Button
              size="sm"
              variant="secondary"
              disabled={testConnectionMutation.isPending}
              onClick={() => testConnectionMutation.mutate()}
              className="text-xs h-8 gap-1.5 cursor-pointer"
            >
              <RefreshCw
                className={cn("size-3.5", testConnectionMutation.isPending && "animate-spin")}
              />
              <span>{testConnectionMutation.isPending ? "Probing…" : "Test connection"}</span>
            </Button>
          )}

          <Button
            size="sm"
            variant="ghost"
            disabled={resetMutation.isPending}
            onClick={() => resetMutation.mutate()}
            className="text-xs h-8 text-subtle hover:text-fg gap-1 cursor-pointer"
            title="Reset onboarding and clear credentials"
          >
            <RotateCcw className="size-3" />
            <span className="hidden sm:inline">Reset</span>
          </Button>
        </div>
      </div>

      {/* Collapsible 10-Step Pipeline Dropdown Accordion */}
      {isDropdownOpen && (
        <div className="space-y-4 rounded-xl border border-border bg-bg-card p-4 animate-in fade-in-50 duration-200">
          <div className="flex items-center justify-between text-xs">
            <span className="text-sm font-medium text-fg">Pipeline diagnostic verification</span>
            <span className="text-muted tabular-nums">
              {isCompleted ? "10 of 10 verified" : `Step ${status?.stepNumber || 1} of 10`}
            </span>
          </div>

          {/* Progress Bar */}
          <div className="w-full h-1.5 bg-bg-subtle rounded-full overflow-hidden">
            <div
              className={cn(
                "h-full transition-all duration-500",
                isCompleted ? "bg-sage" : isError ? "bg-danger" : "bg-accent"
              )}
              style={{ width: `${isCompleted ? 100 : ((status?.stepNumber || 1) / 10) * 100}%` }}
            />
          </div>

          {/* 10-Step Diagnostic Matrix */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1">
            {ONBOARDING_STEPS.map((step) => {
              const stepState = getStepStatus(step);
              const isCurrent = status?.currentStep === step.id;

              return (
                <div
                  key={step.id}
                  className={cn(
                    "flex items-center gap-2.5 rounded-lg p-2 text-xs transition-colors",
                    isCurrent && "bg-bg-subtle",
                    stepState === "completed" && "text-fg",
                    stepState === "pending" && "text-subtle",
                    stepState === "error" && "bg-danger/10 text-danger"
                  )}
                >
                  {/* Status Indicator Icon */}
                  <div
                    className={cn(
                      "flex size-5 shrink-0 items-center justify-center rounded-full text-[10px] font-medium tabular-nums",
                      stepState === "completed" && "bg-sage/20 text-sage",
                      stepState === "in_progress" && "bg-accent/20 text-accent",
                      stepState === "pending" && "border border-border bg-bg-subtle text-subtle",
                      stepState === "error" && "bg-danger/20 text-danger"
                    )}
                  >
                    {stepState === "completed" ? (
                      <Check className="size-3 stroke-[2.5]" />
                    ) : stepState === "in_progress" ? (
                      <ActivitySpinner size="xs" />
                    ) : (
                      step.stepNumber
                    )}
                  </div>

                  {/* Step Title */}
                  <div className="min-w-0 grow">
                    <div
                      className={cn(
                        "truncate font-medium",
                        isCurrent && "text-fg",
                        stepState === "completed" && "text-fg",
                        stepState === "pending" && "text-subtle"
                      )}
                    >
                      {step.stepNumber}. {step.title}
                    </div>
                  </div>

                  {isCurrent && (
                    <StatusChip tone="info">Active</StatusChip>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Active Interactive Action Area */}
      <div className="space-y-4 rounded-xl border border-border bg-bg-card p-4">
        {/* Error Alert */}
        {isError && (
          <div className="flex items-start gap-3 rounded-lg border border-danger/50 bg-danger/10 p-3.5 text-xs text-danger">
            <AlertCircle className="mt-0.5 size-4 shrink-0" />
            <div className="grow space-y-1">
              <div className="font-medium">Onboarding step interrupted</div>
              <p className="leading-relaxed">{status?.error || status?.message}</p>
            </div>
            <Button
              size="sm"
              variant="secondary"
              disabled={advanceMutation.isPending}
              onClick={() => advanceMutation.mutate(selectedMethodId)}
              className="h-7 cursor-pointer text-xs"
            >
              Retry step
            </Button>
          </div>
        )}

        {/* Step 5: Choose Auth Method */}
        {status?.stepNumber === 5 && (
          <div className="space-y-3">
            <div className="text-sm font-medium text-fg">Choose an authentication option</div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {status.supportedAuthMethods.map((m) => (
                <button
                  key={m.id}
                  type="button"
                  onClick={() => setSelectedMethodId(m.id)}
                  className={cn(
                    "cursor-pointer space-y-1 rounded-lg border p-3 text-left transition-colors",
                    selectedMethodId === m.id ? "border-accent bg-bg-subtle" : "border-border bg-bg-elevated hover:bg-bg-subtle"
                  )}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium text-fg">{m.name}</span>
                    {m.isRecommended && (
                      <StatusChip tone="info">Recommended</StatusChip>
                    )}
                  </div>
                  <p className="text-[11px] text-subtle leading-relaxed">{m.description}</p>
                </button>
              ))}
            </div>

            <Button
              size="sm"
              variant="primary"
              disabled={advanceMutation.isPending}
              onClick={() => advanceMutation.mutate(selectedMethodId)}
              className="h-8 cursor-pointer gap-1.5 text-xs font-medium"
            >
              {advanceMutation.isPending ? (
                <>
                  <ActivitySpinner size="xs" />
                  <span>Generating session…</span>
                </>
              ) : (
                <>
                  <span>Continue with {selectedMethodId === "google_oauth" ? "Google OAuth" : "API key"}</span>
                </>
              )}
            </Button>
          </div>
        )}

        {/* Step 7: Waiting for Authentication */}
        {isWaitingForAuth && (
          <div className="space-y-4">
            <div className="space-y-3 rounded-lg border border-border bg-bg-subtle/50 p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-1.5 text-sm font-medium text-fg">
                  <Shield className="size-4 text-muted" strokeWidth={1.75} />
                  <span>Google account single sign-on (PKCE flow)</span>
                </div>
                <StatusChip tone="info" dot>
                  PKCE challenge active
                </StatusChip>
              </div>

              <p className="text-xs text-muted leading-relaxed">
                Click below to authenticate with your Google account. Google will authorize the container vault and present an authorization code.
              </p>

              <div className="pt-1">
                <a
                  href={status.authUrl || "#"}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex h-9 cursor-pointer items-center gap-2 rounded-lg bg-accent px-3.5 text-sm font-medium text-accent-fg transition-opacity hover:opacity-90"
                >
                  <ExternalLink className="size-3.5" />
                  <span>Open Google authorization portal</span>
                </a>
              </div>
            </div>

            {/* Code Input Field */}
            <div className="space-y-2">
              <label className="block text-xs font-medium text-subtle">
                Paste Google authorization code
              </label>
              <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
                <Input
                  placeholder="Paste authorization code (starts with 4/0...) or callback URL..."
                  value={authCodeInput}
                  onChange={(e) => setAuthCodeInput(e.target.value)}
                  className="h-9 grow rounded-lg border-border bg-bg-elevated font-mono text-xs"
                />
                <Button
                  size="sm"
                  variant="primary"
                  disabled={!authCodeInput.trim() || submitCodeMutation.isPending}
                  onClick={() => submitCodeMutation.mutate(authCodeInput)}
                  className="h-9 shrink-0 cursor-pointer px-4 text-xs font-medium"
                >
                  {submitCodeMutation.isPending ? (
                    <>
                      <ActivitySpinner size="xs" />
                      <span>Verifying token…</span>
                    </>
                  ) : (
                    <>
                      <Check className="size-3.5" />
                      <span>Submit code & connect</span>
                    </>
                  )}
                </Button>
              </div>
              <p className="text-[11px] text-subtle">
                Once submitted, credentials are encrypted directly into the containerized vault volume (<code className="font-mono text-muted">aie-agent-vault</code>).
              </p>
            </div>
          </div>
        )}

        {/* Step 10: Onboarding Completed State with Enterprise Model Switcher */}
        {isCompleted && (
          <div className="space-y-3 rounded-lg border border-sage/40 bg-sage/5 p-4">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <div className="flex items-center gap-2 text-sm font-medium text-sage">
                <CheckCircle2 className="size-4" />
                <span>Agent engine active & warm-initialized</span>
              </div>
              {status.latencyMs && (
                <span className="text-xs text-muted tabular-nums">{status.latencyMs} ms roundtrip</span>
              )}
            </div>

            <p className="text-xs text-muted leading-relaxed">
              Containerized agent daemon is actively listening for autonomous adversary TTP extraction, kill-chain reconstruction, and research source harvesting.
            </p>

            {/* Model Selector listing only verified AGY models */}
            <div className="pt-2 flex flex-col sm:flex-row sm:items-center gap-3">
              <label className="text-xs font-medium text-subtle shrink-0 flex items-center gap-1.5">
                <Sparkles className="size-3.5" strokeWidth={1.75} />
                <span>Active model</span>
              </label>
              <select
                value={activeModelDisplay}
                onChange={(e) => setModelMutation.mutate(e.target.value)}
                disabled={setModelMutation.isPending}
                className="h-9 max-w-sm rounded-lg border border-border bg-bg-elevated px-3 text-sm text-fg focus:border-accent focus:outline-none"
              >
                {AGY_AVAILABLE_MODELS.map((m) => (
                  <option key={m.id} value={m.id}>
                    {m.name} {m.isFast ? "(Fastest)" : ""}
                  </option>
                ))}
              </select>
              {setModelMutation.isPending && (
                <span className="flex items-center gap-1 text-[11px] text-muted">
                  <ActivitySpinner size="xs" />
                  Updating model…
                </span>
              )}
            </div>
          </div>
        )}

        {/* Initial Step 1 / Launch Button when idle */}
        {status?.stepNumber === 1 && status.state === "idle" && (
          <div className="space-y-3">
            <p className="text-xs text-muted leading-relaxed">
              Initialize the isolated container environment and verify agent runtime.
            </p>
            <Button
              size="sm"
              variant="primary"
              disabled={advanceMutation.isPending}
              onClick={() => advanceMutation.mutate(selectedMethodId)}
              className="h-8 cursor-pointer gap-1.5 text-xs font-medium"
            >
              {advanceMutation.isPending ? (
                <>
                  <ActivitySpinner size="xs" />
                  <span>Starting sandbox…</span>
                </>
              ) : (
                <>
                  <Sparkles className="size-3.5" />
                  <span>Start agent onboarding</span>
                </>
              )}
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}
