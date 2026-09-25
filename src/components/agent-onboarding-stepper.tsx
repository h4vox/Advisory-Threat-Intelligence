import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Check,
  CheckCircle2,
  ExternalLink,
  Loader2,
  RefreshCw,
  Shield,
  AlertCircle,
  Zap,
  RotateCcw,
  Sparkles,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
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
  const { data: status, isLoading, refetch } = useQuery({
    queryKey: ["agent_onboarding_status", agentId],
    queryFn: () => getAgentOnboardingStatus({ data: { agentId } }),
    refetchInterval: (query) => {
      const current = query.state.data?.currentStep;
      // When in progress, poll every 2s; when waiting for input or completed, poll slower
      if (current && ["starting_environment", "installing_agent", "starting_agent", "generating_auth_link", "testing_agent_connection"].includes(current)) {
        return 2000;
      }
      return 15000;
    },
  });

  // Start or advance onboarding mutation (steps 1 through 7)
  const advanceMutation = useMutation({
    mutationFn: (methodId?: string) =>
      advanceAgentOnboarding({ data: { agentId, authMethod: methodId || selectedMethodId } }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["agent_onboarding_status", agentId] });
      queryClient.invalidateQueries({ queryKey: ["marketplace_state"] });
      queryClient.invalidateQueries({ queryKey: ["app_settings"] });
    },
  });

  // Submit authorization code mutation (steps 8 through 10)
  const submitCodeMutation = useMutation({
    mutationFn: (code: string) =>
      submitAgentOnboardingCode({
        data: {
          agentId,
          code,
          codeVerifier: status?.authState,
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
        <Loader2 className="size-6 animate-spin text-accent" />
        <p className="text-xs">Connecting to agent lifecycle service...</p>
      </div>
    );
  }

  const currentStepDef =
    ONBOARDING_STEPS.find((s) => s.id === status?.currentStep) || ONBOARDING_STEPS[0];
  const isCompleted = status?.currentStep === "agent_onboarding_completed";
  const isWaitingForAuth = status?.currentStep === "waiting_for_auth";
  const isError = status?.state === "error" || status?.currentStep === "error";

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

  return (
    <div className={cn("space-y-6 text-fg", className)}>
      {/* Header Overview Card */}
      <div className="p-4 rounded-2xl border border-border/80 bg-bg-subtle/50 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xs">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold text-fg">
              {status?.agentName || "Autonomous AI Agent Engine"}
            </h3>
            {isCompleted ? (
              <Badge className="bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 text-[10px] gap-1">
                <CheckCircle2 className="size-3" />
                Operational
              </Badge>
            ) : isWaitingForAuth ? (
              <Badge className="bg-amber-500/15 text-amber-400 border border-amber-500/30 text-[10px] gap-1">
                <Shield className="size-3" />
                Authentication Required
              </Badge>
            ) : (
              <Badge className="bg-accent/10 text-accent border border-accent/20 text-[10px]">
                Onboarding Step {status?.stepNumber || 1} of 10
              </Badge>
            )}
          </div>
          <p className="text-xs text-subtle mt-0.5">{status?.providerLabel || "Google Gemini"}</p>
        </div>

        <div className="flex items-center gap-2">
          {isCompleted && (
            <Button
              size="sm"
              variant="secondary"
              disabled={testConnectionMutation.isPending}
              onClick={() => testConnectionMutation.mutate()}
              className="text-xs h-8 gap-1.5 cursor-pointer"
            >
              <RefreshCw
                className={cn("size-3.5 text-accent", testConnectionMutation.isPending && "animate-spin")}
              />
              <span>{testConnectionMutation.isPending ? "Testing..." : "Test Connection"}</span>
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

      {/* 10-Step Visual Timeline Progress Strip */}
      <div className="p-4 rounded-2xl border border-border/80 bg-bg-card shadow-xs space-y-4">
        <div className="flex items-center justify-between text-xs">
          <span className="font-medium text-subtle">Onboarding Pipeline Progress</span>
          <span className="font-mono text-accent font-semibold">
            {isCompleted ? "100%" : `${Math.round(((status?.stepNumber || 1) / 10) * 100)}%`}
          </span>
        </div>

        {/* Progress Bar */}
        <div className="w-full h-1.5 bg-bg-subtle rounded-full overflow-hidden">
          <div
            className={cn(
              "h-full transition-all duration-500",
              isCompleted ? "bg-emerald-500" : isError ? "bg-rose-500" : "bg-accent"
            )}
            style={{ width: `${isCompleted ? 100 : ((status?.stepNumber || 1) / 10) * 100}%` }}
          />
        </div>

        {/* 10-Step Timeline List */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1">
          {ONBOARDING_STEPS.map((step) => {
            const stepState = getStepStatus(step);
            const isCurrent = status?.currentStep === step.id;

            return (
              <div
                key={step.id}
                className={cn(
                  "flex items-center gap-2.5 p-2 rounded-xl border text-xs transition-colors",
                  isCurrent && "border-accent/40 bg-accent/5",
                  stepState === "completed" && "border-emerald-500/20 bg-emerald-500/5 text-fg",
                  stepState === "pending" && "border-transparent bg-transparent text-subtle/70",
                  stepState === "error" && "border-rose-500/40 bg-rose-500/10 text-rose-300"
                )}
              >
                {/* Status Indicator Icon */}
                <div
                  className={cn(
                    "size-5 rounded-full flex items-center justify-center text-[10px] shrink-0 font-medium",
                    stepState === "completed" && "bg-emerald-500 text-white shadow-xs",
                    stepState === "in_progress" && "bg-accent text-white animate-pulse shadow-xs",
                    stepState === "pending" && "bg-bg-subtle text-subtle border border-border",
                    stepState === "error" && "bg-rose-500 text-white"
                  )}
                >
                  {stepState === "completed" ? (
                    <Check className="size-3 stroke-[2.5]" />
                  ) : stepState === "in_progress" ? (
                    <Loader2 className="size-3 animate-spin" />
                  ) : (
                    step.stepNumber
                  )}
                </div>

                {/* Step Title */}
                <div className="min-w-0 grow">
                  <div
                    className={cn(
                      "truncate font-medium",
                      isCurrent && "text-accent font-semibold",
                      stepState === "completed" && "text-fg",
                      stepState === "pending" && "text-subtle"
                    )}
                  >
                    {step.stepNumber}. {step.title}
                  </div>
                </div>

                {isCurrent && (
                  <Badge className="text-[9px] px-1.5 py-0 bg-accent text-white shrink-0">
                    Active
                  </Badge>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Active Step Interactive Card */}
      <div className="p-5 rounded-2xl border border-border/90 bg-bg-card shadow-sm space-y-4">
        {/* Error Alert */}
        {isError && (
          <div className="p-3.5 rounded-xl border border-rose-500/30 bg-rose-500/10 flex items-start gap-3 text-xs text-rose-300">
            <AlertCircle className="size-4 shrink-0 text-rose-400 mt-0.5" />
            <div className="grow space-y-1">
              <div className="font-semibold text-rose-200">Onboarding Step Interrupted</div>
              <p className="leading-relaxed">{status?.error || status?.message}</p>
            </div>
            <Button
              size="sm"
              variant="secondary"
              disabled={advanceMutation.isPending}
              onClick={() => advanceMutation.mutate(selectedMethodId)}
              className="text-xs h-7 border-rose-500/30 hover:bg-rose-500/20 text-rose-300 cursor-pointer"
            >
              Retry Step
            </Button>
          </div>
        )}

        {/* Step 5: Select Authentication Method */}
        {status?.stepNumber === 5 && (
          <div className="space-y-3">
            <div className="font-medium text-xs text-subtle">Choose Authentication Option:</div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {status.supportedAuthMethods.map((m) => (
                <button
                  key={m.id}
                  type="button"
                  onClick={() => setSelectedMethodId(m.id)}
                  className={cn(
                    "p-3 rounded-xl border text-left space-y-1 transition-all cursor-pointer",
                    selectedMethodId === m.id
                      ? "border-accent bg-accent/10 shadow-xs"
                      : "border-border hover:border-border/80 bg-bg-subtle/50"
                  )}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-xs text-fg">{m.name}</span>
                    {m.isRecommended && (
                      <Badge className="text-[9px] bg-accent/20 text-accent border border-accent/30">
                        Recommended
                      </Badge>
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
              className="text-xs h-8 gap-1.5 bg-accent text-white font-medium"
            >
              {advanceMutation.isPending ? (
                <>
                  <Loader2 className="size-3.5 animate-spin" />
                  <span>Generating Session...</span>
                </>
              ) : (
                <>
                  <span>Continue with {selectedMethodId === "google_oauth" ? "Google OAuth" : "API Key"}</span>
                </>
              )}
            </Button>
          </div>
        )}

        {/* Step 7: Waiting for Authentication (Interactive User Flow) */}
        {isWaitingForAuth && (
          <div className="space-y-4">
            <div className="p-4 rounded-xl border border-accent/20 bg-accent/5 space-y-3">
              <div className="flex items-center justify-between">
                <div className="font-semibold text-xs text-fg flex items-center gap-1.5">
                  <Shield className="size-4 text-accent" />
                  <span>Google Account Authentication</span>
                </div>
                <Badge className="text-[10px] border border-accent/30 text-accent font-mono">
                  PKCE S256 Secure
                </Badge>
              </div>

              <p className="text-xs text-muted leading-relaxed">
                Click the portal button below to authenticate with your Google account. After granting permission, Google will provide an authorization code.
              </p>

              <div className="pt-1">
                <a
                  href={status.authUrl || "#"}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-2 px-3.5 py-2 rounded-xl bg-accent text-white font-medium text-xs hover:bg-accent/90 transition-all shadow-xs cursor-pointer"
                >
                  <ExternalLink className="size-3.5" />
                  <span>Open Google OAuth Authorization Portal</span>
                </a>
              </div>
            </div>

            {/* Code Input Field */}
            <div className="space-y-2">
              <label className="block text-xs font-medium text-subtle">
                Paste Google Authorization Code:
              </label>
              <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
                <Input
                  placeholder="Paste authorization code (starts with 4/0...) or callback URL..."
                  value={authCodeInput}
                  onChange={(e) => setAuthCodeInput(e.target.value)}
                  className="font-mono text-xs bg-bg-subtle grow"
                />
                <Button
                  size="sm"
                  variant="primary"
                  disabled={!authCodeInput.trim() || submitCodeMutation.isPending}
                  onClick={() => submitCodeMutation.mutate(authCodeInput)}
                  className="text-xs h-9 px-4 bg-accent text-white font-medium shrink-0 cursor-pointer"
                >
                  {submitCodeMutation.isPending ? (
                    <>
                      <Loader2 className="size-3.5 animate-spin" />
                      <span>Verifying...</span>
                    </>
                  ) : (
                    <>
                      <Check className="size-3.5" />
                      <span>Submit Code & Connect</span>
                    </>
                  )}
                </Button>
              </div>
              <p className="text-[11px] text-subtle">
                Copy the code displayed by Google on the completion screen and paste it here to finalize setup.
              </p>
            </div>
          </div>
        )}

        {/* Step 10: Onboarding Completed (Success State) */}
        {isCompleted && (
          <div className="p-4 rounded-xl border border-emerald-500/30 bg-emerald-500/10 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-emerald-400 font-semibold text-xs">
                <CheckCircle2 className="size-4" />
                <span>Agent Onboarding Successfully Completed</span>
              </div>
              {status.latencyMs && (
                <Badge className="text-[10px] font-mono border border-emerald-500/30 text-emerald-400 bg-emerald-500/10">
                  {status.latencyMs}ms roundtrip
                </Badge>
              )}
            </div>

            <p className="text-xs text-muted leading-relaxed">
              The autonomous threat intelligence agent engine is active and ready for automated entity extraction, attack chain synthesis, and emulation plan generation.
            </p>

            {/* Model Selector */}
            <div className="pt-2 flex flex-col sm:flex-row sm:items-center gap-3">
              <label className="text-xs font-medium text-subtle shrink-0">Default Model:</label>
              <select
                value={selectedModel || status.activeModel}
                onChange={(e) => setModelMutation.mutate(e.target.value)}
                className="rounded-lg border border-border bg-bg-subtle px-3 py-1.5 text-xs text-fg focus:border-accent focus:outline-none"
              >
                {status.supportedModels.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            </div>
          </div>
        )}

        {/* Initial Step 1 / Launch Button when idle */}
        {status?.stepNumber === 1 && status.state === "idle" && (
          <div className="space-y-3">
            <p className="text-xs text-muted leading-relaxed">
              Start the automated onboarding process to initialize the isolated agent environment and configure credentials.
            </p>
            <Button
              size="sm"
              variant="primary"
              disabled={advanceMutation.isPending}
              onClick={() => advanceMutation.mutate(selectedMethodId)}
              className="text-xs h-8 gap-1.5 bg-accent text-white font-medium cursor-pointer"
            >
              {advanceMutation.isPending ? (
                <>
                  <Loader2 className="size-3.5 animate-spin" />
                  <span>Starting Agent Environment...</span>
                </>
              ) : (
                <>
                  <Sparkles className="size-3.5" />
                  <span>Start Agent Onboarding</span>
                </>
              )}
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}
