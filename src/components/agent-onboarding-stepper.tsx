import { useEffect, useRef, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  AlertCircle,
  Check,
  CheckCircle2,
  ChevronDown,
  Copy,
  ExternalLink,
  Layers,
  RefreshCw,
  RotateCcw,
  Shield,
  Sparkles,
  Terminal,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { StatusChip } from "@/components/ui/primitives";
import { ActivitySpinner } from "@/components/ui/activity-spinner";
import { cn } from "@/lib/cn";
import {
  getAgentOnboardingStatus,
  advanceAgentOnboarding,
  submitAgentOnboardingCode,
  cancelAgentOnboardingSignIn,
  testAgentOnboardingConnection,
  resetAgentOnboarding,
  setActiveAgentProvider,
} from "@/lib/aie/server";
// Types and constants only: the framework index also re-exports server-only modules.
import { AGY_AVAILABLE_MODELS, ONBOARDING_STEPS, sanitizeAgyModel, type AgentOnboardingStatus } from "@/lib/aie/agent-framework/types";

interface AgentOnboardingStepperProps {
  agentId?: string;
  onCompleted?: () => void;
  className?: string;
}

type Phase = "loading" | "idle" | "working" | "awaiting_code" | "signing_in" | "error" | "done";

function phaseOf(status: AgentOnboardingStatus | undefined): Phase {
  if (!status) return "loading";
  if (status.state === "success") return "done";
  if (status.state === "error") return "error";
  if (status.state === "waiting_input" && status.authUrl) return "awaiting_code";
  if (status.currentStep === "waiting_for_auth" && status.state === "in_progress") return "signing_in";
  if (status.state === "in_progress" || status.state === "waiting_input") return "working";
  return "idle";
}

/**
 * Install and sign in the containerized agent. Every step runs on the server; this view polls its
 * status. Sign-in is the agent CLI's own Google sign-in: the link comes from the CLI and the code
 * the user pastes is typed into the CLI, never stored.
 */
export function AgentOnboardingStepper({ agentId = "agy_agent", onCompleted, className }: AgentOnboardingStepperProps) {
  const queryClient = useQueryClient();
  const [code, setCode] = useState("");
  const [selectedModel, setSelectedModel] = useState<string | null>(null);
  const [showSteps, setShowSteps] = useState(false);
  const [showOutput, setShowOutput] = useState(false);
  const [confirmReset, setConfirmReset] = useState(false);

  const { data: status, isLoading } = useQuery({
    queryKey: ["agent_onboarding_status", agentId],
    queryFn: () => getAgentOnboardingStatus({ data: { agentId } }),
    refetchInterval: (query) => {
      const p = phaseOf(query.state.data);
      return p === "working" || p === "signing_in" ? 1500 : p === "awaiting_code" ? 4000 : 15000;
    },
  });
  const phase = isLoading ? "loading" : phaseOf(status);

  // Report completion once, when the agent becomes ready while this view is open.
  const previousPhase = useRef<Phase>(phase);
  useEffect(() => {
    if (phase === "done" && previousPhase.current !== "done" && previousPhase.current !== "loading") {
      toast.success("Agent signed in and ready");
      queryClient.invalidateQueries({ queryKey: ["marketplace_state"] });
      queryClient.invalidateQueries({ queryKey: ["app_settings"] });
      onCompleted?.();
    }
    previousPhase.current = phase;
  }, [phase, onCompleted, queryClient]);

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ["agent_onboarding_status", agentId] });
    queryClient.invalidateQueries({ queryKey: ["marketplace_state"] });
  };
  const onFailure = (err: unknown) => toast.error(err instanceof Error ? err.message : String(err));

  const start = useMutation({ mutationFn: () => advanceAgentOnboarding({ data: { agentId } }), onSuccess: refresh, onError: onFailure });
  const submit = useMutation({
    mutationFn: (value: string) => submitAgentOnboardingCode({ data: { agentId, code: value } }),
    onSuccess: (res) => {
      if (res.error && res.state !== "in_progress") toast.error(res.error);
      else setCode("");
      queryClient.setQueryData(["agent_onboarding_status", agentId], res);
      refresh();
    },
    onError: onFailure,
  });
  const cancel = useMutation({ mutationFn: () => cancelAgentOnboardingSignIn({ data: { agentId } }), onSuccess: refresh, onError: onFailure });
  const test = useMutation({
    mutationFn: () => testAgentOnboardingConnection({ data: { agentId } }),
    onSuccess: (res) => {
      if (res.success) toast.success(res.message);
      else toast.error(res.message);
      refresh();
    },
    onError: onFailure,
  });
  const reset = useMutation({
    mutationFn: () => resetAgentOnboarding({ data: { agentId } }),
    onSuccess: (res) => {
      setConfirmReset(false);
      setCode("");
      if (res.success) toast.success(res.message);
      else toast.error(res.message);
      refresh();
      queryClient.invalidateQueries({ queryKey: ["app_settings"] });
    },
    onError: onFailure,
  });
  const setModel = useMutation({
    mutationFn: (model: string) => setActiveAgentProvider({ data: { id: agentId, model } }),
    onSuccess: (res) => {
      setSelectedModel(res.activeModel);
      queryClient.invalidateQueries({ queryKey: ["marketplace_state"] });
      queryClient.invalidateQueries({ queryKey: ["app_settings"] });
    },
    onError: onFailure,
  });

  if (phase === "loading" || !status) {
    return (
      <div className="flex flex-col items-center justify-center space-y-3 p-8 text-subtle">
        <ActivitySpinner size="lg" className="text-accent" />
        <p className="text-xs">Checking the agent…</p>
      </div>
    );
  }

  const canManage = status.canManage;
  const stepTitle = ONBOARDING_STEPS.find((s) => s.id === status.currentStep)?.title;
  const activeModel = sanitizeAgyModel(selectedModel || status.activeModel);
  const transcript = status.signIn?.transcript?.trim();
  const busy = start.isPending || submit.isPending || cancel.isPending || reset.isPending;

  const stepState = (index: number): "completed" | "current" | "error" | "pending" => {
    if (phase === "done") return "completed";
    const currentIndex = ONBOARDING_STEPS.findIndex((s) => s.id === status.currentStep);
    if (index < currentIndex) return "completed";
    if (index === currentIndex) return phase === "error" ? "error" : "current";
    return "pending";
  };

  return (
    <div className={cn("space-y-4 text-fg", className)}>
      {/* Summary */}
      <div className="flex flex-col justify-between gap-3 rounded-xl border border-border bg-bg-card p-4 sm:flex-row sm:items-center">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="text-sm font-medium text-fg">{status.agentName}</h3>
            {phase === "done" ? (
              <StatusChip tone="success" dot>
                Signed in · ready
              </StatusChip>
            ) : phase === "awaiting_code" ? (
              <StatusChip tone="warning" dot>
                Waiting for your Google sign-in
              </StatusChip>
            ) : phase === "error" ? (
              <StatusChip tone="danger" dot>
                Needs attention
              </StatusChip>
            ) : phase === "idle" ? (
              <StatusChip>Not set up</StatusChip>
            ) : (
              <StatusChip tone="info" dot>
                Step {status.stepNumber} of {status.totalSteps}
              </StatusChip>
            )}
            {phase === "done" && <span className="font-mono text-[11px] text-muted">{activeModel}</span>}
          </div>
          <p className="mt-0.5 text-xs text-subtle">
            {status.providerLabel}
            {status.version ? ` · CLI ${status.version}` : ""}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" variant="secondary" onClick={() => setShowSteps((v) => !v)} className="h-8 gap-1.5 rounded-lg text-xs">
            <Layers className="size-3.5" strokeWidth={1.75} />
            <span>{showSteps ? "Hide steps" : "Show steps"}</span>
            <ChevronDown className={cn("size-3.5 transition-transform duration-200", showSteps && "rotate-180")} />
          </Button>
          {phase === "done" && (
            <Button size="sm" variant="secondary" disabled={test.isPending} onClick={() => test.mutate()} className="h-8 gap-1.5 text-xs">
              <RefreshCw className={cn("size-3.5", test.isPending && "animate-spin")} />
              <span>{test.isPending ? "Testing…" : "Test connection"}</span>
            </Button>
          )}
          {canManage && phase !== "idle" && (
            confirmReset ? (
              <span className="flex items-center gap-1.5">
                <Button size="sm" variant="danger" disabled={reset.isPending} onClick={() => reset.mutate()} className="h-8 gap-1 text-xs">
                  {reset.isPending ? <ActivitySpinner size="xs" /> : <RotateCcw className="size-3" />}
                  <span>Sign out & remove</span>
                </Button>
                <Button size="sm" variant="ghost" onClick={() => setConfirmReset(false)} className="h-8 text-xs">
                  Keep
                </Button>
              </span>
            ) : (
              <Button
                size="sm"
                variant="ghost"
                onClick={() => setConfirmReset(true)}
                className="h-8 gap-1 text-xs text-subtle hover:text-fg"
                title="Sign out and remove the agent sandbox, including its saved sign-in"
              >
                <RotateCcw className="size-3" />
                <span>Reset</span>
              </Button>
            )
          )}
        </div>
      </div>

      {/* Steps */}
      {showSteps && (
        <div className="space-y-3 rounded-xl border border-border bg-bg-card p-4">
          <div className="flex items-center justify-between text-xs">
            <span className="text-sm font-medium text-fg">Setup steps</span>
            <span className="tabular-nums text-muted">
              {phase === "done" ? `${status.totalSteps} of ${status.totalSteps} done` : `Step ${status.stepNumber} of ${status.totalSteps}`}
            </span>
          </div>
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-bg-subtle">
            <div
              className={cn("h-full transition-all duration-500", phase === "done" ? "bg-sage" : phase === "error" ? "bg-danger" : "bg-accent")}
              style={{ width: `${phase === "done" ? 100 : (status.stepNumber / status.totalSteps) * 100}%` }}
            />
          </div>
          <ol className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
            {ONBOARDING_STEPS.map((step, i) => {
              const st = stepState(i);
              return (
                <li
                  key={step.id}
                  className={cn(
                    "flex items-center gap-2.5 rounded-lg p-2 text-xs",
                    st === "current" && "bg-bg-subtle",
                    st === "error" && "bg-danger/10 text-danger",
                    st === "pending" && "text-subtle",
                  )}
                >
                  <span
                    className={cn(
                      "flex size-5 shrink-0 items-center justify-center rounded-full text-[10px] font-medium tabular-nums",
                      st === "completed" && "bg-sage/20 text-sage",
                      st === "current" && "bg-accent/20 text-accent",
                      st === "pending" && "border border-border bg-bg-subtle",
                      st === "error" && "bg-danger/20 text-danger",
                    )}
                  >
                    {st === "completed" ? <Check className="size-3 stroke-[2.5]" /> : st === "current" && phase !== "awaiting_code" ? <ActivitySpinner size="xs" /> : step.stepNumber}
                  </span>
                  <span className="truncate font-medium">{step.title}</span>
                </li>
              );
            })}
          </ol>
        </div>
      )}

      {/* Current action */}
      <div className="space-y-4 rounded-xl border border-border bg-bg-card p-4">
        {phase === "idle" && (
          <div className="space-y-3">
            <p className="text-xs leading-relaxed text-muted">
              Installs the Antigravity CLI in an isolated Docker sandbox, then signs it in with your Google account through the CLI&apos;s own
              sign-in. The first install builds the sandbox image and can take a few minutes.
            </p>
            {canManage ? (
              <Button size="sm" variant="primary" disabled={busy} onClick={() => start.mutate()} className="h-8 gap-1.5 text-xs">
                {start.isPending ? <ActivitySpinner size="xs" /> : <Sparkles className="size-3.5" />}
                <span>{start.isPending ? "Starting…" : "Install and sign in"}</span>
              </Button>
            ) : (
              <p className="text-xs text-subtle">An administrator installs and signs in the agent for this workspace.</p>
            )}
          </div>
        )}

        {phase === "working" && (
          <div className="flex items-start gap-3">
            <ActivitySpinner size="sm" className="mt-0.5 text-accent" />
            <div className="min-w-0 space-y-0.5">
              <div className="text-sm font-medium text-fg">{stepTitle}</div>
              <p className="text-xs leading-relaxed text-muted">{status.message}</p>
            </div>
          </div>
        )}

        {phase === "awaiting_code" && status.authUrl && (
          <div className="space-y-4">
            <div className="space-y-3 rounded-lg border border-border bg-bg-subtle/50 p-4">
              <div className="flex items-center gap-1.5 text-sm font-medium text-fg">
                <Shield className="size-4 text-muted" strokeWidth={1.75} />
                <span>Sign in with Google</span>
              </div>
              <ol className="list-decimal space-y-1 pl-4 text-xs leading-relaxed text-muted">
                <li>Open the sign-in link. The Antigravity CLI in your sandbox created it.</li>
                <li>Choose your Google account and allow access.</li>
                <li>Google then shows an authorization code. Copy it and paste it below.</li>
              </ol>
              <div className="flex flex-wrap items-center gap-2 pt-1">
                <a
                  href={status.authUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex h-9 items-center gap-2 rounded-lg bg-accent px-3.5 text-sm font-medium text-accent-fg transition-opacity hover:opacity-90"
                >
                  <ExternalLink className="size-3.5" />
                  <span>Open Google sign-in</span>
                </a>
                <Button
                  size="sm"
                  variant="secondary"
                  className="h-9 gap-1.5 text-xs"
                  onClick={() =>
                    navigator.clipboard?.writeText(status.authUrl!).then(
                      () => toast.success("Sign-in link copied"),
                      () => toast.error("Could not copy the link"),
                    )
                  }
                >
                  <Copy className="size-3.5" />
                  <span>Copy link</span>
                </Button>
              </div>
            </div>

            {canManage && (
              <form
                className="space-y-2"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (code.trim()) submit.mutate(code.trim());
                }}
              >
                <label htmlFor="agent-auth-code" className="block text-xs font-medium text-subtle">
                  Authorization code
                </label>
                <div className="flex flex-col items-stretch gap-2 sm:flex-row sm:items-center">
                  <Input
                    id="agent-auth-code"
                    autoComplete="off"
                    spellCheck={false}
                    placeholder="Paste the code from Google (or the page address it sent you to)"
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    className="h-9 grow rounded-lg border-border bg-bg-elevated font-mono text-xs"
                  />
                  <Button type="submit" size="sm" variant="primary" disabled={!code.trim() || busy} className="h-9 shrink-0 gap-1.5 px-4 text-xs">
                    {submit.isPending ? <ActivitySpinner size="xs" /> : <Check className="size-3.5" />}
                    <span>{submit.isPending ? "Sending…" : "Sign in"}</span>
                  </Button>
                </div>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="text-[11px] text-subtle">The code goes straight to the CLI in the sandbox. AIE does not store it.</p>
                  <button type="button" disabled={busy} onClick={() => cancel.mutate()} className="text-[11px] text-subtle underline-offset-2 hover:text-fg hover:underline">
                    Cancel sign-in
                  </button>
                </div>
              </form>
            )}
          </div>
        )}

        {phase === "signing_in" && (
          <div className="flex items-start gap-3">
            <ActivitySpinner size="sm" className="mt-0.5 text-accent" />
            <div className="min-w-0 space-y-0.5">
              <div className="text-sm font-medium text-fg">Signing in…</div>
              <p className="text-xs leading-relaxed text-muted">{status.signIn?.message || status.message}</p>
            </div>
          </div>
        )}

        {phase === "error" && (
          <div className="flex items-start gap-3 rounded-lg border border-danger/50 bg-danger/10 p-3.5 text-xs text-danger">
            <AlertCircle className="mt-0.5 size-4 shrink-0" />
            <div className="min-w-0 grow space-y-1">
              <div className="font-medium">
                {status.currentStep === "waiting_for_auth" ? "Sign-in did not finish" : stepTitle ? `${stepTitle} did not finish` : "Setup did not finish"}
              </div>
              <p className="whitespace-pre-line break-words leading-relaxed">{status.error || status.message}</p>
            </div>
            {canManage && (
              <Button size="sm" variant="secondary" disabled={busy} onClick={() => start.mutate()} className="h-7 shrink-0 text-xs">
                {start.isPending ? "Starting…" : "Try again"}
              </Button>
            )}
          </div>
        )}

        {phase === "done" && (
          <div className="space-y-3 rounded-lg border border-sage/40 bg-sage/5 p-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-sm font-medium text-sage">
                <CheckCircle2 className="size-4" />
                <span>{status.message}</span>
              </div>
              {status.latencyMs ? <span className="text-xs tabular-nums text-muted">Last test: {status.latencyMs} ms</span> : null}
            </div>
            <p className="text-xs leading-relaxed text-muted">
              The agent CLI keeps its Google sign-in inside the sandbox, so it stays signed in across restarts. Reset signs it out and removes the sandbox.
            </p>
            <div className="flex flex-col gap-3 pt-1 sm:flex-row sm:items-center">
              <label htmlFor="agent-model" className="flex shrink-0 items-center gap-1.5 text-xs font-medium text-subtle">
                <Sparkles className="size-3.5" strokeWidth={1.75} />
                <span>Model</span>
              </label>
              <Select
                id="agent-model"
                value={activeModel}
                onValueChange={(v) => setModel.mutate(v)}
                disabled={setModel.isPending}
                className="max-w-sm"
              >
                {AGY_AVAILABLE_MODELS.map((m) => (
                  <option key={m.id} value={m.id}>
                    {m.name}
                    {m.isFast ? " (fastest)" : ""}
                  </option>
                ))}
              </Select>
              {setModel.isPending && (
                <span className="flex items-center gap-1 text-[11px] text-muted">
                  <ActivitySpinner size="xs" />
                  Saving…
                </span>
              )}
            </div>
          </div>
        )}

        {canManage && transcript && phase !== "done" && (
          <div className="border-t border-border pt-3">
            <button
              type="button"
              onClick={() => setShowOutput((v) => !v)}
              className="flex items-center gap-1.5 text-[11px] font-medium text-subtle hover:text-fg"
              aria-expanded={showOutput}
            >
              <Terminal className="size-3.5" />
              <span>{showOutput ? "Hide CLI output" : "Show CLI output"}</span>
            </button>
            {showOutput && (
              <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-border bg-bg p-3 font-mono text-[11px] leading-relaxed text-muted">
                {transcript}
              </pre>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
