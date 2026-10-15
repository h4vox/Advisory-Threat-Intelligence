/**
 * Always-Alive Warm Agent Session Service
 *
 * Maintains a persistent, warm NDJSON streaming process inside the isolated
 * Docker sandbox (`aie-agent-sandbox`) using
 * `agy --print --input-format stream-json --output-format stream-json`.
 * The agent runs print-only without permission bypass (no tools), prompts are
 * sent over stdin, and nothing ever runs on the host. Conversation state is
 * kept in memory only.
 *
 * Eliminates the 14-second cold-start penalty per prompt down to 2.0 - 2.8s pure inference latency,
 * and maintains conversational memory across multi-turn interactions.
 */

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import readline from "node:readline";
import {
  DEFAULT_AGY_MODEL,
  UNTRUSTED_CONTENT_NOTICE,
  sanitizeAgyModel,
  wrapUntrustedContent,
} from "./agent-framework/types";
import {
  AGENT_CONTAINER_NAME,
  buildAgentCliArgs,
  detectSandboxRuntime,
  encodeAgentUserTurn,
  runAgentPromptInSandbox,
} from "./agent-sandbox";

const CONTAINER_NAME = AGENT_CONTAINER_NAME;
const IDLE_TIMEOUT_MS = 25 * 60 * 1000; // 25 minutes idle shutdown
const TURN_TIMEOUT_MS = 65 * 1000; // 65 seconds per turn

interface TurnQueueItem {
  prompt: string;
  model: string;
  timeoutMs: number;
  resolve: (res: WarmInferenceResult) => void;
  startTime: number;
}

interface ActiveTurn {
  id: number;
  item: TurnQueueItem;
  /** Cold fallback is running; warm-stream events must not settle this turn. */
  inFallback: boolean;
  response: string;
  startTime: number;
  timer: NodeJS.Timeout | null;
}

export interface WarmInferenceResult {
  success: boolean;
  text: string;
  latencyMs: number;
  model: string;
  conversationId?: string;
  isWarm?: boolean;
  tokens?: {
    inputTokens: number;
    outputTokens: number;
    totalTokens: number;
  };
  error?: string;
}

export type AgentSkill =
  | "CTI_COPILOT"
  | "REPORT_QUALIFIER"
  | "ATTACK_CHAIN"
  | "SOURCE_HARVESTER"
  | "DOMAIN_HARVESTER";

export interface SkillOptions {
  skill: AgentSkill;
  payload: string;
  context?: string;
  history?: string;
  model?: string;
  timeoutMs?: number;
}

/**
 * Skill-Based Dynamic Prompt Builder
 * Uses concise [SKILL: ...] task headers instead of repetitive 500-word boilerplates.
 */
export function buildSkillPrompt(
  skill: AgentSkill,
  payload: string,
  context?: string,
  history?: string
): string {
  switch (skill) {
    case "CTI_COPILOT":
      return `[SKILL: CTI_COPILOT]
Role: Native Platform Cyber Threat Intelligence Copilot.
Directives:
- Provide authoritative threat analysis, TTP attribution, MITRE technique mappings (Txxxx), and purple team emulation steps.
- Maintain high information density using structured markdown, bullet points, and code blocks for telemetry/command lines.
- Ground analysis strictly in verified platform intelligence reports when provided.
- NEVER disclose underlying model architectures, container runtimes, or internal system wrappers.
${context ? `\n${UNTRUSTED_CONTENT_NOTICE}\nPLATFORM CTI EVIDENCE (stored third-party reports):\n${wrapUntrustedContent(context)}\n` : ""}
${history ? `\nPRIOR CONVERSATION CONTEXT:\n${history}\n` : ""}
Operator Inquiry: ${payload}`;

    case "REPORT_QUALIFIER":
      return `[SKILL: REPORT_QUALIFIER]
Evaluate the threat intelligence report candidate using the 5-dimensional rubric:
1. Procedural Depth (0-30 pts): Execution commands, APIs, injection, DLL sideloading, driver tampering.
2. Attack Progression (0-25 pts): Multi-stage sequential intrusion flow (Initial Access -> Loader -> Execution -> C2 -> Impact).
3. Attribution & Context (0-15 pts): Threat actor, campaign timeline, targeted sectors, weaponized CVEs.
4. Emulation Utility (0-20 pts): Sigma/YARA rules, EDR/Sysmon queries, atomic test commands.
5. IOC Verifiability (0-10 pts): C2 IPs, domains, SHA256 hashes, Windows/Sysmon event IDs.
Total Score = sum(dimensions). recommendApproval = true if score >= 50.

Taxonomy:
- Classification: ADVERSARY_EMULATION, INTRUSION_REPORT, ATTACK_CHAIN_REPORT, MALWARE_ANALYSIS, THREAT_ACTOR_REPORT, CAMPAIGN_REPORT, VULNERABILITY_REPORT, DETECTION_RESEARCH, SECURITY_ADVISORY, OTHER.
- ResourceKind: FULL_ATTACK_CHAIN, CAMPAIGN_INTEL, PROCEDURE_DEEPDIVE, MALWARE_ANALYSIS, DETECTION_GUIDANCE, VULNERABILITY_ADVISORY, THREAT_ACTOR_DOSSIER.
${UNTRUSTED_CONTENT_NOTICE}
${context ? `Context:\n${wrapUntrustedContent(context)}\n` : ""}
Input Document:
${wrapUntrustedContent(payload)}

Output pure JSON only:
{"isRelevant":true,"passScore":85,"recommendApproval":true,"classification":"ATTACK_CHAIN_REPORT","resourceKind":"FULL_ATTACK_CHAIN","threatActors":[],"malwareFamilies":[],"cves":[],"mitreTechniques":[],"stages":[],"scoreBreakdown":{"proceduralDepth":26,"attackProgression":22,"attributionContext":12,"emulationUtility":16,"iocVerifiability":9,"totalScore":85},"rationale":"..."}`;

    case "ATTACK_CHAIN":
      return `[SKILL: ATTACK_CHAIN]
Synthesize a chronological multi-stage attack chain with concrete procedures, MITRE ATT&CK techniques, detection rules, and purple team emulation commands from this report.
${UNTRUSTED_CONTENT_NOTICE}
${context ? `Context:\n${wrapUntrustedContent(context)}\n` : ""}
Report Text:
${wrapUntrustedContent(payload)}

Output pure JSON only:
{"classification":"THREAT_REPORT","threatActors":[],"malware":[],"vulnerabilities":[],"ttps":["T1190: ..."],"ioas":[],"attackChain":[{"order":1,"tactic":"Initial Access","techniques":["T1190"],"summary":"..."}],"detections":["Sigma: ..."],"hunting":[],"emulation":["Atomic Test: ..."]}`;

    case "SOURCE_HARVESTER":
      return `[SKILL: SOURCE_HARVESTER]
Role: Adversary Emulation Intelligence Source Hunter.
Mission: Discover high-value, distinct, highly technical threat intelligence sources or research lab endpoints (e.g., Check Point Research, Securelist, Huntress, Red Canary, Volexity, Sophos X-Ops, Cybereason, Sygnia, NCC Group, Malwarebytes Labs, Jamf Threat Labs, Morphisec, Elastic Labs).
Focus: Full intrusion/attack chains, multi-stage infection chains, forensic timelines, adversary TTPs, and malware analysis.
${context ? `${UNTRUSTED_CONTENT_NOTICE}\nKnown Domains To Exclude:\n${wrapUntrustedContent(context)}\n` : ""}
Task: ${payload}

Requirements:
1. "base_url": Exact technical endpoint where research articles live (e.g. 'https://research.checkpoint.com/', 'https://securelist.com/'), not just top-level corporate homepage.
2. "crawl_pattern": Recursive pattern ending with '/*' targeting that specific research endpoint.
3. Exclude generic news aggregators, marketing, or individual article URLs.
4. Output pure JSON only:
{"sources":[{"source_name":"...","domain":"...","crawl_pattern":"https://.../*","base_url":"https://...","primary_content":["Attack Chains","TTPs"],"why_crawl":"..."}]}`;

    case "DOMAIN_HARVESTER":
      return `[SKILL: DOMAIN_HARVESTER]
Task: Extract or identify authoritative technical threat intelligence articles, research papers, malware reverse-engineering posts, and attack chain timelines hosted on this domain.
Focus: DFIR timelines, loader mechanics, APT dossiers, CVE exploits, living-off-the-land techniques. Exclude marketing, generic news, privacy policies.
${UNTRUSTED_CONTENT_NOTICE}
Target Domain: ${payload}
${context ? `HTML / Context Excerpt:\n${wrapUntrustedContent(context)}\n` : ""}

Output pure JSON only:
{"domain":"...","resources":[{"url":"https://...","title":"...","estimatedType":"FULL_ATTACK_CHAIN","relevanceReason":"...","isHighValue":true}]}`;
  }
}

class WarmAgentService {
  private proc: ChildProcessWithoutNullStreams | null = null;
  private rl: readline.Interface | null = null;
  private currentModel: string = DEFAULT_AGY_MODEL;
  /** In-memory only; never persisted to disk. */
  private activeConversationId: string | null = null;
  private queue: TurnQueueItem[] = [];
  private activeTurn: ActiveTurn | null = null;
  private turnSeq = 0;
  private idleTimer: NodeJS.Timeout | null = null;
  private bootPromise: Promise<void> | null = null;
  private turnCount: number = 0;
  private workerReadyResolve: (() => void) | null = null;
  private lastStderr: string = "";

  constructor() {
    this.resetIdleTimer();
  }

  /**
   * Status overview for telemetry and health dashboards
   */
  getStatus() {
    return {
      isAlive: Boolean(this.proc && !this.proc.killed),
      pid: this.proc?.pid ?? null,
      currentModel: this.currentModel,
      activeConversationId: this.activeConversationId,
      queueLength: this.queue.length,
      isProcessing: this.activeTurn !== null,
      turnCount: this.turnCount,
    };
  }

  /**
   * Prewarm the agent in background so first prompt is instantly responsive
   */
  async prewarm(model?: string): Promise<boolean> {
    try {
      const targetModel = sanitizeAgyModel(model);
      await this.ensureProcess(targetModel);
      return Boolean(this.proc);
    } catch (err) {
      console.warn("[warm-agent] Prewarm warning:", (err as Error)?.message);
      return false;
    }
  }

  /**
   * Reset idle shutdown timer
   */
  private resetIdleTimer() {
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = setTimeout(() => {
      if (!this.activeTurn && this.queue.length === 0) {
        console.log("[warm-agent] Idle timeout reached. Gracefully closing warm agent process.");
        this.destroyProcess("idle_timeout");
      }
    }, IDLE_TIMEOUT_MS);
    this.idleTimer.unref?.();
  }

  /**
   * Ensure process is running with requested model (inside the container only)
   */
  private async ensureProcess(targetModel: string): Promise<void> {
    if (this.proc && !this.proc.killed && this.currentModel === targetModel) {
      return;
    }

    if (this.bootPromise) {
      await this.bootPromise;
      if (this.proc && !this.proc.killed && this.currentModel === targetModel) return;
    }

    if (this.proc && !this.proc.killed && this.currentModel !== targetModel) {
      console.log(`[warm-agent] Model change requested (${this.currentModel} -> ${targetModel}). Recycling worker.`);
      this.destroyProcess("model_change");
    }

    const runtime = detectSandboxRuntime();
    if (runtime.runtime !== "docker") {
      throw new Error(`Agent sandbox container unavailable: ${runtime.details}`);
    }

    this.bootPromise = this.spawnWorker(targetModel);
    try {
      await this.bootPromise;
    } finally {
      this.bootPromise = null;
    }
  }

  /**
   * Spawn containerized worker process (docker exec, args array, no shell)
   */
  private spawnWorker(model: string): Promise<void> {
    return new Promise((resolve) => {
      this.currentModel = model;
      console.log(`[warm-agent] Spawning warm agent worker in ${CONTAINER_NAME} with model ${model}...`);

      const args = ["exec", "-i", CONTAINER_NAME, "agy", ...buildAgentCliArgs(model)];
      if (this.activeConversationId) {
        args.push("--conversation", this.activeConversationId);
      }

      let isSettled = false;
      let initTimer: NodeJS.Timeout | null = null;
      const settleReady = () => {
        if (!isSettled) {
          isSettled = true;
          if (initTimer) clearTimeout(initTimer);
          this.workerReadyResolve = null;
          resolve();
        }
      };

      // If agy takes longer than 10s to emit init, allow turns to proceed
      initTimer = setTimeout(settleReady, 10000);
      this.workerReadyResolve = settleReady;

      let child: ChildProcessWithoutNullStreams;
      try {
        child = spawn("docker", args, { stdio: ["pipe", "pipe", "pipe"] });
      } catch (err) {
        console.error("[warm-agent] Failed to spawn docker child process:", (err as Error)?.message);
        settleReady();
        return;
      }

      this.proc = child;
      this.lastStderr = "";
      this.rl = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
      this.rl.on("line", (line) => {
        if (this.proc === child) this.handleStdoutLine(line);
      });

      child.stderr.on("data", (chunk) => {
        const str = chunk.toString();
        if (!str.includes("Print mode: not authenticated") && !str.includes("silent auth")) {
          this.lastStderr = str.trim().slice(0, 500);
        }
      });

      // Prevent EPIPE from crashing the server if the worker dies mid-write.
      child.stdin.on("error", () => {
        if (this.proc === child) this.destroyProcess("stdin_error");
      });

      child.on("error", (err) => {
        console.error("[warm-agent] Process spawn error:", err?.message);
        settleReady();
        if (this.proc === child) this.destroyProcess("spawn_error");
      });

      child.on("exit", (code, signal) => {
        settleReady();
        if (this.proc === child) {
          console.log(`[warm-agent] Process exited with code ${code}, signal ${signal}`);
          this.destroyProcess(`process_exit_${code ?? signal}`);
        }
      });
    });
  }

  /**
   * Handle parsed line from stream-json output
   */
  private handleStdoutLine(line: string) {
    const trimmed = line.trim();
    if (!trimmed) return;

    let data: any;
    try {
      data = JSON.parse(trimmed);
    } catch {
      return; // Plain text trace output is ignored
    }

    if (data.event === "init") {
      if (typeof data.conversation_id === "string" && data.conversation_id.length >= 8) {
        this.activeConversationId = data.conversation_id;
      }
      this.workerReadyResolve?.();
      return;
    }

    const turn = this.activeTurn;
    if (!turn || turn.inFallback) return;

    if (data.event === "step_update") {
      const stepUpdate = data.step_update || {};
      const step = data.step || {};
      if (stepUpdate.text_delta) {
        turn.response += stepUpdate.text_delta;
      } else if (step.type === "PLANNER_RESPONSE" && step.content) {
        turn.response = step.content;
      }
    } else if (data.event === "result") {
      const result = data.result || {};
      const finalResponse = String(result.response || turn.response || "").trim();
      const tokens = result.usage
        ? {
            inputTokens: result.usage.input_tokens || 0,
            outputTokens: result.usage.output_tokens || 0,
            totalTokens: result.usage.total_tokens || 0,
          }
        : undefined;
      this.turnCount++;
      this.settleTurn(turn, {
        success: result.status === "SUCCESS",
        text: finalResponse || (result.error ? `Error: ${result.error}` : "Analysis completed."),
        latencyMs: Date.now() - turn.startTime,
        model: this.currentModel,
        conversationId: this.activeConversationId || result.conversation_id,
        tokens,
        isWarm: true,
        error: result.error,
      });
    }
  }

  /**
   * Resolve a turn exactly once and start the next queued turn.
   */
  private settleTurn(turn: ActiveTurn, res: WarmInferenceResult) {
    if (this.activeTurn !== turn) return;
    if (turn.timer) {
      clearTimeout(turn.timer);
      turn.timer = null;
    }
    this.activeTurn = null;
    try {
      turn.item.resolve(res);
    } finally {
      this.resetIdleTimer();
      setImmediate(() => void this.processNextInQueue());
    }
  }

  /**
   * Hand the active turn to the cold one-shot path. The queue stays blocked
   * until the fallback settles this turn.
   */
  private failoverTurn(turn: ActiveTurn, reason: string) {
    if (this.activeTurn !== turn || turn.inFallback) return;
    turn.inFallback = true;
    if (turn.timer) {
      clearTimeout(turn.timer);
      turn.timer = null;
    }
    console.warn(`[warm-agent] Warm turn failed (${reason}); running one-shot fallback in sandbox.`);
    this.executeColdFallback(turn.item.prompt, turn.item.model, turn.item.timeoutMs)
      .then((res) => this.settleTurn(turn, res))
      .catch((err: any) =>
        this.settleTurn(turn, {
          success: false,
          text: "",
          latencyMs: Date.now() - turn.startTime,
          model: turn.item.model,
          isWarm: false,
          error: err?.message || "Agent execution failed.",
        })
      );
  }

  /**
   * Process next queued turn (one at a time)
   */
  private async processNextInQueue() {
    this.resetIdleTimer();
    if (this.activeTurn || this.queue.length === 0) return;

    const item = this.queue.shift();
    if (!item) return;

    const turn: ActiveTurn = {
      id: ++this.turnSeq,
      item,
      inFallback: false,
      response: "",
      startTime: Date.now(),
      timer: null,
    };
    this.activeTurn = turn;

    try {
      await this.ensureProcess(item.model);

      // The worker may have died (and failed this turn over) while booting.
      if (this.activeTurn !== turn || turn.inFallback) return;

      const proc = this.proc;
      if (!proc || proc.killed || !proc.stdin.writable) {
        throw new Error("Warm agent process is not writable");
      }

      // Stall guard: recycle the worker and fail over to a one-shot run.
      turn.timer = setTimeout(() => {
        if (this.activeTurn !== turn || turn.inFallback) return;
        console.warn(`[warm-agent] Warm stream timed out after ${item.timeoutMs}ms.`);
        this.failoverTurn(turn, "turn_timeout");
        this.destroyProcess("turn_timeout");
      }, item.timeoutMs);

      proc.stdin.write(encodeAgentUserTurn(item.prompt));
    } catch (err: any) {
      if (this.activeTurn === turn && !turn.inFallback) {
        this.failoverTurn(turn, `dispatch_error: ${err?.message || "unknown"}`);
      }
      this.destroyProcess("turn_dispatch_error");
    }
  }

  /**
   * One-shot execution inside the sandbox (stdin prompt, print mode, no tools).
   */
  private async executeColdFallback(
    prompt: string,
    model: string,
    timeoutMs: number
  ): Promise<WarmInferenceResult> {
    let sanitizedModel = sanitizeAgyModel(model);
    let res = await runAgentPromptInSandbox(prompt, { model: sanitizedModel, timeoutMs, category: "agent" });

    // Quota / subscription resilience: retry once with the default model.
    const errText = (res.error || "").toLowerCase();
    if (
      !res.success &&
      res.runtime === "docker" &&
      sanitizedModel !== DEFAULT_AGY_MODEL &&
      (errText.includes("quota") || errText.includes("subscription") || res.exitCode === 3)
    ) {
      console.warn(`[warm-agent] Model ${sanitizedModel} hit quota limits; retrying with ${DEFAULT_AGY_MODEL}`);
      sanitizedModel = DEFAULT_AGY_MODEL;
      res = await runAgentPromptInSandbox(prompt, { model: sanitizedModel, timeoutMs, category: "agent" });
    }

    return {
      success: res.success,
      text: res.success ? res.text : "",
      latencyMs: res.latencyMs,
      model: sanitizedModel,
      isWarm: false,
      tokens: res.tokens,
      error: res.success ? undefined : res.error || "Agent did not produce output.",
    };
  }

  /**
   * Terminate the worker. An in-flight warm turn is failed over to the
   * one-shot path (it is never resolved twice and the queue waits for it).
   */
  destroyProcess(reason: string) {
    if (this.rl) {
      try {
        this.rl.close();
      } catch {
        // readline already closed; safe during teardown.
      }
      this.rl = null;
    }
    const proc = this.proc;
    this.proc = null; // detach first so its exit handler is a no-op
    if (proc) {
      console.log(`[warm-agent] Destroying process (reason: ${reason})`);
      try {
        proc.kill("SIGKILL");
      } catch {
        // Process already exited; nothing to kill.
      }
    }

    const turn = this.activeTurn;
    if (turn && !turn.inFallback) {
      this.failoverTurn(turn, this.lastStderr ? `worker exited: ${this.lastStderr}` : reason);
    }
  }

  /**
   * Public inference API: queues turn and returns fast warm response
   */
  executePrompt(
    prompt: string,
    options?: { model?: string; timeoutMs?: number }
  ): Promise<WarmInferenceResult> {
    const model = sanitizeAgyModel(options?.model || this.currentModel);
    const timeoutMs = options?.timeoutMs || TURN_TIMEOUT_MS;

    return new Promise<WarmInferenceResult>((resolve) => {
      this.queue.push({ prompt, model, timeoutMs, resolve, startTime: Date.now() });
      void this.processNextInQueue();
    });
  }

  /**
   * Skill-Based Task Dispatch on the dedicated agent.
   */
  executeSkill(options: SkillOptions): Promise<WarmInferenceResult> {
    const prompt = buildSkillPrompt(options.skill, options.payload, options.context, options.history);
    return this.executePrompt(prompt, {
      model: options.model,
      timeoutMs: options.timeoutMs,
    });
  }

  /**
   * Get active consolidated conversation ID
   */
  getConversationId(): string | null {
    return this.activeConversationId;
  }

  /**
   * Start a fresh conversation: forget the current id and recycle the worker
   * so the next turn starts without `--conversation`.
   */
  resetConversation() {
    this.activeConversationId = null;
    this.destroyProcess("user_thread_reset");
  }
}

// Global Singleton Instance
export const warmAgentService = new WarmAgentService();
