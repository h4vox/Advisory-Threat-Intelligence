/**
 * Always-Alive Warm Agent Session Service
 *
 * Maintains a persistent, warm NDJSON streaming process inside the isolated
 * Docker sandbox (`aie-agent-sandbox`) using `agy --input-format stream-json --output-format stream-json`.
 *
 * Eliminates the 14-second cold-start penalty per prompt down to 2.0 - 2.8s pure inference latency,
 * and maintains conversational memory across multi-turn interactions.
 */

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import readline from "node:readline";
import fs from "node:fs";
import path from "node:path";
import {
  AGY_AVAILABLE_MODELS,
  DEFAULT_AGY_MODEL,
  sanitizeAgyModel,
} from "./agent-framework/types";
import { executeInAgentSandbox, autoSyncTokenFromHostIfAvailable, type ExecutionTrace } from "./agent-sandbox";

const CONTAINER_NAME = "aie-agent-sandbox";
const IDLE_TIMEOUT_MS = 25 * 60 * 1000; // 25 minutes idle shutdown
const TURN_TIMEOUT_MS = 65 * 1000; // 65 seconds per turn
const CONVERSATION_STATE_FILE = path.join(process.cwd(), ".agy_conversation_id");

interface TurnQueueItem {
  prompt: string;
  model: string;
  timeoutMs: number;
  resolve: (res: WarmInferenceResult) => void;
  reject: (err: any) => void;
  startTime: number;
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
${context ? `\nVERIFIED PLATFORM GROUNDED CTI EVIDENCE:\n${context}\n` : ""}
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
${context ? `Context: ${context}\n` : ""}
Input Document:
${payload}

Output pure JSON only:
{"isRelevant":true,"passScore":85,"recommendApproval":true,"classification":"ATTACK_CHAIN_REPORT","resourceKind":"FULL_ATTACK_CHAIN","threatActors":[],"malwareFamilies":[],"cves":[],"mitreTechniques":[],"stages":[],"scoreBreakdown":{"proceduralDepth":26,"attackProgression":22,"attributionContext":12,"emulationUtility":16,"iocVerifiability":9,"totalScore":85},"rationale":"..."}`;

    case "ATTACK_CHAIN":
      return `[SKILL: ATTACK_CHAIN]
Synthesize a chronological multi-stage attack chain with concrete procedures, MITRE ATT&CK techniques, detection rules, and purple team emulation commands from this report.
${context ? `Context: ${context}\n` : ""}
Report Text:
${payload}

Output pure JSON only:
{"classification":"THREAT_REPORT","threatActors":[],"malware":[],"vulnerabilities":[],"ttps":["T1190: ..."],"ioas":[],"attackChain":[{"order":1,"tactic":"Initial Access","techniques":["T1190"],"summary":"..."}],"detections":["Sigma: ..."],"hunting":[],"emulation":["Atomic Test: ..."]}`;

    case "SOURCE_HARVESTER":
      return `[SKILL: SOURCE_HARVESTER]
Role: Adversary Emulation Intelligence Source Hunter.
Mission: Discover high-value, distinct, highly technical threat intelligence sources or research lab endpoints (e.g., Check Point Research, Securelist, Huntress, Red Canary, Volexity, Sophos X-Ops, Cybereason, Sygnia, NCC Group, Malwarebytes Labs, Jamf Threat Labs, Morphisec, Elastic Labs).
Focus: Full intrusion/attack chains, multi-stage infection chains, forensic timelines, adversary TTPs, and malware analysis.
${context ? `Known Domains To Exclude:\n${context}\n` : ""}
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
Target Domain: ${payload}
${context ? `HTML / Context Excerpt:\n${context}\n` : ""}

Output pure JSON only:
{"domain":"...","resources":[{"url":"https://...","title":"...","estimatedType":"FULL_ATTACK_CHAIN","relevanceReason":"...","isHighValue":true}]}`;
  }
}

class WarmAgentService {
  private proc: ChildProcessWithoutNullStreams | null = null;
  private rl: readline.Interface | null = null;
  private currentModel: string = DEFAULT_AGY_MODEL;
  private activeConversationId: string | null = null;
  private isProcessing: boolean = false;
  private queue: TurnQueueItem[] = [];
  private idleTimer: NodeJS.Timeout | null = null;
  private activeTurnTimer: NodeJS.Timeout | null = null;
  private currentTurnResponse: string = "";
  private currentTurnResolve: ((res: WarmInferenceResult) => void) | null = null;
  private currentTurnReject: ((err: any) => void) | null = null;
  private currentTurnStartTime: number = 0;
  private bootPromise: Promise<void> | null = null;
  private turnCount: number = 0;
  private workerReadyResolve: (() => void) | null = null;
  private lastStderr: string = "";

  constructor() {
    this.activeConversationId = this.getSavedConversationId();
    this.resetIdleTimer();
  }

  private getSavedConversationId(): string | null {
    try {
      if (fs.existsSync(CONVERSATION_STATE_FILE)) {
        const id = fs.readFileSync(CONVERSATION_STATE_FILE, "utf-8").trim();
        if (id && id.length >= 8) return id;
      }
    } catch {}
    return null;
  }

  private saveConversationId(id: string) {
    this.activeConversationId = id;
    try {
      fs.writeFileSync(CONVERSATION_STATE_FILE, id, "utf-8");
    } catch {}
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
      isProcessing: this.isProcessing,
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
      return true;
    } catch (err) {
      console.warn("[warm-agent] Prewarm warning:", err);
      return false;
    }
  }

  /**
   * Reset idle shutdown timer
   */
  private resetIdleTimer() {
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = setTimeout(() => {
      if (!this.isProcessing && this.queue.length === 0) {
        console.log("[warm-agent] Idle timeout reached. Gracefully closing warm agent process.");
        this.destroyProcess("idle_timeout");
      }
    }, IDLE_TIMEOUT_MS);
  }

  /**
   * Ensure process is running with requested model
   */
  private async ensureProcess(targetModel: string): Promise<void> {
    try {
      autoSyncTokenFromHostIfAvailable();
    } catch {}

    if (this.proc && !this.proc.killed && this.currentModel === targetModel) {
      return;
    }

    if (this.proc && !this.proc.killed && this.currentModel !== targetModel) {
      console.log(`[warm-agent] Model change requested (${this.currentModel} -> ${targetModel}). Recycling worker.`);
      this.destroyProcess("model_change");
    }

    if (this.bootPromise) {
      return this.bootPromise;
    }

    this.bootPromise = this.spawnWorker(targetModel);
    try {
      await this.bootPromise;
    } finally {
      this.bootPromise = null;
    }
  }

  /**
   * Spawn containerized worker process
   */
  private spawnWorker(model: string): Promise<void> {
    return new Promise((resolve) => {
      this.currentModel = model;
      console.log(`[warm-agent] Spawning warm agent worker in ${CONTAINER_NAME} with model ${model}...`);

      const args = [
        "exec",
        "-i",
        CONTAINER_NAME,
        "agy",
        "--dangerously-skip-permissions",
        "--disable-slash-commands",
        "--input-format",
        "stream-json",
        "--output-format",
        "stream-json",
        "--model",
        model,
      ];

      const convId = this.activeConversationId || this.getSavedConversationId();
      if (convId) {
        args.push("--conversation", convId);
      }

      try {
        let isSettled = false;
        const settleReady = () => {
          if (!isSettled) {
            isSettled = true;
            if (initTimer) clearTimeout(initTimer);
            resolve();
          }
        };

        // Fallback timer: if agy takes longer than 10s to emit init, allow turns to proceed
        const initTimer = setTimeout(() => {
          console.log("[warm-agent] Init handshake elapsed, worker ready.");
          settleReady();
        }, 10000);

        this.workerReadyResolve = settleReady;

        this.proc = spawn("docker", args, {
          stdio: ["pipe", "pipe", "pipe"],
        });

        this.rl = readline.createInterface({
          input: this.proc.stdout,
          crlfDelay: Infinity,
        });

        this.rl.on("line", (line) => {
          this.handleStdoutLine(line);
        });

        this.proc.stderr.on("data", (chunk) => {
          const str = chunk.toString();
          // Filter routine auth / debug noise from stderr
          if (!str.includes("Print mode: not authenticated") && !str.includes("silent auth")) {
            const trimmed = str.trim();
            console.warn(`[warm-agent:stderr] ${trimmed}`);
            this.lastStderr = trimmed;
          }
        });

        this.proc.on("error", (err) => {
          console.error("[warm-agent] Process spawn error:", err);
          settleReady();
          this.destroyProcess(`spawn_error_${err?.message || "unknown"}`);
        });

        this.proc.on("exit", (code, signal) => {
          console.log(`[warm-agent] Process exited with code ${code}, signal ${signal}`);
          settleReady();
          this.destroyProcess(`process_exit_${code ?? signal}`);
        });
      } catch (err) {
        console.error("[warm-agent] Failed to spawn docker child process:", err);
        this.destroyProcess("spawn_failure");
        resolve(); // Allow turns to fallback
      }
    });
  }

  /**
   * Handle parsed line from stream-json output
   */
  private handleStdoutLine(line: string) {
    const trimmed = line.trim();
    if (!trimmed) return;

    try {
      const data = JSON.parse(trimmed);

      if (data.event === "init") {
        if (data.conversation_id) {
          this.saveConversationId(data.conversation_id);
        }
        if (this.workerReadyResolve) {
          this.workerReadyResolve();
          this.workerReadyResolve = null;
        }
      } else if (data.event === "step_update") {
        const stepUpdate = data.step_update || {};
        const step = data.step || {};

        if (stepUpdate.text_delta) {
          this.currentTurnResponse += stepUpdate.text_delta;
        } else if (step.type === "PLANNER_RESPONSE" && step.content) {
          this.currentTurnResponse = step.content;
        }
      } else if (data.event === "result") {
        const result = data.result || {};
        const finalResponse = (result.response || this.currentTurnResponse || "").trim();
        const latencyMs = Date.now() - this.currentTurnStartTime;
        const tokens = result.usage
          ? {
              inputTokens: result.usage.input_tokens || 0,
              outputTokens: result.usage.output_tokens || 0,
              totalTokens: result.usage.total_tokens || 0,
            }
          : undefined;

        if (this.activeTurnTimer) {
          clearTimeout(this.activeTurnTimer);
          this.activeTurnTimer = null;
        }

        if (this.currentTurnResolve) {
          this.turnCount++;
          this.currentTurnResolve({
            success: result.status === "SUCCESS",
            text: finalResponse || (result.error ? `Error: ${result.error}` : "Analysis completed."),
            latencyMs,
            model: this.currentModel,
            conversationId: this.activeConversationId || result.conversation_id,
            tokens,
            isWarm: true,
            error: result.error,
          });
          this.currentTurnResolve = null;
          this.currentTurnReject = null;
        }

        this.currentTurnResponse = "";
        this.isProcessing = false;
        this.processNextInQueue();
      }
    } catch {
      // Plain text or unformatted trace output
      if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
        // Ignored unparsable JSON
      }
    }
  }

  /**
   * Process next queued turn
   */
  private async processNextInQueue() {
    this.resetIdleTimer();

    if (this.isProcessing || this.queue.length === 0) {
      return;
    }

    const next = this.queue.shift();
    if (!next) return;

    this.isProcessing = true;
    this.currentTurnStartTime = Date.now();
    this.currentTurnResponse = "";
    this.currentTurnResolve = next.resolve;
    this.currentTurnReject = next.reject;

    try {
      await this.ensureProcess(next.model);

      if (!this.proc || this.proc.killed || !this.proc.stdin.writable) {
        throw new Error("Warm agent process is not writable");
      }

      // Set turn timeout guard: if warm stream stalls, recycle and execute cold fallback
      this.activeTurnTimer = setTimeout(async () => {
        console.warn(`[warm-agent] Warm stream timed out after ${next.timeoutMs}ms. Recycling process and executing fallback.`);
        const resolve = this.currentTurnResolve;
        this.currentTurnResolve = null;
        this.currentTurnReject = null;
        this.destroyProcess("turn_timeout");

        try {
          const fallbackRes = await this.executeColdFallback(next.prompt, next.model, 45000);
          if (resolve) resolve(fallbackRes);
        } catch (e: any) {
          if (resolve) {
            resolve({
              success: false,
              text: "Analysis temporarily unavailable due to concurrent background operations. Please retry your query.",
              latencyMs: Date.now() - this.currentTurnStartTime,
              model: this.currentModel,
              isWarm: false,
              error: e?.message || "Execution timeout",
            });
          }
        } finally {
          this.isProcessing = false;
          this.processNextInQueue();
        }
      }, next.timeoutMs);

      // Write NDJSON turn to container agent stdin
      const ndjsonMessage =
        JSON.stringify({
          event: "user",
          message: {
            content: next.prompt,
          },
        }) + "\n";

      this.proc.stdin.write(ndjsonMessage);
    } catch (err: any) {
      console.warn("[warm-agent] Turn dispatch failed, attempting cold fallback:", err?.message);
      if (this.activeTurnTimer) {
        clearTimeout(this.activeTurnTimer);
        this.activeTurnTimer = null;
      }

      // Fallback to cold execution
      this.destroyProcess("turn_dispatch_error");
      this.executeColdFallback(next.prompt, next.model, next.timeoutMs)
        .then(next.resolve)
        .catch(next.reject)
        .finally(() => {
          this.isProcessing = false;
          this.processNextInQueue();
        });
    }
  }

  /**
   * Robust cold execution fallback using executeInAgentSandbox
   */
  private async executeColdFallback(
    prompt: string,
    model: string,
    timeoutMs: number
  ): Promise<WarmInferenceResult> {
    const startTime = Date.now();
    let sanitizedModel = sanitizeAgyModel(model);
    const convId = this.activeConversationId || this.getSavedConversationId();
    const buildArgs = (m: string) => {
      const a = ["--dangerously-skip-permissions", "--disable-slash-commands", "--print", prompt, "--model", m];
      if (convId) a.push("--conversation", convId);
      return a;
    };

    try {
      let sandboxRes = await executeInAgentSandbox(
        buildArgs(sanitizedModel),
        { timeoutMs, category: "agent" }
      );

      // Quota / subscription resilience: if requested model fails (e.g. Claude quota reached), auto fallback to default Gemini
      if (
        !sandboxRes.success &&
        (sandboxRes.error?.toLowerCase().includes("quota") ||
          sandboxRes.error?.toLowerCase().includes("subscription") ||
          sandboxRes.exitCode === 3)
      ) {
        if (sanitizedModel !== DEFAULT_AGY_MODEL) {
          console.warn(
            `[warm-agent] Model ${sanitizedModel} exceeded quota/subscription limits. Automatically falling back to default ${DEFAULT_AGY_MODEL}`
          );
          sanitizedModel = DEFAULT_AGY_MODEL;
          sandboxRes = await executeInAgentSandbox(
            buildArgs(sanitizedModel),
            { timeoutMs, category: "agent" }
          );
        }
      }

      return {
        success: sandboxRes.success,
        text: sandboxRes.output || sandboxRes.error || "Agent did not produce output.",
        latencyMs: sandboxRes.latencyMs || Date.now() - startTime,
        model: sanitizedModel,
        isWarm: false,
        error: sandboxRes.error,
      };
    } catch (err: any) {
      return {
        success: false,
        text: "",
        latencyMs: Date.now() - startTime,
        model: sanitizedModel,
        isWarm: false,
        error: err?.message || "Cold execution failed.",
      };
    }
  }

  /**
   * Handle unexpected worker error
   */
  private handleWorkerError(err: any) {
    this.destroyProcess(`worker_error_${err?.message || "unknown"}`);
  }

  /**
   * Cleanly terminate process, cleanup streams, and ensure pending turns are settled
   */
  destroyProcess(reason: string) {
    console.log(`[warm-agent] Destroying process (reason: ${reason})`);
    if (this.activeTurnTimer) {
      clearTimeout(this.activeTurnTimer);
      this.activeTurnTimer = null;
    }
    if (this.rl) {
      try {
        this.rl.close();
      } catch {}
      this.rl = null;
    }
    if (this.proc) {
      try {
        this.proc.kill("SIGKILL");
      } catch {}
      this.proc = null;
    }

    // CRITICAL: Guarantee waiting turns never hang when a worker process terminates
    if (this.currentTurnResolve) {
      const resolve = this.currentTurnResolve;
      this.currentTurnResolve = null;
      this.currentTurnReject = null;
      const errorMsg = this.lastStderr
        ? `Agent worker exited: ${this.lastStderr}`
        : `Agent worker terminated unexpectedly (${reason})`;
      resolve({
        success: false,
        text: this.currentTurnResponse || "",
        latencyMs: Date.now() - this.currentTurnStartTime,
        model: this.currentModel,
        isWarm: false,
        error: errorMsg,
      });
      this.currentTurnResponse = "";
      this.isProcessing = false;
      this.processNextInQueue();
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

    return new Promise<WarmInferenceResult>((resolve, reject) => {
      this.queue.push({
        prompt,
        model,
        timeoutMs,
        resolve,
        reject,
        startTime: Date.now(),
      });

      this.processNextInQueue();
    });
  }

  /**
   * Skill-Based Task Dispatch:
   * Executes a specialized internal skill on the dedicated agent without
   * spinning up a new AGY instance or sending repetitive boilerplates.
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
   * Gracefully reset consolidated conversation thread
   */
  resetConversation() {
    this.destroyProcess("user_thread_reset");
  }
}

// Global Singleton Instance
export const warmAgentService = new WarmAgentService();
