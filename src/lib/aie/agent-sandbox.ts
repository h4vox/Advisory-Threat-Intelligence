import { execFile, execFileSync, execSync, spawn, type ChildProcess } from "node:child_process";
import { DEFAULT_AGY_CLI_FLAVOR, agyStreamJsonArgs, nextAgyCliFlavor, type AgyCliFlavor } from "./agy-cli-flags";
import readline from "node:readline";
import { sanitizeAgyModel } from "./agent-framework/types";

export type SandboxRuntime = "docker" | "wsl" | "native" | "unavailable";

export type LogLevel =
  | "DEBUG"
  | "INFO"
  | "WARN"
  | "ERROR"
  | "EXEC"
  | "STDOUT"
  | "STDERR"
  | "AUTH"
  | "AUDIT";

export type LogCategory = "sandbox" | "install" | "auth" | "agent" | "system" | "network" | "intel";

export interface SandboxLogEntry {
  id: string;
  timestamp: string; // ISO 8601
  formattedTime: string; // [YYYY-MM-DD HH:mm:ss.SSS]
  level: LogLevel;
  category: LogCategory;
  message: string;
  meta?: Record<string, any>;
}

export interface ExecutionTrace {
  id: string;
  command: string;
  args: string[];
  fullCommandStr: string;
  runtime: SandboxRuntime;
  containerName: string;
  pid?: number;
  startTime: string;
  endTime?: string;
  latencyMs: number;
  exitCode: number | null;
  stdoutBytes: number;
  stderrBytes: number;
  status: "success" | "error" | "timeout";
  stepLogs: string[];
}

export interface SandboxStatus {
  runtime: SandboxRuntime;
  dockerAvailable: boolean;
  containerRunning: boolean;
  containerName: string;
  hostPlatform: NodeJS.Platform;
  binaryPath: string;
  isReady: boolean;
  agentVersion?: string;
  details: string;
  logCount?: number;
}

const CONTAINER_NAME = "aie-agent-sandbox";
export const AGENT_CONTAINER_NAME = CONTAINER_NAME;
/** Non-root user inside the sandbox image (see docker/agent-sandbox/Dockerfile). */
export const AGENT_CONTAINER_UID = 10001;
export const AGENT_CONTAINER_HOME = "/home/agent";

// ---------------------------------------------------------------------------
// In-Memory Ring Buffer for High-Detail Diagnostics & Telemetry
// ---------------------------------------------------------------------------
const MAX_LOGS = 1000;
const logBuffer: SandboxLogEntry[] = [];

export function appendSandboxLog(
  level: LogLevel,
  category: LogCategory,
  message: string,
  meta?: Record<string, any>
): SandboxLogEntry {
  const now = new Date();
  const pad = (n: number, s = 2) => n.toString().padStart(s, "0");
  const formattedTime = `[${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}.${pad(now.getMilliseconds(), 3)}]`;

  const entry: SandboxLogEntry = {
    id: `log-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    timestamp: now.toISOString(),
    formattedTime,
    level,
    category,
    message,
    meta,
  };

  logBuffer.push(entry);
  if (logBuffer.length > MAX_LOGS) {
    logBuffer.shift();
  }
  return entry;
}

export function getRecentSandboxLogs(options?: {
  limit?: number;
  level?: LogLevel;
  category?: LogCategory;
  search?: string;
}): SandboxLogEntry[] {
  let filtered = [...logBuffer];
  if (options?.level) {
    filtered = filtered.filter((l) => l.level === options.level);
  }
  if (options?.category) {
    filtered = filtered.filter((l) => l.category === options.category);
  }
  if (options?.search) {
    const q = options.search.toLowerCase();
    filtered = filtered.filter(
      (l) => l.message.toLowerCase().includes(q) || l.level.toLowerCase().includes(q)
    );
  }
  const limit = options?.limit || 250;
  return filtered.slice(-limit);
}

export function clearSandboxLogs(): void {
  logBuffer.length = 0;
  appendSandboxLog("INFO", "system", "Diagnostics log buffer cleared by operator.");
}

// ---------------------------------------------------------------------------
// Runtime Detection with In-Memory Caching (15-second TTL)
// ---------------------------------------------------------------------------
let cachedRuntimeStatus: { status: SandboxStatus; expiresAt: number } | null = null;
const CACHE_TTL_MS = 15000;

export function invalidateSandboxCache(): void {
  cachedRuntimeStatus = null;
}

export type AgySandboxProbe = { usable: boolean; detail: string };
const AGY_PROBE_TTL_MS = 120_000;

/** Forgets the cached agent probe and runtime status (after an install, a rebuild or a sign-in). */
export function invalidateAgyProbe(): void {
  (globalThis as typeof globalThis & { __aieAgyProbe?: unknown }).__aieAgyProbe = undefined;
  invalidateSandboxCache();
}

/**
 * Non-blocking check that the sandbox container is running and holds a real `agy` CLI (the bundled
 * shim prints no version). Used by the crawler to skip the agent up front instead of making every
 * article wait out a timeout. Async `execFile`, never the synchronous probes, so a slow or missing
 * Docker cannot freeze the server; cached per process.
 */
export async function probeAgySandboxUsable(): Promise<AgySandboxProbe> {
  const g = globalThis as typeof globalThis & { __aieAgyProbe?: { at: number; result: AgySandboxProbe } };
  if (g.__aieAgyProbe && Date.now() - g.__aieAgyProbe.at < AGY_PROBE_TTL_MS) return g.__aieAgyProbe.result;
  const result = await new Promise<AgySandboxProbe>((resolve) => {
    execFile("docker", ["exec", CONTAINER_NAME, "agy", "--version"], { timeout: 6000, encoding: "utf-8" }, (err, stdout) => {
      if (err) {
        const why = String(err.message || err).split("\n")[0].slice(0, 140);
        resolve({ usable: false, detail: `sandbox container ${CONTAINER_NAME} is not reachable (${why})` });
        return;
      }
      const version = String(stdout || "").trim();
      resolve(version ? { usable: true, detail: `agy ${version.slice(0, 60)}` } : { usable: false, detail: "the sandbox has no real agy CLI (bundled shim)" });
    });
  });
  g.__aieAgyProbe = { at: Date.now(), result };
  return result;
}

export function detectSandboxRuntime(options?: { forceRefresh?: boolean }): SandboxStatus {
  const now = Date.now();
  if (!options?.forceRefresh && cachedRuntimeStatus && cachedRuntimeStatus.expiresAt > now) {
    return {
      ...cachedRuntimeStatus.status,
      logCount: logBuffer.length,
    };
  }

  const isWin = process.platform === "win32";
  let dockerAvailable = false;
  let containerRunning = false;

  // 1. Check if Docker daemon is operational
  try {
    const dockerVer = execSync("docker --version", {
      encoding: "utf-8",
      timeout: 3000,
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    dockerAvailable = true;
    appendSandboxLog("DEBUG", "sandbox", `Host Docker daemon operational: ${dockerVer}`);
  } catch (err: any) {
    dockerAvailable = false;
    appendSandboxLog("WARN", "sandbox", `Host Docker daemon probe failed: ${err?.message}`);
  }

  // 2. Check if the agent sandbox container is running
  if (dockerAvailable) {
    try {
      const inspect = execSync(
        `docker inspect -f "{{.State.Running}}" ${CONTAINER_NAME}`,
        { encoding: "utf-8", timeout: 4000, stdio: ["ignore", "pipe", "ignore"] }
      ).trim();
      containerRunning = inspect === "true";
      appendSandboxLog(
        containerRunning ? "INFO" : "DEBUG",
        "sandbox",
        `Container '${CONTAINER_NAME}' state check: running=${containerRunning}`
      );
    } catch (err: any) {
      containerRunning = false;
      appendSandboxLog("DEBUG", "sandbox", `Container '${CONTAINER_NAME}' not found or stopped`);
    }
  }

  // Docker sandbox runtime active
  if (dockerAvailable && containerRunning) {
    let agentVersion = "";
    try {
      agentVersion = execSync(
        `docker exec ${CONTAINER_NAME} agy --version`, // constant command, no user input
        { encoding: "utf-8", timeout: 5000, stdio: ["ignore", "pipe", "ignore"] }
      ).trim();
    } catch {
      // Version probe is informational; empty string when agy is unavailable.
    }

    const result: SandboxStatus = {
      runtime: "docker",
      dockerAvailable: true,
      containerRunning: true,
      containerName: CONTAINER_NAME,
      hostPlatform: process.platform,
      binaryPath: `/usr/local/bin/agy`,
      isReady: true,
      agentVersion: agentVersion || undefined,
      details: `Isolated Docker sandbox (${CONTAINER_NAME}) operational. All agent executions sandboxed.`,
      logCount: logBuffer.length,
    };
    cachedRuntimeStatus = { status: result, expiresAt: now + CACHE_TTL_MS };
    return result;
  }

  // Strictly container-only isolation: never fall back to host binary
  const result: SandboxStatus = {
    runtime: "unavailable",
    dockerAvailable,
    containerRunning: false,
    containerName: CONTAINER_NAME,
    hostPlatform: process.platform,
    binaryPath: "/usr/local/bin/agy",
    isReady: false,
    agentVersion: undefined,
    details: dockerAvailable
      ? `Dedicated agent container (${CONTAINER_NAME}) is not running. Launch container environment to proceed.`
      : "Docker daemon is not accessible on host. Container sandbox runtime requires Docker.",
    logCount: logBuffer.length,
  };
  cachedRuntimeStatus = { status: result, expiresAt: now + CACHE_TTL_MS };
  return result;
}

// ---------------------------------------------------------------------------
// Container hardening (mirrors docker-compose.agent-sandbox.yml)
// ---------------------------------------------------------------------------
/** Persistent volume holding the agent's home: the CLI's own sign-in and settings live there. */
export const AGENT_HOME_VOLUME = "aie-agent-home";
/** Volume used by older versions (mounted at ~/.gemini only). */
export const LEGACY_AGENT_VOLUME = "aie-agent-vault";

/**
 * `docker run` arguments used when compose is unavailable. Kept in sync with
 * docker-compose.agent-sandbox.yml: non-root user, all capabilities dropped,
 * no-new-privileges, read-only root fs with tmpfs scratch space, resource
 * limits, and only the dedicated home volume (never a host directory).
 * Network access is kept because the agent must reach the model API.
 */
export function hardenedDockerRunArgs(): string[] {
  const uidGid = `${AGENT_CONTAINER_UID}:${AGENT_CONTAINER_UID}`;
  return [
    "run",
    "-d",
    "--init",
    "--name",
    CONTAINER_NAME,
    "--restart",
    "unless-stopped",
    "--user",
    uidGid,
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges:true",
    "--read-only",
    "--tmpfs",
    "/tmp:rw,noexec,nosuid,nodev,size=64m",
    "--tmpfs",
    `/workspace:rw,noexec,nosuid,nodev,size=32m,uid=${AGENT_CONTAINER_UID},gid=${AGENT_CONTAINER_UID}`,
    "--pids-limit",
    "256",
    "--memory",
    "1g",
    "--cpus",
    "1.5",
    "-v",
    `${AGENT_HOME_VOLUME}:${AGENT_CONTAINER_HOME}`,
    "-e",
    "AGENT_ENV=isolated_sandbox",
    "-e",
    `HOME=${AGENT_CONTAINER_HOME}`,
    "aie-agent-sandbox:latest",
    "tail",
    "-f",
    "/dev/null",
  ];
}

// ---------------------------------------------------------------------------
// Autonomous Lifecycle: Ensure Sandbox Container Is Running
// ---------------------------------------------------------------------------
export async function ensureAgentSandboxRunning(): Promise<{
  success: boolean;
  message: string;
  status: SandboxStatus;
}> {
  appendSandboxLog("INFO", "sandbox", `[LIFECYCLE] Initiating ensureAgentSandboxRunning check...`);
  const current = detectSandboxRuntime();
  if (current.runtime === "docker" && current.containerRunning) {
    appendSandboxLog("INFO", "sandbox", `Container ${CONTAINER_NAME} already running and healthy.`);
    return {
      success: true,
      message: `Container ${CONTAINER_NAME} is already running and healthy.`,
      status: current,
    };
  }

  if (!current.dockerAvailable) {
    const msg = "Docker is not accessible. The agent only runs inside its sandbox container, so agent features are unavailable.";
    appendSandboxLog("WARN", "sandbox", msg);
    return { success: false, message: msg, status: current };
  }

  try {
    // Check if container exists in stopped state
    const psAll = execFileSync(
      "docker",
      ["ps", "-a", "--filter", `name=^${CONTAINER_NAME}$`, "--format", "{{.Names}}"],
      { encoding: "utf-8", timeout: 5000 }
    ).trim();

    if (psAll === CONTAINER_NAME) {
      appendSandboxLog("INFO", "sandbox", `Container ${CONTAINER_NAME} exists in stopped state. Starting...`);
      execFileSync("docker", ["start", CONTAINER_NAME], { encoding: "utf-8", timeout: 10000 });
      appendSandboxLog("INFO", "sandbox", `Container ${CONTAINER_NAME} started.`);
    } else {
      appendSandboxLog("INFO", "sandbox", `Deploying fresh instance of ${CONTAINER_NAME} via compose...`);
      try {
        execFileSync("docker", ["compose", "-f", "docker-compose.agent-sandbox.yml", "up", "-d"], {
          encoding: "utf-8",
          timeout: 20000,
        });
        appendSandboxLog("INFO", "sandbox", `docker compose up -d executed cleanly.`);
      } catch (composeErr: any) {
        appendSandboxLog(
          "WARN",
          "sandbox",
          `docker compose failed. Falling back to hardened docker run of the prebuilt image...`
        );
        execFileSync("docker", hardenedDockerRunArgs(), { encoding: "utf-8", timeout: 15000 });
        appendSandboxLog("INFO", "sandbox", `Hardened container run command initialized.`);
      }
    }

    invalidateSandboxCache();
    const updated = detectSandboxRuntime({ forceRefresh: true });
    if (!updated.isReady) {
      return {
        success: false,
        message: `Agent sandbox container (${CONTAINER_NAME}) did not become ready.`,
        status: updated,
      };
    }
    appendSandboxLog("INFO", "sandbox", `Sandbox container (${CONTAINER_NAME}) verified online.`);
    return {
      success: true,
      message: `Agent Sandbox container (${CONTAINER_NAME}) successfully initialized.`,
      status: updated,
    };
  } catch (err: any) {
    invalidateSandboxCache();
    appendSandboxLog(
      "ERROR",
      "sandbox",
      `Failed to launch sandbox container: ${err?.message || "Unknown docker error"}`
    );
    return {
      success: false,
      message: `Could not start sandbox container: ${err?.message || "Unknown docker error"}`,
      status: detectSandboxRuntime({ forceRefresh: true }),
    };
  }
}

// Credentials: the agent CLI keeps its own Google sign-in in its home (the `aie-agent-home` volume).
// AIE never writes, reads or exports them; sign-in runs through the CLI (see ./agy-login.server).

// ---------------------------------------------------------------------------
// Process execution helpers
// ---------------------------------------------------------------------------
/** Flags that must never be passed to the agent CLI. */
const FORBIDDEN_AGENT_FLAGS = new Set(["--dangerously-skip-permissions", "--yolo"]);

/**
 * Diagnostic sub-commands that may be run through executeInAgentSandbox.
 * Model prompts must go through runAgentPromptInSandbox (stdin, print mode).
 */
const DIAGNOSTIC_COMMANDS = new Set(["--version", "--help", "models"]);

function makeTrace(
  traceId: string,
  label: string,
  runtime: SandboxRuntime,
  startTime: number,
  fields: Partial<ExecutionTrace> & Pick<ExecutionTrace, "status" | "exitCode" | "stepLogs">
): ExecutionTrace {
  return {
    id: traceId,
    // Command lines / argv / prompts are deliberately not included in traces.
    command: "agy",
    args: [],
    fullCommandStr: `agy ${label} (sandboxed)`,
    runtime,
    containerName: CONTAINER_NAME,
    startTime: new Date(startTime).toISOString(),
    endTime: new Date().toISOString(),
    latencyMs: Date.now() - startTime,
    stdoutBytes: 0,
    stderrBytes: 0,
    ...fields,
  };
}

/**
 * Run a diagnostic agent CLI command (`--version`, `--help`, `models`) inside
 * the sandbox container. Never runs on the host; returns an error result when
 * the container is unavailable. Not for model prompts.
 */
export function executeInAgentSandbox(
  args: string[],
  options?: { timeoutMs?: number; input?: string; category?: LogCategory }
): Promise<{
  success: boolean;
  output: string;
  error?: string;
  latencyMs: number;
  runtime: SandboxRuntime;
  exitCode: number | null;
  logs: string[];
  trace: ExecutionTrace;
}> {
  const startTime = Date.now();
  const timeoutMs = options?.timeoutMs || 45000;
  const category = options?.category || "agent";
  const traceId = `trace-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
  const stepLogs: string[] = [];
  const label = args.length === 1 && DIAGNOSTIC_COMMANDS.has(args[0]) ? args[0] : "command";

  const addStepLog = (level: LogLevel, msg: string) => {
    const entry = appendSandboxLog(level, category, msg, { traceId });
    stepLogs.push(`${entry.formattedTime} [${level}] ${msg}`);
  };

  const fail = (error: string, runtime: SandboxRuntime) => {
    addStepLog("ERROR", error);
    return {
      success: false,
      output: "",
      error,
      latencyMs: Date.now() - startTime,
      runtime,
      exitCode: -1,
      logs: stepLogs,
      trace: makeTrace(traceId, label, runtime, startTime, { status: "error", exitCode: -1, stepLogs }),
    };
  };

  if (args.length !== 1 || !DIAGNOSTIC_COMMANDS.has(args[0]) || args.some((a) => FORBIDDEN_AGENT_FLAGS.has(a))) {
    return Promise.resolve(
      fail("Refused: only diagnostic agent commands (--version, --help, models) may run here.", "unavailable")
    );
  }

  const status = detectSandboxRuntime();
  if (status.runtime !== "docker") {
    return Promise.resolve(
      fail(
        `Agent container runtime unavailable (${status.details}). Execution requires the dedicated container (${CONTAINER_NAME}).`,
        "unavailable"
      )
    );
  }

  return new Promise((resolve) => {
    const finalArgs = ["exec", "-i", CONTAINER_NAME, "agy", ...args];
    addStepLog("EXEC", `Dispatched agy ${label} inside ${CONTAINER_NAME}`);

    let settled = false;
    const settle = (value: Awaited<ReturnType<typeof executeInAgentSandbox>>) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };

    let proc: ChildProcess;
    let stdout = "";
    let stderr = "";

    try {
      proc = spawn("docker", finalArgs, { stdio: ["pipe", "pipe", "pipe"] });
    } catch (spawnErr: any) {
      return settle(fail(`Failed to start sandboxed process: ${spawnErr?.message}`, status.runtime));
    }

    const timer = setTimeout(() => {
      try {
        proc.kill("SIGKILL");
      } catch {
        // Process already exited; nothing to kill.
      }
      addStepLog("ERROR", `Agent sandbox execution timed out after ${Math.round(timeoutMs / 1000)}s`);
      settle({
        success: false,
        output: stdout.trim(),
        error: `Agent sandbox execution timed out after ${Math.round(timeoutMs / 1000)}s`,
        latencyMs: Date.now() - startTime,
        runtime: status.runtime,
        exitCode: -1,
        logs: stepLogs,
        trace: makeTrace(traceId, label, status.runtime, startTime, {
          status: "timeout",
          exitCode: -1,
          stepLogs,
          pid: proc.pid,
          stdoutBytes: Buffer.byteLength(stdout),
          stderrBytes: Buffer.byteLength(stderr),
        }),
      });
    }, timeoutMs);

    // Mandatory error listener prevents Node from crashing on ENOENT / spawn failure.
    proc.on("error", (err: any) => {
      clearTimeout(timer);
      settle(fail(`Sandbox process error: ${err?.message || "Execution failed"}`, status.runtime));
    });

    if (proc.stdin) {
      try {
        if (options?.input) proc.stdin.write(options.input);
        proc.stdin.end();
      } catch (err) {
        console.warn("[agent-sandbox] failed writing prompt to sandbox stdin:", err);
      }
    }

    proc.stdout?.on("data", (chunk: Buffer) => {
      if (stdout.length < MAX_CAPTURE_BYTES) stdout += chunk.toString("utf-8");
    });
    proc.stderr?.on("data", (chunk: Buffer) => {
      if (stderr.length < MAX_CAPTURE_BYTES) stderr += chunk.toString("utf-8");
    });

    proc.on("close", (code) => {
      clearTimeout(timer);
      const latencyMs = Date.now() - startTime;
      const cleanOut = stdout.trim();
      const cleanErr = stderr.trim();
      addStepLog(
        code === 0 ? "INFO" : "WARN",
        `Process exited with code ${code} (latency ${latencyMs}ms, stdout ${Buffer.byteLength(stdout)} bytes, stderr ${Buffer.byteLength(stderr)} bytes)`
      );
      const ok = code === 0 && cleanOut.length > 0;
      settle({
        success: ok,
        output: cleanOut || cleanErr,
        error: code !== 0 ? `Process exited with code ${code}${cleanErr ? `: ${cleanErr.slice(0, 300)}` : ""}` : undefined,
        latencyMs,
        runtime: status.runtime,
        exitCode: code,
        logs: stepLogs,
        trace: makeTrace(traceId, label, status.runtime, startTime, {
          status: ok ? "success" : "error",
          exitCode: code,
          stepLogs,
          pid: proc.pid,
          stdoutBytes: Buffer.byteLength(stdout),
          stderrBytes: Buffer.byteLength(stderr),
        }),
      });
    });
  });
}

const MAX_CAPTURE_BYTES = 4 * 1024 * 1024;

// Flag form the installed CLI accepts (see ./agy-cli-flags), learnt from its usage errors, per process.
const agyFlags = globalThis as typeof globalThis & { __aieAgyCliFlavor?: AgyCliFlavor };
agyFlags.__aieAgyCliFlavor ??= { ...DEFAULT_AGY_CLI_FLAVOR };

/**
 * Agent CLI flags for every model invocation:
 * - stream-json input and output: the prompt travels over stdin, never argv.
 * - `--print=` (last, value attached): non-interactive print mode.
 * - no `--dangerously-skip-permissions`: tool calls need interactive approval,
 *   which cannot be given in print mode, so the agent cannot run tools.
 * - `--disable-slash-commands`: no slash-command side effects.
 * `extra` (e.g. `--conversation <id>`) goes before the print flag.
 */
export function buildAgentCliArgs(model: string, extra: string[] = []): string[] {
  return agyStreamJsonArgs(agyFlags.__aieAgyCliFlavor!, sanitizeAgyModel(model), extra);
}

/**
 * Adapts the flags to a usage error from the CLI (exit code 2). True when they changed, so the
 * caller can run the prompt again; false when the error is not about these flags.
 */
export function adaptAgentCliFlags(errorText: string): boolean {
  const next = nextAgyCliFlavor(agyFlags.__aieAgyCliFlavor!, errorText);
  if (!next) return false;
  agyFlags.__aieAgyCliFlavor = next;
  appendSandboxLog("WARN", "agent", `The agent CLI refused the previous flags; now using: agy ${agyStreamJsonArgs(next, "<model>").join(" ")}`);
  return true;
}

/** NDJSON user turn written to the agent's stdin. */
export function encodeAgentUserTurn(prompt: string): string {
  return JSON.stringify({ event: "user", message: { content: prompt } }) + "\n";
}

export interface AgentPromptResult {
  success: boolean;
  text: string;
  error?: string;
  latencyMs: number;
  runtime: SandboxRuntime;
  exitCode: number | null;
  model: string;
  tokens?: { inputTokens: number; outputTokens: number; totalTokens: number };
  trace: ExecutionTrace;
}

/**
 * One-shot model prompt inside the sandbox container.
 * The prompt is delivered over stdin (stream-json), the CLI runs in print mode
 * without permission bypass, and nothing ever runs on the host. Always
 * resolves (never throws); an unavailable container yields an error result.
 */
export async function runAgentPromptInSandbox(
  prompt: string,
  options: { model?: string; timeoutMs?: number; category?: LogCategory }
): Promise<AgentPromptResult> {
  // A usage error (exit 2) about our flags is answered once per flag form: adapt and run again.
  for (let attempt = 0; ; attempt++) {
    const res = await runAgentPromptOnce(prompt, options);
    if (res.success || res.exitCode !== 2 || attempt >= 2 || !adaptAgentCliFlags(res.error || "")) return res;
  }
}

function runAgentPromptOnce(
  prompt: string,
  options: { model?: string; timeoutMs?: number; category?: LogCategory }
): Promise<AgentPromptResult> {
  const startTime = Date.now();
  const timeoutMs = options.timeoutMs || 60000;
  const category = options.category || "agent";
  const model = sanitizeAgyModel(options.model);
  const traceId = `trace-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
  const stepLogs: string[] = [];

  const addStepLog = (level: LogLevel, msg: string) => {
    const entry = appendSandboxLog(level, category, msg, { traceId });
    stepLogs.push(`${entry.formattedTime} [${level}] ${msg}`);
  };

  const status = detectSandboxRuntime();
  if (status.runtime !== "docker") {
    const error = `Agent sandbox container (${CONTAINER_NAME}) is unavailable: ${status.details}`;
    addStepLog("ERROR", error);
    return Promise.resolve({
      success: false,
      text: "",
      error,
      latencyMs: Date.now() - startTime,
      runtime: "unavailable",
      exitCode: -1,
      model,
      trace: makeTrace(traceId, "prompt", "unavailable", startTime, { status: "error", exitCode: -1, stepLogs }),
    });
  }

  return new Promise((resolve) => {
    let settled = false;
    let stdoutBytes = 0;
    let stderr = "";
    let streamedText = "";
    let rawText = "";
    let proc: ChildProcess | null = null;
    let timer: NodeJS.Timeout | null = null;

    const finish = (
      res: Omit<AgentPromptResult, "latencyMs" | "runtime" | "model" | "trace">,
      traceStatus: ExecutionTrace["status"]
    ) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      const latencyMs = Date.now() - startTime;
      addStepLog(
        res.success ? "INFO" : "WARN",
        `Agent prompt ${traceStatus} (latency ${latencyMs}ms, stdout ${stdoutBytes} bytes)`
      );
      // Stop the process once we have what we need.
      if (proc) {
        try {
          proc.stdin?.end();
        } catch {
          // stdin already closed; safe to ignore during shutdown.
        }
        const p = proc;
        setTimeout(() => {
          try {
            if (p.exitCode === null) p.kill("SIGKILL");
          } catch {
            // Process already exited; nothing to kill.
          }
        }, 2000).unref?.();
      }
      resolve({
        ...res,
        latencyMs,
        runtime: status.runtime,
        model,
        trace: makeTrace(traceId, "prompt", status.runtime, startTime, {
          status: traceStatus,
          exitCode: res.exitCode,
          stepLogs,
          pid: proc?.pid,
          stdoutBytes,
          stderrBytes: Buffer.byteLength(stderr),
        }),
      });
    };

    try {
      proc = spawn("docker", ["exec", "-i", CONTAINER_NAME, "agy", ...buildAgentCliArgs(model)], {
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch (spawnErr: any) {
      return finish(
        { success: false, text: "", error: `Failed to start sandboxed agent: ${spawnErr?.message}`, exitCode: -1 },
        "error"
      );
    }
    addStepLog("EXEC", `Dispatched agent prompt (${Buffer.byteLength(prompt)} bytes via stdin) inside ${CONTAINER_NAME}`);

    timer = setTimeout(() => {
      try {
        proc?.kill("SIGKILL");
      } catch {
        // Process already exited; nothing to kill.
      }
      finish(
        {
          success: false,
          text: "",
          error: `Agent sandbox execution timed out after ${Math.round(timeoutMs / 1000)}s`,
          exitCode: -1,
        },
        "timeout"
      );
    }, timeoutMs);

    proc.on("error", (err: any) => {
      finish({ success: false, text: "", error: `Sandbox process error: ${err?.message || "unknown"}`, exitCode: -1 }, "error");
    });

    const rl = readline.createInterface({ input: proc.stdout!, crlfDelay: Infinity });
    rl.on("line", (line) => {
      stdoutBytes += Buffer.byteLength(line) + 1;
      const trimmed = line.trim();
      if (!trimmed) return;
      let data: any;
      try {
        data = JSON.parse(trimmed);
      } catch {
        if (rawText.length < MAX_CAPTURE_BYTES) rawText += `${line}\n`;
        return;
      }
      if (data?.event === "step_update") {
        const stepUpdate = data.step_update || {};
        const step = data.step || {};
        if (stepUpdate.text_delta) {
          if (streamedText.length < MAX_CAPTURE_BYTES) streamedText += stepUpdate.text_delta;
        } else if (step.type === "PLANNER_RESPONSE" && typeof step.content === "string") {
          streamedText = step.content;
        }
      } else if (data?.event === "result") {
        const result = data.result || {};
        const text = String(result.response || streamedText || "").trim();
        const ok = result.status === "SUCCESS" && text.length > 0;
        finish(
          {
            success: ok,
            text,
            error: ok ? undefined : String(result.error || "Agent returned no output."),
            exitCode: ok ? 0 : 1,
            tokens: result.usage
              ? {
                  inputTokens: result.usage.input_tokens || 0,
                  outputTokens: result.usage.output_tokens || 0,
                  totalTokens: result.usage.total_tokens || 0,
                }
              : undefined,
          },
          ok ? "success" : "error"
        );
      } else if (rawText.length < MAX_CAPTURE_BYTES && !data?.event) {
        // Plain JSON envelope (e.g. non-streaming output) — keep for parsing.
        rawText += `${trimmed}\n`;
      }
    });

    proc.stderr?.on("data", (chunk: Buffer) => {
      if (stderr.length < 64 * 1024) stderr += chunk.toString("utf-8");
    });

    proc.on("close", (code) => {
      const text = (streamedText || rawText).trim();
      const ok = code === 0 && text.length > 0;
      const cleanErr = stderr.trim();
      finish(
        {
          success: ok,
          text,
          error: ok
            ? undefined
            : `Agent process exited with code ${code}${cleanErr ? `: ${cleanErr.slice(0, 300)}` : ""}`,
          exitCode: code,
        },
        ok ? "success" : "error"
      );
    });

    try {
      proc.stdin?.write(encodeAgentUserTurn(prompt));
    } catch (err: any) {
      finish({ success: false, text: "", error: `Failed to send prompt to agent: ${err?.message}`, exitCode: -1 }, "error");
    }
  });
}
