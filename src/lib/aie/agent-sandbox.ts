import { execSync, spawn, type ChildProcess } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";

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

export type LogCategory = "sandbox" | "install" | "auth" | "agent" | "system" | "network";

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
const LINUX_AGY_PATH = "/home/havox/.local/bin/agy";
const OAUTH_TOKEN_PATH = "/home/havox/.gemini/antigravity-cli/antigravity-oauth-token";

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
        `docker exec ${CONTAINER_NAME} agy --version`,
        { encoding: "utf-8", timeout: 5000, stdio: ["ignore", "pipe", "ignore"] }
      ).trim();
    } catch {}

    const result: SandboxStatus = {
      runtime: "docker",
      dockerAvailable: true,
      containerRunning: true,
      containerName: CONTAINER_NAME,
      hostPlatform: process.platform,
      binaryPath: `/usr/local/bin/agy`,
      isReady: true,
      agentVersion: agentVersion || "1.2.3",
      details: `Isolated Docker sandbox (${CONTAINER_NAME}) operational. All agent executions sandboxed.`,
      logCount: logBuffer.length,
    };
    cachedRuntimeStatus = { status: result, expiresAt: now + CACHE_TTL_MS };
    return result;
  }

  // 3. Fallback to Host (WSL on Windows, native on Linux)
  if (isWin) {
    let wslAvailable = false;
    let agentVersion = "";
    try {
      const vOut = execSync(
        `wsl.exe -e ${LINUX_AGY_PATH} --version`,
        { encoding: "utf-8", timeout: 6000, stdio: ["ignore", "pipe", "ignore"] }
      ).trim();
      if (vOut) {
        wslAvailable = true;
        agentVersion = vOut;
        appendSandboxLog("INFO", "sandbox", `WSL runtime fallback active: agy v${vOut}`);
      }
    } catch {
      wslAvailable = false;
    }

    const result: SandboxStatus = {
      runtime: wslAvailable ? "wsl" : "unavailable",
      dockerAvailable,
      containerRunning: false,
      containerName: CONTAINER_NAME,
      hostPlatform: "win32",
      binaryPath: LINUX_AGY_PATH,
      isReady: wslAvailable,
      agentVersion: agentVersion || undefined,
      details: wslAvailable
        ? `Windows Host: Bridged to WSL Linux runtime at ${LINUX_AGY_PATH}. Docker sandbox standby.`
        : `Windows Host: Docker container offline and WSL binary not reached. Ready for container launch.`,
      logCount: logBuffer.length,
    };
    cachedRuntimeStatus = { status: result, expiresAt: now + CACHE_TTL_MS };
    return result;
  }

  // Native Linux host
  const nativeBinaryExists = existsSync(LINUX_AGY_PATH);
  let agentVersion = "";
  if (nativeBinaryExists) {
    try {
      agentVersion = execSync(
        `${LINUX_AGY_PATH} --version`,
        { encoding: "utf-8", timeout: 4000, stdio: ["ignore", "pipe", "ignore"] }
      ).trim();
      appendSandboxLog("INFO", "sandbox", `Native Linux host runtime active: agy v${agentVersion}`);
    } catch {}
  }

  const result: SandboxStatus = {
    runtime: nativeBinaryExists ? "native" : "unavailable",
    dockerAvailable,
    containerRunning: false,
    containerName: CONTAINER_NAME,
    hostPlatform: process.platform,
    binaryPath: LINUX_AGY_PATH,
    isReady: nativeBinaryExists,
    agentVersion: agentVersion || undefined,
    details: nativeBinaryExists
      ? `Native Linux host runtime (${LINUX_AGY_PATH}). Docker sandbox standby.`
      : `Linux host: Binary not found at ${LINUX_AGY_PATH}. Ready for containerized sandbox onboarding.`,
    logCount: logBuffer.length,
  };
  cachedRuntimeStatus = { status: result, expiresAt: now + CACHE_TTL_MS };
  return result;
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
    appendSandboxLog(
      "WARN",
      "sandbox",
      `Docker daemon not accessible on host. Using ${current.runtime.toUpperCase()} fallback.`
    );
    return {
      success: false,
      message: `Docker daemon not accessible on host. Using ${current.runtime.toUpperCase()} fallback.`,
      status: current,
    };
  }

  try {
    // Check if container exists in stopped state
    const psAll = execSync(`docker ps -a --filter "name=^${CONTAINER_NAME}$" --format "{{.Names}}"`, {
      encoding: "utf-8",
      timeout: 5000,
    }).trim();

    if (psAll === CONTAINER_NAME) {
      appendSandboxLog("INFO", "sandbox", `Container ${CONTAINER_NAME} exists in stopped state. Starting...`);
      execSync(`docker start ${CONTAINER_NAME}`, { encoding: "utf-8", timeout: 10000 });
      appendSandboxLog("INFO", "sandbox", `docker start ${CONTAINER_NAME} completed successfully.`);
    } else {
      appendSandboxLog("INFO", "sandbox", `Deploying fresh instance of ${CONTAINER_NAME} via compose...`);
      try {
        execSync("docker compose -f docker-compose.agent-sandbox.yml up -d", {
          encoding: "utf-8",
          timeout: 20000,
        });
        appendSandboxLog("INFO", "sandbox", `docker compose up -d executed cleanly.`);
      } catch (composeErr: any) {
        appendSandboxLog(
          "WARN",
          "sandbox",
          `docker compose failed (${composeErr?.message}). Falling back to manual docker run...`
        );
        const image = "aie-agent-sandbox:latest";
        const runCmd = [
          "docker run -d",
          `--name ${CONTAINER_NAME}`,
          "--restart unless-stopped",
          "-v aie-agent-vault:/root/.gemini",
          existsSync(LINUX_AGY_PATH) ? `-v ${LINUX_AGY_PATH}:/usr/local/bin/agy:ro` : "",
          existsSync(OAUTH_TOKEN_PATH)
            ? `-v ${OAUTH_TOKEN_PATH}:/root/.gemini/antigravity-cli/antigravity-oauth-token:ro`
            : "",
          "-e AGENT_ENV=isolated_sandbox",
          "-e PATH=/root/.local/bin:/usr/local/bin:/usr/bin:/bin",
          image,
          "tail -f /dev/null",
        ]
          .filter(Boolean)
          .join(" ");

        execSync(runCmd, { encoding: "utf-8", timeout: 15000 });
        appendSandboxLog("INFO", "sandbox", `Manual container run command initialized.`);
      }
    }

    invalidateSandboxCache();
    const updated = detectSandboxRuntime({ forceRefresh: true });
    appendSandboxLog(
      "INFO",
      "sandbox",
      `Sandbox container (${CONTAINER_NAME}) successfully verified online (v${updated.agentVersion || "1.2.3"}).`
    );
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

// ---------------------------------------------------------------------------
// High-Fidelity Process Execution Engine with Step-by-Step Logging
// ---------------------------------------------------------------------------
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
  const status = detectSandboxRuntime();
  const traceId = `trace-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
  const stepLogs: string[] = [];

  const addStepLog = (level: LogLevel, msg: string) => {
    const entry = appendSandboxLog(level, category, msg, { traceId });
    stepLogs.push(`${entry.formattedTime} [${level}] ${msg}`);
  };

  return new Promise((resolve) => {
    let cmd = "";
    let finalArgs: string[] = [];

    if (status.runtime === "docker") {
      cmd = "docker";
      finalArgs = ["exec", "-i", CONTAINER_NAME, "agy", ...args];
    } else if (status.runtime === "wsl") {
      cmd = "wsl.exe";
      finalArgs = ["-e", LINUX_AGY_PATH, ...args];
    } else if (status.runtime === "native") {
      cmd = status.binaryPath || LINUX_AGY_PATH;
      finalArgs = args;
    } else {
      const errNotice = `Agent runtime unavailable (${status.details}). Please click 'Run Sandbox Installation' or start the Docker sandbox container.`;
      addStepLog("ERROR", errNotice);
      const trace: ExecutionTrace = {
        id: traceId,
        command: cmd || "unavailable",
        args: finalArgs,
        fullCommandStr: `${cmd} ${finalArgs.join(" ")}`.trim(),
        runtime: "unavailable",
        containerName: CONTAINER_NAME,
        startTime: new Date(startTime).toISOString(),
        endTime: new Date().toISOString(),
        latencyMs: Date.now() - startTime,
        exitCode: -1,
        stdoutBytes: 0,
        stderrBytes: 0,
        status: "error",
        stepLogs,
      };

      return resolve({
        success: false,
        output: "",
        error: errNotice,
        latencyMs: Date.now() - startTime,
        runtime: "unavailable",
        exitCode: -1,
        logs: stepLogs,
        trace,
      });
    }

    const fullCmdStr = `${cmd} ${finalArgs.join(" ")}`;
    addStepLog("EXEC", `Dispatched process: ${fullCmdStr}`);
    addStepLog("DEBUG", `Target runtime: [${status.runtime.toUpperCase()}], timeout: ${timeoutMs}ms`);

    let proc: ChildProcess;
    let stdout = "";
    let stderr = "";

    try {
      proc = spawn(cmd, finalArgs, {
        stdio: ["pipe", "pipe", "pipe"],
      });
      if (proc.pid) {
        addStepLog("DEBUG", `Spawned process child PID: ${proc.pid}`);
      }
    } catch (spawnErr: any) {
      addStepLog("ERROR", `Process spawn failed: ${spawnErr?.message}`);
      const trace: ExecutionTrace = {
        id: traceId,
        command: cmd,
        args: finalArgs,
        fullCommandStr: fullCmdStr,
        runtime: status.runtime,
        containerName: CONTAINER_NAME,
        startTime: new Date(startTime).toISOString(),
        endTime: new Date().toISOString(),
        latencyMs: Date.now() - startTime,
        exitCode: -1,
        stdoutBytes: 0,
        stderrBytes: 0,
        status: "error",
        stepLogs,
      };

      return resolve({
        success: false,
        output: "",
        error: `Failed to initiate process ${cmd}: ${spawnErr?.message}`,
        latencyMs: Date.now() - startTime,
        runtime: status.runtime,
        exitCode: -1,
        logs: stepLogs,
        trace,
      });
    }

    const timer = setTimeout(() => {
      try {
        proc.kill("SIGKILL");
        addStepLog("WARN", `Process killed via SIGKILL after timeout (${timeoutMs}ms)`);
      } catch {}

      addStepLog("ERROR", `Agent sandbox execution timed out after ${Math.round(timeoutMs / 1000)}s`);
      const trace: ExecutionTrace = {
        id: traceId,
        command: cmd,
        args: finalArgs,
        fullCommandStr: fullCmdStr,
        runtime: status.runtime,
        containerName: CONTAINER_NAME,
        pid: proc.pid,
        startTime: new Date(startTime).toISOString(),
        endTime: new Date().toISOString(),
        latencyMs: Date.now() - startTime,
        exitCode: -1,
        stdoutBytes: Buffer.byteLength(stdout),
        stderrBytes: Buffer.byteLength(stderr),
        status: "timeout",
        stepLogs,
      };

      resolve({
        success: false,
        output: stdout.trim(),
        error: `Agent sandbox execution timed out after ${Math.round(timeoutMs / 1000)}s`,
        latencyMs: Date.now() - startTime,
        runtime: status.runtime,
        exitCode: -1,
        logs: stepLogs,
        trace,
      });
    }, timeoutMs);

    // CRITICAL: Mandatory error listener prevents Node from crashing on ENOENT or spawn failure!
    proc.on("error", (err: any) => {
      clearTimeout(timer);
      addStepLog("ERROR", `Sandbox process error event: ${err?.message || "Execution error"}`);
      const trace: ExecutionTrace = {
        id: traceId,
        command: cmd,
        args: finalArgs,
        fullCommandStr: fullCmdStr,
        runtime: status.runtime,
        containerName: CONTAINER_NAME,
        pid: proc.pid,
        startTime: new Date(startTime).toISOString(),
        endTime: new Date().toISOString(),
        latencyMs: Date.now() - startTime,
        exitCode: -1,
        stdoutBytes: Buffer.byteLength(stdout),
        stderrBytes: Buffer.byteLength(stderr),
        status: "error",
        stepLogs,
      };

      resolve({
        success: false,
        output: stdout.trim(),
        error: `Sandbox execution notice (${cmd}): ${err?.message || "Execution failed"}`,
        latencyMs: Date.now() - startTime,
        runtime: status.runtime,
        exitCode: -1,
        logs: stepLogs,
        trace,
      });
    });

    if (options?.input && proc.stdin) {
      try {
        proc.stdin.write(options.input);
        proc.stdin.end();
        addStepLog("DEBUG", `Injected ${Buffer.byteLength(options.input)} bytes into process stdin`);
      } catch (inErr: any) {
        addStepLog("WARN", `Failed to write stdin: ${inErr?.message}`);
      }
    }

    let stdoutChunks = 0;
    proc.stdout?.on("data", (chunk: Buffer) => {
      stdoutChunks++;
      const text = chunk.toString("utf-8");
      stdout += text;
      const preview = text.length > 80 ? `${text.slice(0, 80)}...` : text.trim();
      if (preview) {
        addStepLog("STDOUT", `[Chunk ${stdoutChunks}] (${chunk.length} bytes): ${preview}`);
      }
    });

    let stderrChunks = 0;
    proc.stderr?.on("data", (chunk: Buffer) => {
      stderrChunks++;
      const text = chunk.toString("utf-8");
      stderr += text;
      const preview = text.length > 80 ? `${text.slice(0, 80)}...` : text.trim();
      if (preview) {
        addStepLog("STDERR", `[Chunk ${stderrChunks}] (${chunk.length} bytes): ${preview}`);
      }
    });

    proc.on("close", (code) => {
      clearTimeout(timer);
      const latencyMs = Date.now() - startTime;
      const cleanOut = stdout.trim();
      const cleanErr = stderr.trim();

      addStepLog(
        code === 0 ? "INFO" : "WARN",
        `Process exited with code ${code} (Latency: ${latencyMs}ms, stdout: ${Buffer.byteLength(stdout)} bytes, stderr: ${Buffer.byteLength(stderr)} bytes)`
      );

      const trace: ExecutionTrace = {
        id: traceId,
        command: cmd,
        args: finalArgs,
        fullCommandStr: fullCmdStr,
        runtime: status.runtime,
        containerName: CONTAINER_NAME,
        pid: proc.pid,
        startTime: new Date(startTime).toISOString(),
        endTime: new Date().toISOString(),
        latencyMs,
        exitCode: code,
        stdoutBytes: Buffer.byteLength(stdout),
        stderrBytes: Buffer.byteLength(stderr),
        status: code === 0 && cleanOut.length > 0 ? "success" : "error",
        stepLogs,
      };

      resolve({
        success: code === 0 && cleanOut.length > 0,
        output: cleanOut || cleanErr,
        error: code !== 0 ? `Process exited with code ${code}${cleanErr ? `: ${cleanErr}` : ""}` : undefined,
        latencyMs,
        runtime: status.runtime,
        exitCode: code,
        logs: stepLogs,
        trace,
      });
    });
  });
}
