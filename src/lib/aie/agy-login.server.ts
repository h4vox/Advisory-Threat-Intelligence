/**
 * Server side of the Antigravity CLI sign-in (flow and safety rules: ./agy-login).
 *
 * Runs the real `agy` in a pseudo-terminal inside the sandbox container (`script` from util-linux,
 * started with `docker exec -i`) and keeps at most one sign-in per server process, on globalThis so
 * a dev reload cannot start a second terminal. The CLI saves the sign-in in its own home, which is
 * the container's persistent volume; AIE never sees or stores the Google tokens.
 */
import { execFile, spawn } from "node:child_process";
import { AgyLoginSession, ptyChildTerminal, type AgyLoginSnapshot, type LoginTimings } from "./agy-login";
import { AGENT_CONTAINER_NAME, invalidateAgyProbe, runAgentPromptInSandbox } from "./agent-sandbox";

/** A real prompt through the agent: the only proof that the sign-in works. */
const VERIFY_PROMPT = "Reply with exactly the word READY and nothing else.";
const VERIFY_TIMEOUT_MS = 60_000;

/** Sign-in ids are `agylogin_` + lowercase letters and digits: safe inside the container's shell command. */
const LOGIN_ID_RE = /^agylogin_[a-z0-9]{8,32}$/;

function newLoginId(): string {
  return `agylogin_${Math.random().toString(36).slice(2, 10).padEnd(8, "0")}`;
}

/**
 * `docker exec` arguments that run `agy` under a 1000-column pseudo-terminal (long URLs stay on one
 * line). The CLI carries AIE_AGY_LOGIN=<id> in its environment so its processes can be found and
 * stopped inside the container: killing the local `docker exec` client does not stop them.
 */
export function containerLoginArgs(loginId: string, container = AGENT_CONTAINER_NAME): string[] {
  if (!LOGIN_ID_RE.test(loginId)) throw new Error("invalid sign-in id");
  return [
    "exec",
    "-i",
    "-e",
    "TERM=xterm-256color",
    "-e",
    "COLUMNS=1000",
    "-e",
    "LINES=50",
    container,
    "script",
    "-qfec",
    `stty cols 1000 rows 50 2>/dev/null; exec env AIE_AGY_LOGIN=${loginId} agy`,
    "/dev/null",
  ];
}

// Kills the sign-in processes inside the container: those whose environment or command line carries
// AIE_AGY_LOGIN=<id> ($1), or any sign-in's ($1 = "*"). POSIX sh + /proc only (no procps needed).
// The bracketed first letter keeps grep's own command line from matching its pattern.
const KILL_LOGIN_SCRIPT = `
if [ "$1" = "*" ]; then pat='AIE_AGY_LOGIN=[a]gylogin_'; else pat="AIE_AGY_LOGIN=[a]\${1#a}\\b"; fi
for p in /proc/[0-9]*; do
  pid=\${p#/proc/}
  [ "$pid" = "$$" ] && continue
  if tr '\\0' '\\n' < "$p/environ" 2>/dev/null | grep -q "^$pat" || tr '\\0' ' ' < "$p/cmdline" 2>/dev/null | grep -q "$pat"; then
    kill -9 "$pid" 2>/dev/null
  fi
done
exit 0`;

/** Stops a sign-in's CLI inside the container (or every sign-in's, with "*"). Never throws. */
export function stopContainerLogin(loginId: string | "*"): Promise<void> {
  if (loginId !== "*" && !LOGIN_ID_RE.test(loginId)) return Promise.resolve();
  return new Promise((done) => {
    execFile("docker", ["exec", AGENT_CONTAINER_NAME, "sh", "-c", KILL_LOGIN_SCRIPT, "sh", loginId], { timeout: 10_000 }, () => done());
  });
}

export type AgentVerification = { ok: boolean; detail: string; latencyMs?: number };

export async function verifyAgentAnswers(): Promise<AgentVerification> {
  invalidateAgyProbe();
  const res = await runAgentPromptInSandbox(VERIFY_PROMPT, { timeoutMs: VERIFY_TIMEOUT_MS, category: "auth" });
  if (res.success && /\bREADY\b/i.test(res.text)) {
    return { ok: true, detail: `the agent answered in ${res.latencyMs} ms`, latencyMs: res.latencyMs };
  }
  const why = res.error || `unexpected reply "${res.text.slice(0, 80)}"`;
  return { ok: false, detail: /not authenticated|sign in/i.test(why) ? "the CLI is not signed in" : why, latencyMs: res.latencyMs };
}

type Listener = (snapshot: AgyLoginSnapshot) => void;
type Registry = {
  session: AgyLoginSession | null;
  listeners: Set<Listener>;
  /** Round trip of the verification prompt of the last successful sign-in. */
  lastVerifiedLatencyMs?: number;
};
const g = globalThis as typeof globalThis & { __aieAgyLogin?: Registry };
const registry: Registry = (g.__aieAgyLogin ??= { session: null, listeners: new Set() });

/** Subscribes to sign-in state changes; returns the unsubscribe function. */
export function onAgyLoginChange(listener: Listener): () => void {
  registry.listeners.add(listener);
  return () => registry.listeners.delete(listener);
}

export function lastVerifiedLatencyMs(): number | undefined {
  return registry.lastVerifiedLatencyMs;
}

/**
 * Starts the CLI's sign-in, or returns the one already in progress (one terminal at a time).
 * `restart`: abandon an unfinished sign-in and start over.
 */
export async function startAgyLogin(options: { restart?: boolean; timings?: Partial<LoginTimings> } = {}): Promise<AgyLoginSnapshot> {
  const current = registry.session;
  if (current && !current.isFinished()) {
    if (!options.restart) return current.snapshot();
    current.cancel();
  }
  // Sign-ins left by an earlier server process (a restart while one waited for its code) still hold a CLI.
  await stopContainerLogin("*");
  const id = newLoginId();
  const session = new AgyLoginSession({
    id,
    timings: options.timings,
    spawn: () => ptyChildTerminal(spawn("docker", containerLoginArgs(id), { stdio: ["pipe", "pipe", "pipe"] })),
    verify: async () => {
      const result = await verifyAgentAnswers();
      if (result.ok) registry.lastVerifiedLatencyMs = result.latencyMs;
      return result;
    },
    onChange: (snapshot) => {
      if (snapshot.state === "signed_in" || snapshot.state === "failed" || snapshot.state === "cancelled") {
        // The session asked the CLI to quit (Ctrl+C); make sure nothing of it stays in the container.
        setTimeout(() => void stopContainerLogin(id), 2_000).unref?.();
      }
      if (registry.session !== session) return; // superseded by a newer sign-in
      if (snapshot.state === "signed_in") invalidateAgyProbe();
      for (const listener of registry.listeners) {
        try {
          listener(snapshot);
        } catch {
          /* a listener failure must not break the sign-in */
        }
      }
    },
  });
  registry.session = session;
  return session.start();
}

export function getAgyLoginSnapshot(): AgyLoginSnapshot | null {
  return registry.session?.snapshot() ?? null;
}

export function submitAgyLoginCode(code: string): { ok: true; snapshot: AgyLoginSnapshot } | { ok: false; error: string } {
  const session = registry.session;
  if (!session) return { ok: false, error: "No sign-in is in progress. Start sign-in again." };
  const res = session.submitCode(code);
  return res.ok ? { ok: true, snapshot: session.snapshot() } : res;
}

export function cancelAgyLogin(): AgyLoginSnapshot | null {
  const session = registry.session;
  return session ? session.cancel() : null;
}
