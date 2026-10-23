/**
 * Lifecycle of the agent sandbox container for the Marketplace install: build the image (which installs
 * the Antigravity CLI), start or recreate the container, report what is inside, and remove it all.
 *
 * Every Docker call is asynchronous with a timeout, so a slow or missing Docker never freezes the
 * server, and the long image build (minutes) can report progress. Compose is preferred (it holds the
 * full hardening); `docker build` + the hardened `docker run` is the fallback.
 */
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import {
  AGENT_CONTAINER_HOME,
  AGENT_CONTAINER_NAME,
  AGENT_HOME_VOLUME,
  LEGACY_AGENT_VOLUME,
  appendSandboxLog,
  hardenedDockerRunArgs,
  invalidateAgyProbe,
} from "./agent-sandbox";

export const AGENT_IMAGE = "aie-agent-sandbox:latest";
const COMPOSE_FILE = "docker-compose.agent-sandbox.yml";
const BUILD_CONTEXT = "docker/agent-sandbox";
const BUILD_TIMEOUT_MS = 20 * 60_000;

type RunResult = { ok: boolean; code: number | null; stdout: string; stderr: string };

function run(args: string[], timeoutMs: number): Promise<RunResult> {
  return new Promise((done) => {
    execFile("docker", args, { timeout: timeoutMs, maxBuffer: 8 * 1024 * 1024, encoding: "utf-8" }, (err, stdout, stderr) => {
      const code = err ? ((err as { code?: unknown }).code as number | null) ?? null : 0;
      done({ ok: !err, code: typeof code === "number" ? code : null, stdout: String(stdout ?? ""), stderr: String(stderr ?? (err ? err.message : "")) });
    });
  });
}

function tail(text: string, lines = 12): string {
  return text.trim().split("\n").slice(-lines).join("\n");
}

function composeFile(): string | null {
  const file = resolve(process.cwd(), COMPOSE_FILE);
  return existsSync(file) ? file : null;
}

export async function dockerReachable(): Promise<{ ok: boolean; detail: string }> {
  const res = await run(["version", "--format", "{{.Server.Version}}"], 8000);
  if (res.ok && res.stdout.trim()) return { ok: true, detail: `Docker ${res.stdout.trim()}` };
  const why = (res.stderr || res.stdout).trim().split("\n")[0] || "the docker command is not available";
  return { ok: false, detail: /not found|ENOENT/i.test(why) ? "Docker is not installed on this machine" : `Docker is not reachable: ${why.slice(0, 200)}` };
}

export async function imageExists(): Promise<boolean> {
  return (await run(["image", "inspect", AGENT_IMAGE, "--format", "{{.Id}}"], 10_000)).ok;
}

export type ContainerInfo = { exists: boolean; running: boolean; homeOnVolume: boolean; image: string | null };

export async function inspectContainer(): Promise<ContainerInfo> {
  const res = await run(
    ["inspect", "-f", '{{.State.Running}}|{{.Config.Image}}|{{range .Mounts}}{{.Type}}:{{.Destination}};{{end}}', AGENT_CONTAINER_NAME],
    8000,
  );
  if (!res.ok) return { exists: false, running: false, homeOnVolume: false, image: null };
  const [running, image, mounts = ""] = res.stdout.trim().split("|");
  return {
    exists: true,
    running: running === "true",
    homeOnVolume: mounts.split(";").includes(`volume:${AGENT_CONTAINER_HOME}`),
    image: image || null,
  };
}

/** `agy --version` inside the container: the version, "" for the bundled shim, null when unreachable. */
export async function agyVersionInContainer(): Promise<string | null> {
  const res = await run(["exec", AGENT_CONTAINER_NAME, "agy", "--version"], 10_000);
  return res.ok ? res.stdout.trim() : null;
}

/**
 * Builds the sandbox image. Its Dockerfile installs the Antigravity CLI from Google's official
 * installer; when that download fails the image still builds with the shim, and the caller reports it.
 */
export async function buildAgentImage(): Promise<{ ok: boolean; detail: string }> {
  appendSandboxLog("INFO", "sandbox", "Building the agent sandbox image (installs the Antigravity CLI)...");
  const compose = composeFile();
  const res = compose
    ? await run(["compose", "-f", compose, "build"], BUILD_TIMEOUT_MS)
    : await run(["build", "-t", AGENT_IMAGE, resolve(process.cwd(), BUILD_CONTEXT)], BUILD_TIMEOUT_MS);
  const log = `${res.stdout}\n${res.stderr}`;
  invalidateAgyProbe();
  if (!res.ok) {
    appendSandboxLog("ERROR", "sandbox", `Agent image build failed: ${tail(log, 4)}`);
    return { ok: false, detail: `The agent image did not build:\n${tail(log)}` };
  }
  const warning = log.split("\n").find((l) => /WARNING: .*(Antigravity|agy|install)/i.test(l));
  appendSandboxLog(warning ? "WARN" : "INFO", "sandbox", warning ? warning.replace(/^#\d+\s+[\d.]+\s+/, "") : "Agent sandbox image built.");
  return { ok: true, detail: warning ? warning.replace(/^#\d+\s+[\d.]+\s+/, "") : "built" };
}

/** Starts the container, creating (or with `recreate`, replacing) it from the current image. */
export async function startAgentContainer(options: { recreate?: boolean } = {}): Promise<{ ok: boolean; detail: string }> {
  const info = await inspectContainer();
  if (info.exists && !options.recreate) {
    if (info.running) return { ok: true, detail: "running" };
    const started = await run(["start", AGENT_CONTAINER_NAME], 30_000);
    invalidateAgyProbe();
    if (started.ok) return { ok: true, detail: "started" };
  }
  const compose = composeFile();
  if (compose) {
    const up = await run(["compose", "-f", compose, "up", "-d", ...(info.exists ? ["--force-recreate"] : [])], 120_000);
    invalidateAgyProbe();
    if (up.ok) return { ok: true, detail: info.exists ? "recreated" : "created" };
    appendSandboxLog("WARN", "sandbox", `docker compose up failed, using docker run: ${tail(up.stderr, 3)}`);
  }
  if (info.exists) await run(["rm", "-f", AGENT_CONTAINER_NAME], 30_000);
  const created = await run(hardenedDockerRunArgs(), 60_000);
  invalidateAgyProbe();
  return created.ok ? { ok: true, detail: "created" } : { ok: false, detail: `The agent container did not start:\n${tail(created.stderr)}` };
}

/** Removes the container and the agent's home volume: the CLI's sign-in is gone for good. */
export async function removeAgentContainerAndHome(): Promise<{ ok: boolean; detail: string }> {
  await run(["rm", "-f", AGENT_CONTAINER_NAME], 30_000);
  const vol = await run(["volume", "rm", "-f", AGENT_HOME_VOLUME], 30_000);
  await run(["volume", "rm", "-f", LEGACY_AGENT_VOLUME], 30_000);
  invalidateAgyProbe();
  return vol.ok ? { ok: true, detail: "removed" } : { ok: false, detail: tail(vol.stderr, 3) };
}
