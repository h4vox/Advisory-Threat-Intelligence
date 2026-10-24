/**
 * What "Test connection" checks, step by step, so the result says exactly what works and what does
 * not. For the Antigravity agent: Docker, the sandbox container, the CLI in it, and a real prompt
 * (which proves the sign-in). The first failure stops the run; later steps show as not checked.
 *
 * SERVER ONLY.
 */
import { agyVersionInContainer, dockerReachable, inspectContainer } from "./agent-container.server";
import { verifyAgentAnswers } from "./agy-login.server";

export type ConnectionCheck = { label: string; ok: boolean | null; detail: string; ms?: number };

export async function runAgentConnectionChecks(): Promise<{ ok: boolean; checks: ConnectionCheck[]; latencyMs?: number; message: string }> {
  const checks: ConnectionCheck[] = [];
  const skip = (labels: string[]) => labels.forEach((label) => checks.push({ label, ok: null, detail: "not checked" }));
  const timed = async <T>(f: () => Promise<T>): Promise<[T, number]> => {
    const t0 = Date.now();
    const v = await f();
    return [v, Date.now() - t0];
  };

  const [docker, dockerMs] = await timed(() => dockerReachable());
  checks.push({ label: "Docker", ok: docker.ok, detail: docker.detail, ms: dockerMs });
  if (!docker.ok) {
    skip(["Sandbox container", "Antigravity CLI", "Signed in and answering"]);
    return { ok: false, checks, message: docker.detail };
  }

  const [container, cMs] = await timed(() => inspectContainer());
  const cOk = container.exists && container.running;
  checks.push({
    label: "Sandbox container",
    ok: cOk,
    detail: !container.exists ? "not created yet: use Install and sign in" : container.running ? `running${container.homeOnVolume ? ", sign-in kept on the home volume" : ""}` : "stopped: Install and sign in starts it",
    ms: cMs,
  });
  if (!cOk) {
    skip(["Antigravity CLI", "Signed in and answering"]);
    return { ok: false, checks, message: `The sandbox container is ${container.exists ? "stopped" : "not created yet"}.` };
  }

  const [version, vMs] = await timed(() => agyVersionInContainer());
  const vOk = Boolean(version);
  checks.push({ label: "Antigravity CLI", ok: vOk, detail: version ? `version ${version}` : version === "" ? "only the placeholder is installed: Install rebuilds the image" : "does not answer in the container", ms: vMs });
  if (!vOk) {
    skip(["Signed in and answering"]);
    return { ok: false, checks, message: "The Antigravity CLI is not installed in the sandbox." };
  }

  const [answer, aMs] = await timed(() => verifyAgentAnswers());
  checks.push({ label: "Signed in and answering", ok: answer.ok, detail: answer.ok ? `a test prompt was answered in ${answer.latencyMs} ms` : answer.detail, ms: aMs });
  return {
    ok: answer.ok,
    checks,
    latencyMs: answer.ok ? answer.latencyMs : undefined,
    message: answer.ok ? `All checks passed: the agent answered a test prompt in ${answer.latencyMs} ms.` : `The agent did not answer: ${answer.detail}.`,
  };
}
