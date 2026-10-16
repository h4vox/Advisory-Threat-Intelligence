/**
 * Network layer for structured connectors.
 *
 * - File contents (STIX bundle, KEV JSON, raw GitHub files) go through the
 *   hardened safeFetchResource (SSRF checks on every hop, pinned DNS, byte cap,
 *   single deadline). Large bundles raise the cap per call (e.g. 80 MB for the
 *   ATT&CK STIX bundle) — the cap is still enforced while streaming.
 * - Repository listings use the GitHub git-trees API. The host is fixed to
 *   api.github.com (never taken from input), redirects are refused and the
 *   body is size-capped; GITHUB_TOKEN, when set, is sent only to that host.
 */
import { safeFetchResource } from "../security.ts";

export type GithubTreeEntry = { path: string; type: "blob" | "tree" | string; size?: number };

export type ConnectorFetcher = {
  text(url: string, opts?: { maxBytes?: number; timeoutMs?: number; accept?: string }): Promise<string>;
  githubTree(owner: string, repo: string, branch: string): Promise<{ entries: GithubTreeEntry[]; truncated: boolean }>;
};

const GH_NAME_RE = /^[A-Za-z0-9_.-]{1,100}$/;
const GH_REF_RE = /^[A-Za-z0-9_./-]{1,200}$/;

function assertGithubName(kind: string, value: string, re = GH_NAME_RE) {
  if (!re.test(value) || value.includes("..")) throw new Error(`Invalid GitHub ${kind}: ${value}`);
}

/** raw.githubusercontent.com URL for a repository file (path segments encoded). */
export function githubRawUrl(owner: string, repo: string, branch: string, path: string): string {
  assertGithubName("owner", owner);
  assertGithubName("repo", repo);
  assertGithubName("branch", branch, GH_REF_RE);
  const clean = path.replace(/^\/+/, "");
  if (clean.split("/").some((seg) => seg === ".." || seg === ".")) throw new Error(`Invalid repository path: ${path}`);
  const encoded = clean
    .split("/")
    .map((seg) => encodeURIComponent(seg))
    .join("/");
  return `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${encoded}`;
}

export function githubBlobUrl(owner: string, repo: string, branch: string, path: string): string {
  const clean = path.replace(/^\/+/, "");
  return `https://github.com/${owner}/${repo}/blob/${branch}/${clean.split("/").map(encodeURIComponent).join("/")}`;
}

export function githubTreeUrl(owner: string, repo: string, branch: string, path: string): string {
  const clean = path.replace(/^\/+|\/+$/g, "");
  return `https://github.com/${owner}/${repo}/tree/${branch}/${clean.split("/").map(encodeURIComponent).join("/")}`;
}

async function readCapped(res: Response, maxBytes: number): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => {});
        throw new Error(`GitHub API response exceeded ${(maxBytes / 1_000_000).toFixed(0)} MB`);
      }
      chunks.push(value);
    }
  }
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    buf.set(c, off);
    off += c.byteLength;
  }
  return new TextDecoder().decode(buf);
}

async function githubTree(owner: string, repo: string, branch: string) {
  assertGithubName("owner", owner);
  assertGithubName("repo", repo);
  assertGithubName("branch", branch, GH_REF_RE);
  const url = `https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`;
  const headers: Record<string, string> = {
    accept: "application/vnd.github+json",
    "user-agent": "AIE-Threat-Retrieval/3.0",
    "x-github-api-version": "2022-11-28",
  };
  const token = process.env.GITHUB_TOKEN?.trim();
  const request = async (withToken: boolean) => {
    const h = { ...headers };
    if (withToken && token) h.authorization = `Bearer ${token}`;
    try {
      return await fetch(url, { headers: h, redirect: "error", signal: AbortSignal.timeout(30_000) });
    } catch (err) {
      throw new Error(`GitHub API unreachable (${err instanceof Error ? err.message : String(err)})`);
    }
  };
  let res = await request(true);
  if (res.status === 401 && token) {
    // A stale/invalid token should not block public repositories: retry anonymously.
    await res.body?.cancel().catch(() => {});
    res = await request(false);
  }
  if (!res.ok) {
    await res.body?.cancel().catch(() => {});
    const hint =
      res.status === 403 || res.status === 429
        ? " — forbidden or rate limited (set GITHUB_TOKEN for higher limits)"
        : res.status === 401
          ? " — GitHub API rejected the request"
          : "";
    throw new Error(`GitHub API returned HTTP ${res.status} for ${owner}/${repo}${hint}`);
  }
  const body = JSON.parse(await readCapped(res, 40_000_000)) as { tree?: GithubTreeEntry[]; truncated?: boolean };
  return { entries: Array.isArray(body.tree) ? body.tree : [], truncated: Boolean(body.truncated) };
}

export const defaultFetcher: ConnectorFetcher = {
  async text(url, opts) {
    const r = await safeFetchResource(url, {
      maxBytes: opts?.maxBytes ?? 4_000_000,
      timeoutMs: opts?.timeoutMs ?? 45_000,
      acceptHeader: opts?.accept ?? "application/json, application/yaml, text/plain;q=0.9, */*;q=0.5",
    });
    return r.body;
  },
  githubTree,
};
