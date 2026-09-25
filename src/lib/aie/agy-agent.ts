/**
 * AGY Agent Integration & Enhancement Layer
 *
 * Spawns and orchestrates the autonomous AGY CLI agent as an intelligent enhancement
 * layer over the core crawler engine.
 *
 * Guiding Architecture Rules:
 * 1. Crawler Engine is Core: Crawling, extraction, deduplication, existing tagging, and ingestion remain primary.
 * 2. Fail-Safe Fallback: If AGY CLI is unavailable, disabled, times out, or produces invalid output,
 *    the crawler engine seamlessly falls back to existing heuristic evaluation without disruption.
 * 3. Exact Taxonomy: Agent enforces the exact same tag categories, classifications, and ResourceKinds as the crawler engine.
 * 4. Single-Command Operation: Operates via Node child processes spawned automatically during `npm run dev`.
 */

import { spawn, execSync } from "node:child_process";
import { existsSync } from "node:fs";
import type { ResourceClassification } from "./qualification";
import type { ResourceKind, AgentScoreBreakdown } from "./types";

export type DiscoveredAgentSource = {
  source_name: string;
  domain: string;
  crawl_pattern: string;
  base_url: string;
  primary_content: string[];
  why_crawl: string;
  confidence?: number;
};

export type DiscoveredDomainResource = {
  url: string;
  title: string;
  category?: string;
  relevanceReason?: string;
  estimatedType?: ResourceKind;
  isHighValue?: boolean;
};

export type DomainResourceHarvestResult = {
  success: boolean;
  domain: string;
  baseUrl: string;
  resources: DiscoveredDomainResource[];
  totalExtracted: number;
  sitemapFound?: boolean;
  error?: string;
};

export type AgentEvaluationResult = {
  success: boolean;
  fallback: boolean;
  isRelevant: boolean;
  passScore: number; // 0 - 100
  recommendApproval: boolean;
  classification: ResourceClassification;
  resourceKind: ResourceKind;
  threatActors: string[];
  malwareFamilies: string[];
  cves: string[];
  mitreTechniques: string[];
  stages?: string[];
  rationale: string;
  discoveredSources?: Array<{ name: string; domain: string; url: string }>;
  scoreBreakdown?: AgentScoreBreakdown;
  tokensUsed?: { inputTokens: number; outputTokens: number; totalTokens: number };
  providerId?: string;
  providerName?: string;
  error?: string;
};

// Allowed Classifications matching crawler engine taxonomy
const VALID_CLASSIFICATIONS: Set<ResourceClassification> = new Set([
  "ADVERSARY_EMULATION",
  "ADVERSARY_SIMULATION",
  "INTRUSION_REPORT",
  "ATTACK_CHAIN_REPORT",
  "MALWARE_ANALYSIS",
  "THREAT_ACTOR_REPORT",
  "CAMPAIGN_REPORT",
  "VULNERABILITY_REPORT",
  "DETECTION_RESEARCH",
  "SECURITY_ADVISORY",
  "PURPLE_TEAM",
  "MITRE_RESEARCH",
  "THREAT_REPORT",
  "OTHER",
]);

// Allowed ResourceKinds matching crawler engine taxonomy
const VALID_RESOURCE_KINDS: Set<ResourceKind> = new Set([
  "FULL_ATTACK_CHAIN",
  "CAMPAIGN_INTEL",
  "PROCEDURE_DEEPDIVE",
  "MALWARE_ANALYSIS",
  "DETECTION_GUIDANCE",
  "VULNERABILITY_ADVISORY",
  "THREAT_ACTOR_DOSSIER",
]);

export const PREMIER_RESEARCH_LABS: Array<{
  source_name: string;
  domain: string;
  crawl_pattern: string;
  base_url: string;
  primary_content: string[];
  why_crawl: string;
}> = [
  {
    source_name: "Check Point Research",
    domain: "research.checkpoint.com",
    crawl_pattern: "https://research.checkpoint.com/*",
    base_url: "https://research.checkpoint.com",
    primary_content: ["Attack Chains", "Malware Analysis", "TTPs"],
    why_crawl: "Publishes in-depth reverse engineering of zero-days, nation-state loaders, and ransomware intrusion flows",
  },
  {
    source_name: "Elastic Security Labs",
    domain: "elastic.co",
    crawl_pattern: "https://www.elastic.co/security-labs/*",
    base_url: "https://www.elastic.co/security-labs",
    primary_content: ["Detections & Sigma", "Attack Chains", "TTPs"],
    why_crawl: "Publishes enterprise intrusion case studies, execution command-lines, and Sigma detection rules",
  },
  {
    source_name: "Huntress Labs",
    domain: "huntress.com",
    crawl_pattern: "https://www.huntress.com/blog/*",
    base_url: "https://www.huntress.com/blog",
    primary_content: ["Attack Chains", "Procedures & TTPs", "Malware Analysis"],
    why_crawl: "Granular investigation of active living-off-the-land attacks, initial access brokers, and persistence mechanisms",
  },
  {
    source_name: "Volexity Threat Research",
    domain: "volexity.com",
    crawl_pattern: "https://www.volexity.com/blog/*",
    base_url: "https://www.volexity.com/blog",
    primary_content: ["Attack Chains", "Campaigns", "Zero-Day Exploits"],
    why_crawl: "Renowned tracking of state-sponsored espionage, zero-day in-the-wild exploitation, and memory forensics",
  },
  {
    source_name: "Sophos X-Ops",
    domain: "news.sophos.com",
    crawl_pattern: "https://news.sophos.com/en-us/category/threat-research/*",
    base_url: "https://news.sophos.com/en-us/category/threat-research",
    primary_content: ["Attack Chains", "Malware Analysis", "Campaigns"],
    why_crawl: "Technical teardowns of ransomware payloads, initial access chains, and driver vulnerabilities (BYOVD)",
  },
  {
    source_name: "Group-IB Threat Intelligence",
    domain: "group-ib.com",
    crawl_pattern: "https://www.group-ib.com/blog/*",
    base_url: "https://www.group-ib.com/blog",
    primary_content: ["Campaigns", "Attack Chains", "Threat Actor Dossiers"],
    why_crawl: "Global adversary group attribution, banking trojans, ransomware affiliate tracking, and network telemetry",
  },
  {
    source_name: "Sygnia Incident Response",
    domain: "sygnia.co",
    crawl_pattern: "https://www.sygnia.co/blog/*",
    base_url: "https://www.sygnia.co/blog",
    primary_content: ["Attack Chains", "Procedures & TTPs"],
    why_crawl: "Forensic analysis of complex cloud compromises, active directory escalations, and sophisticated APT intrusions",
  },
  {
    source_name: "Dragos Industrial Cyber Threat",
    domain: "dragos.com",
    crawl_pattern: "https://www.dragos.com/blog/*",
    base_url: "https://www.dragos.com/blog",
    primary_content: ["Procedures & TTPs", "Campaigns", "ICS Advisories"],
    why_crawl: "Specialized ICS/SCADA adversary tracking, industrial protocol tampering, and OT attack chain mechanics",
  },
  {
    source_name: "Rapid7 Threat Research",
    domain: "rapid7.com",
    crawl_pattern: "https://www.rapid7.com/blog/category/threat-research/*",
    base_url: "https://www.rapid7.com/blog/category/threat-research",
    primary_content: ["Vulnerability Advisories", "Attack Chains", "TTPs"],
    why_crawl: "Weaponized CVE analysis, public-facing exploit telemetry, and Metasploit adversary procedure intelligence",
  },
  {
    source_name: "Qualys Threat Research",
    domain: "blog.qualys.com",
    crawl_pattern: "https://blog.qualys.com/vulnerabilities-threat-research/*",
    base_url: "https://blog.qualys.com/vulnerabilities-threat-research",
    primary_content: ["Vulnerability Advisories", "Procedures & TTPs"],
    why_crawl: "Deep dive advisory and exploit analysis for critical Linux/Windows kernel and enterprise network CVEs",
  },
];

let cachedSandboxRunning: { running: boolean; expiresAt: number } | null = null;

function isSandboxContainerActive(): boolean {
  const now = Date.now();
  if (cachedSandboxRunning && cachedSandboxRunning.expiresAt > now) {
    return cachedSandboxRunning.running;
  }
  try {
    const inspect = execSync("docker inspect -f '{{.State.Running}}' aie-agent-sandbox", {
      encoding: "utf-8",
      timeout: 2000,
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    const running = inspect === "true";
    cachedSandboxRunning = { running, expiresAt: now + 15000 };
    return running;
  } catch {
    cachedSandboxRunning = { running: false, expiresAt: now + 15000 };
    return false;
  }
}

/**
 * Resolve the CLI command & arguments based on sandbox container and OS platform
 */
function getAgyCommandArgs(args: string[]): { command: string; finalArgs: string[] } {
  if (isSandboxContainerActive()) {
    return {
      command: "docker",
      finalArgs: ["exec", "-i", "aie-agent-sandbox", "agy", ...args],
    };
  }

  if (existsSync("/home/havox/.local/bin/agy")) {
    return {
      command: "/home/havox/.local/bin/agy",
      finalArgs: args,
    };
  }

  if (process.platform === "win32") {
    return {
      command: "wsl.exe",
      finalArgs: ["-e", "/home/havox/.local/bin/agy", ...args],
    };
  }

  return {
    command: "agy",
    finalArgs: args,
  };
}

/**
 * Execute agy CLI command with strict timeout and output capturing
 */
function runAgyCli(args: string[], timeoutMs = 60000): Promise<{ stdout: string; stderr: string; code: number | null }> {
  return new Promise((resolve, reject) => {
    const { command, finalArgs } = getAgyCommandArgs(args);
    let proc: any = null;
    let stdout = "";
    let stderr = "";

    try {
      proc = spawn(command, finalArgs, {
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (spawnErr) {
      return reject(spawnErr);
    }

    const timer = setTimeout(() => {
      try {
        proc.kill("SIGKILL");
      } catch {
        /* ignore kill error */
      }
      reject(new Error(`AGY CLI process timed out after ${Math.round(timeoutMs / 1000)}s`));
    }, timeoutMs);

    proc.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf-8");
    });

    proc.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf-8");
    });

    proc.on("error", (err: Error) => {
      clearTimeout(timer);
      reject(err);
    });

    proc.on("close", (code: number | null) => {
      clearTimeout(timer);
      resolve({ stdout, stderr, code });
    });
  });
}

/**
 * Extract clean JSON data from raw agy output (handling envelope or markdown fences)
 */
function extractJsonPayload(text: string): any {
  const raw = text.trim();
  if (!raw) throw new Error("Empty response from AGY agent");

  // If inside an agy JSON envelope
  try {
    const envelope = JSON.parse(raw);
    if (envelope && typeof envelope === "object") {
      if (envelope.structured_output) return envelope.structured_output;
      if (typeof envelope.response === "string") {
        return extractJsonPayload(envelope.response);
      }
    }
  } catch {
    /* not an envelope, parse directly */
  }

  // Strip markdown code fences if present
  let clean = raw;
  const fenceMatch = raw.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
  if (fenceMatch) {
    clean = fenceMatch[1].trim();
  }

  // Find outermost JSON brackets
  const firstBrace = clean.indexOf("{");
  const firstBracket = clean.indexOf("[");

  let start = -1;
  let end = -1;
  if (firstBracket !== -1 && (firstBrace === -1 || firstBracket < firstBrace)) {
    start = firstBracket;
    end = clean.lastIndexOf("]");
  } else if (firstBrace !== -1) {
    start = firstBrace;
    end = clean.lastIndexOf("}");
  }

  if (start !== -1 && end !== -1 && end > start) {
    clean = clean.slice(start, end + 1);
  }

  return JSON.parse(clean);
}

/**
 * Check if the AGY agent CLI is currently installed and executable
 */
export async function isAgentAvailable(): Promise<{
  available: boolean;
  version?: string;
  platform: string;
  error?: string;
}> {
  try {
    const res = await runAgyCli(["--version"], 8000);
    const ver = (res.stdout || "").trim();
    if (res.code === 0 && ver) {
      return { available: true, version: ver, platform: process.platform };
    }
    return { available: false, platform: process.platform, error: res.stderr || `Exit code ${res.code}` };
  } catch (err) {
    return { available: false, platform: process.platform, error: (err as Error).message };
  }
}

/**
 * Autonomous Source Discovery:
 * Discovers new threat intelligence source root domains and recursive crawl patterns (e.g. https://domain/blog/*)
 * comparing against known domains to prevent duplicate rediscovery.
 */
export async function discoverAgentSources(options: {
  limit?: number;
  existingDomains?: string[];
  timeoutSeconds?: number;
  model?: string;
}): Promise<{
  sources: DiscoveredAgentSource[];
  candidateCount?: number;
  candidateDomains?: string[];
  raw?: any;
  error?: string;
}> {
  const limit = Math.min(Math.max(options.limit ?? 6, 1), 20);
  const timeoutSec = options.timeoutSeconds ?? 90;
  const model = options.model || "gemini-3.8-flash-low";
  const knownDomains = options.existingDomains || [];

  const knownListSnippet =
    knownDomains.length > 0
      ? `\nALREADY KNOWN DOMAINS & SOURCES (DO NOT RETURN THESE OR REDISCOVER THEM):\n${knownDomains
          .slice(0, 60)
          .map((d) => `- ${d}`)
          .join("\n")}\n`
      : "";

  const prompt = `You are an Adversary Emulation Intelligence Source Hunter operating under the Resource Collection Skill (Adversary Simulation & Emulation Intelligence).

PRIMARY MISSION:
Perform a live, intelligent discovery of exactly ${limit} NEW, distinct, highly technical threat intelligence sources or research lab endpoints.
The objective is NOT generic cybersecurity news or marketing blogs.
The objective is to find authoritative technical publications that regularly document:
1. Full Intrusion / Attack Chain Reports (Initial Access → Execution → Credential Access → Lateral Movement → C2 → Impact).
2. Multi-Stage Infection Chains (Delivery → Dropper → Loader → Payload → C2).
3. Incident Response & Forensic Timelines (real host, network, and EDR observed actions).
4. Granular Adversary Procedures & TTPs (concrete attacker tradecraft and commands).
5. Malware behavioral reverse engineering and campaign analyses.

TARGET HIGH-VALUE LABS & SPECIALIZED TEAMS (e.g. Check Point Research, Securelist, Huntress, Red Canary, Volexity, Sophos X-Ops, Cybereason, Sygnia, NCC Group, Malwarebytes Labs, Jamf Threat Labs, Morphisec, Elastic Labs, etc.).
${knownListSnippet}
STRICT REQUIREMENTS:
1. "base_url": Provide the EXACT technical endpoint where research articles live (e.g. 'https://research.checkpoint.com/', 'https://www.huntress.com/blog', 'https://securelist.com/'), NOT just the top-level corporate homepage.
2. "crawl_pattern": Must be a recursive pattern ending with '/*' targeting that specific research endpoint (e.g. 'https://research.checkpoint.com/*' or 'https://www.huntress.com/blog/*').
3. DO NOT return individual article URLs (NO date or single-article slugs).
4. DO NOT return marketing, press releases, or generic news aggregators.
5. Every domain must be active, distinct, and not in the already known list.

OUTPUT FORMAT:
Return pure, valid JSON with this exact structure:
{
  "sources": [
    {
      "source_name": "Publisher or Lab Name (e.g. Check Point Research)",
      "domain": "research.checkpoint.com",
      "crawl_pattern": "https://research.checkpoint.com/*",
      "base_url": "https://research.checkpoint.com",
      "primary_content": ["Attack Chains", "Infection Chains", "TTPs"],
      "why_crawl": "Publishes stage-by-stage reverse engineering of multi-stage loaders and enterprise intrusion timelines with ATT&CK mappings"
    }
  ]
}
Return pure JSON only. No markdown fences.`;

  try {
    const res = await runAgyCli(
      [
        "--print",
        prompt,
        "--output-format",
        "json",
        "--model",
        model,
        "--dangerously-skip-permissions",
        "--print-timeout",
        `${timeoutSec}s`,
      ],
      (timeoutSec + 15) * 1000,
    );

    if (res.code !== 0 && !res.stdout) {
      return {
        sources: [],
        error: `Agent exited with code ${res.code}: ${res.stderr.slice(0, 200)}`,
      };
    }

    const payload = extractJsonPayload(res.stdout);
    const rawList: any[] = Array.isArray(payload)
      ? payload
      : Array.isArray(payload?.sources)
      ? payload.sources
      : [];

    const existingDomainSet = new Set(knownDomains.map((d) => d.toLowerCase().trim()));
    const validSources: DiscoveredAgentSource[] = [];

    for (const item of rawList) {
      if (!item || typeof item !== "object") continue;
      const rawDomain = (item.domain || item.source_domain || "").toLowerCase().trim().replace(/^www\./, "");
      if (!rawDomain || existingDomainSet.has(rawDomain)) continue;

      let crawlPattern = item.crawl_pattern || item.base_url || `https://${rawDomain}/*`;
      if (!crawlPattern.endsWith("/*") && !crawlPattern.endsWith("*")) {
        crawlPattern = `${crawlPattern.replace(/\/+$/, "")}/*`;
      }

      validSources.push({
        source_name: item.source_name || rawDomain,
        domain: rawDomain,
        crawl_pattern: crawlPattern,
        base_url: item.base_url || crawlPattern.replace(/\/\*$/, ""),
        primary_content: Array.isArray(item.primary_content) ? item.primary_content : ["Attack Chains", "TTPs"],
        why_crawl: item.why_crawl || "Identified by AI Agent as high-value threat intelligence source",
        confidence: 0.9,
      });
      existingDomainSet.add(rawDomain);
    }

    // If live discovery returned fewer than requested limit, supplement with premier research labs
    if (validSources.length < limit) {
      for (const lab of PREMIER_RESEARCH_LABS) {
        if (validSources.length >= limit) break;
        if (!existingDomainSet.has(lab.domain.toLowerCase())) {
          validSources.push({
            source_name: lab.source_name,
            domain: lab.domain,
            crawl_pattern: lab.crawl_pattern,
            base_url: lab.base_url,
            primary_content: lab.primary_content,
            why_crawl: lab.why_crawl,
            confidence: 0.95,
          });
          existingDomainSet.add(lab.domain.toLowerCase());
        }
      }
    }

    const candidateDomains = validSources.map((s) => s.domain);

    return {
      sources: validSources,
      candidateCount: validSources.length,
      candidateDomains,
      raw: payload,
    };
  } catch (err) {
    const existingDomainSet = new Set(knownDomains.map((d) => d.toLowerCase().trim()));
    const fallbackSources: DiscoveredAgentSource[] = [];
    for (const lab of PREMIER_RESEARCH_LABS) {
      if (fallbackSources.length >= limit) break;
      if (!existingDomainSet.has(lab.domain.toLowerCase())) {
        fallbackSources.push({
          source_name: lab.source_name,
          domain: lab.domain,
          crawl_pattern: lab.crawl_pattern,
          base_url: lab.base_url,
          primary_content: lab.primary_content,
          why_crawl: lab.why_crawl,
          confidence: 0.95,
        });
        existingDomainSet.add(lab.domain.toLowerCase());
      }
    }
    return {
      sources: fallbackSources,
      candidateCount: fallbackSources.length,
      candidateDomains: fallbackSources.map((s) => s.domain),
      error: (err as Error).message,
    };
  }
}

/**
 * Coordinated Target Domain Resource Extraction:
 * Uses the AGY Agent (with anchor-regex fallback) to extract all active research report
 * and attack chain permalinks from a target domain in a single coordinated pass.
 */
export async function discoverDomainResourcesWithAgent(options: {
  domain: string;
  baseUrl: string;
  htmlSnippet?: string;
  model?: string;
  timeoutSeconds?: number;
}): Promise<DomainResourceHarvestResult> {
  const timeoutSec = options.timeoutSeconds ?? 60;
  const model = options.model || "gemini-3.8-flash-low";
  const domain = options.domain.toLowerCase().replace(/^www\./, "");
  const baseUrl = options.baseUrl.startsWith("http") ? options.baseUrl : `https://${domain}`;

  const prompt = `You are the Adversary Emulation Domain Harvester operating under the domain-resource-discovery-intel skill.
TARGET DOMAIN: ${domain}
BASE URL: ${baseUrl}
CONTEXT / HTML EXCERPT:
${(options.htmlSnippet || "").slice(0, 4000)}

MISSION:
Extract or identify all authoritative technical threat intelligence articles, research papers, malware reverse-engineering posts, and attack chain timelines hosted on this domain.
Focus exclusively on deep technical research (DFIR timelines, loader mechanics, APT dossiers, CVE exploits, living-off-the-land techniques).
DO NOT return marketing pages, product pricing, generic news summaries, privacy policies, or author index pages.

OUTPUT FORMAT:
Return pure JSON with this exact structure:
{
  "domain": "${domain}",
  "resources": [
    {
      "url": "https://${domain}/path/to/specific-technical-report",
      "title": "Article Title",
      "estimatedType": "FULL_ATTACK_CHAIN",
      "relevanceReason": "Multi-stage loader and lateral movement analysis",
      "isHighValue": true
    }
  ]
}
Return pure JSON only.`;

  try {
    const res = await runAgyCli(
      [
        "--print",
        prompt,
        "--output-format",
        "json",
        "--model",
        model,
        "--dangerously-skip-permissions",
        "--print-timeout",
        `${timeoutSec}s`,
      ],
      (timeoutSec + 15) * 1000,
    );

    if (res.code === 0 && res.stdout) {
      const parsed = extractJsonPayload(res.stdout);
      const rawList = Array.isArray(parsed)
        ? parsed
        : Array.isArray(parsed?.resources)
        ? parsed.resources
        : [];

      const resources: DiscoveredDomainResource[] = [];
      const seenUrls = new Set<string>();

      for (const item of rawList) {
        if (!item || !item.url) continue;
        const urlStr = String(item.url).trim();
        try {
          const u = new URL(urlStr);
          const itemHost = u.hostname.toLowerCase().replace(/^www\./, "");
          if (itemHost === domain || itemHost.endsWith(`.${domain}`)) {
            if (!seenUrls.has(u.href)) {
              seenUrls.add(u.href);
              const estType: ResourceKind = VALID_RESOURCE_KINDS.has(item.estimatedType as ResourceKind)
                ? (item.estimatedType as ResourceKind)
                : "FULL_ATTACK_CHAIN";
              resources.push({
                url: u.href,
                title: String(item.title || u.pathname.split("/").filter(Boolean).pop() || domain),
                category: item.category || "Threat Research",
                relevanceReason: item.relevanceReason || "Identified by Agent as high-signal research report",
                estimatedType: estType,
                isHighValue: Boolean(item.isHighValue ?? true),
              });
            }
          }
        } catch {
          /* ignore invalid URL */
        }
      }

      if (resources.length > 0) {
        return {
          success: true,
          domain,
          baseUrl,
          resources,
          totalExtracted: resources.length,
        };
      }
    }
  } catch {
    // Falls through to heuristic anchor extraction fallback
  }

  // Fallback: Automated anchor extraction from HTML snippet if agent failed or returned empty
  const fallbackResources: DiscoveredDomainResource[] = [];
  if (options.htmlSnippet) {
    const linkRegex = /href=["'](https?:\/\/[^"'>]+|\/[^"'>]+)["'][^>]*>(.*?)<\/a>/gi;
    let match: RegExpExecArray | null;
    const seen = new Set<string>();

    while ((match = linkRegex.exec(options.htmlSnippet)) !== null) {
      let rawHref = match[1];
      const rawTitle = match[2].replace(/<[^>]+>/g, "").trim();

      if (rawHref.startsWith("/")) {
        rawHref = `${baseUrl.replace(/\/+$/, "")}${rawHref}`;
      }

      try {
        const u = new URL(rawHref);
        const host = u.hostname.toLowerCase().replace(/^www\./, "");
        if (host === domain || host.endsWith(`.${domain}`)) {
          const path = u.pathname;
          // Filter for likely research articles (has depth, date, or research keywords)
          const isArticleCandidate =
            /\/(?:blog|research|labs|threat-intel|advisories|reports|posts)\/[a-z0-9_-]{5,}/i.test(path) ||
            /\/\d{4}\/\d{2}\/[a-z0-9_-]+/i.test(path) ||
            /-(?:ransomware|apt|malware|cve|zero-day|backdoor|loader|exploit)/i.test(path);

          if (isArticleCandidate && !seen.has(u.href)) {
            seen.add(u.href);
            fallbackResources.push({
              url: u.href,
              title: rawTitle || path.split("/").filter(Boolean).pop()?.replace(/[-_]/g, " ") || "Threat Analysis",
              category: "Threat Research",
              relevanceReason: "Pattern-matched research article endpoint from domain extraction",
              estimatedType: "FULL_ATTACK_CHAIN",
              isHighValue: true,
            });
          }
        }
      } catch {}
    }
  }

  return {
    success: fallbackResources.length > 0,
    domain,
    baseUrl,
    resources: fallbackResources,
    totalExtracted: fallbackResources.length,
  };
}

/**
 * Intelligent Resource Analysis, Tagging & 5-Dimensional Approval Validation:
 * Evaluates extracted text, identifies TTPs, attack chains, and maps directly to the
 * 5-dimensional rubric specified in the domain-resource-discovery-intel skill:
 * 1. Procedural Depth (0 - 30 pts)
 * 2. Attack Progression / Chain Completeness (0 - 25 pts)
 * 3. Attribution & Context (0 - 15 pts)
 * 4. Emulation & Detection Utility (0 - 20 pts)
 * 5. IOC Verifiability (0 - 10 pts)
 */
export async function evaluateResourceWithAgent(options: {
  text: string;
  title: string;
  url: string;
  domain?: string;
  timeoutSeconds?: number;
  model?: string;
}): Promise<AgentEvaluationResult> {
  const timeoutSec = options.timeoutSeconds ?? 45;
  const model = options.model || "gemini-3.8-flash-low";
  const textSnippet = options.text.slice(0, 4500);

  const prompt = `You are the Senior Threat Intelligence Analysis & Adversary Emulation Evaluation Agent operating under the domain-resource-discovery-intel skill.
Analyze the following threat intelligence report snippet and determine whether it contains actionable adversary tradecraft, multi-stage attack chains, or emulation utility using a strict 5-dimensional scoring rubric.

TITLE: ${options.title}
URL: ${options.url}
CONTENT SNIPPET:
${textSnippet}

INSTRUCTIONS:
1. Evaluate the content against this 5-DIMENSIONAL RUBRIC (Total 100 points):
   - Dimension 1: Procedural Depth (0 to 30 pts): Concrete execution commands (PowerShell, cmd, LOLBins, bash), API call sequences, registry keys, process injection, DLL sideloading, or driver tampering.
   - Dimension 2: Attack Progression & Chain Completeness (0 to 25 pts): Multi-stage sequential intrusion flow (Initial Access -> Loader -> Execution -> Lateral Movement -> C2 -> Impact).
   - Dimension 3: Attribution & Threat Context (0 to 15 pts): Identified threat actor (APT, cybercrime syndicate), campaign timeline, targeted sectors, or weaponized CVE references.
   - Dimension 4: Emulation & Detection Utility (0 to 20 pts): Direct utility for purple teams/SOC: Sigma rules, YARA rules, EDR/Sysmon telemetry queries, or Atomic Red Team / Caldera replay commands.
   - Dimension 5: IOC & Telemetry Verifiability (0 to 10 pts): Defanged network indicators (C2 IPs, domains), file hashes (SHA256), Windows Event IDs, Sysmon events.
   - Total Score = sum of the 5 dimensions (0 - 100).
   - recommendApproval: true if Total Score >= 50, false if < 50.

2. Assign exactly ONE Classification from this STRICT taxonomy:
   - "ADVERSARY_EMULATION" (concrete command lines, atomic test plans, emulation blueprints)
   - "ADVERSARY_SIMULATION" (purple team scenarios, breach simulation)
   - "ATTACK_CHAIN_REPORT" (end-to-end multi-stage intrusion flows)
   - "INTRUSION_REPORT" (incident response investigations, DFIR timelines)
   - "MALWARE_ANALYSIS" (reverse engineering, loaders, beacons, infostealers)
   - "THREAT_ACTOR_REPORT" (targeted adversary group tracking, dossiers)
   - "CAMPAIGN_REPORT" (widespread adversary campaign tracking)
   - "VULNERABILITY_REPORT" (exploit analysis, zero-days, CVE weaponization)
   - "DETECTION_RESEARCH" (Sigma rules, YARA signatures, hunting queries)
   - "SECURITY_ADVISORY" (vendor/CERT vulnerability advisories)
   - "OTHER" (generic news, high-level marketing)

3. Assign exactly ONE ResourceKind from this STRICT taxonomy:
   - "FULL_ATTACK_CHAIN", "CAMPAIGN_INTEL", "PROCEDURE_DEEPDIVE", "MALWARE_ANALYSIS", "DETECTION_GUIDANCE", "VULNERABILITY_ADVISORY", "THREAT_ACTOR_DOSSIER"

4. Extract MITRE ATT&CK technique IDs (e.g., T1059.001, T1055, T1078).
5. Extract named threat actors, malware families, and CVEs.

OUTPUT FORMAT:
Return pure JSON matching this exact schema:
{
  "isRelevant": true,
  "passScore": 86,
  "recommendApproval": true,
  "classification": "ATTACK_CHAIN_REPORT",
  "resourceKind": "FULL_ATTACK_CHAIN",
  "threatActors": ["Lazarus", "APT38"],
  "malwareFamilies": ["ComeBackCode"],
  "cves": ["CVE-2023-46805"],
  "mitreTechniques": ["T1059.001", "T1055.012"],
  "stages": ["Initial Phishing", "DLL Sideloading", "C2 Beaconing"],
  "scoreBreakdown": {
    "proceduralDepth": 26,
    "attackProgression": 24,
    "attributionContext": 13,
    "emulationUtility": 15,
    "iocVerifiability": 8,
    "totalScore": 86
  },
  "rationale": "High-fidelity intrusion flow with concrete PowerShell commands and DLL sideloading mechanics."
}
Return pure JSON only.`;

  try {
    const res = await runAgyCli(
      [
        "--print",
        prompt,
        "--output-format",
        "json",
        "--model",
        model,
        "--dangerously-skip-permissions",
        "--print-timeout",
        `${timeoutSec}s`,
      ],
      (timeoutSec + 15) * 1000,
    );

    if (res.code !== 0 && !res.stdout) {
      return {
        success: false,
        fallback: true,
        isRelevant: false,
        passScore: 0,
        recommendApproval: false,
        classification: "OTHER",
        resourceKind: "CAMPAIGN_INTEL",
        threatActors: [],
        malwareFamilies: [],
        cves: [],
        mitreTechniques: [],
        rationale: "Agent process failed or returned empty output",
        error: res.stderr.slice(0, 200),
      };
    }

    const parsed = extractJsonPayload(res.stdout);

    // Validate classification against crawler taxonomy
    let classification: ResourceClassification = "THREAT_REPORT";
    if (parsed.classification && VALID_CLASSIFICATIONS.has(parsed.classification as ResourceClassification)) {
      classification = parsed.classification as ResourceClassification;
    }

    // Validate resourceKind against crawler taxonomy
    let resourceKind: ResourceKind = "CAMPAIGN_INTEL";
    if (parsed.resourceKind && VALID_RESOURCE_KINDS.has(parsed.resourceKind as ResourceKind)) {
      resourceKind = parsed.resourceKind as ResourceKind;
    }

    // Parse and normalize 5-dimensional score breakdown
    const rawBreakdown = parsed.scoreBreakdown;
    let scoreBreakdown: AgentScoreBreakdown;
    if (rawBreakdown && typeof rawBreakdown === "object") {
      const p = Math.min(Math.max(Number(rawBreakdown.proceduralDepth ?? 0), 0), 30);
      const a = Math.min(Math.max(Number(rawBreakdown.attackProgression ?? 0), 0), 25);
      const at = Math.min(Math.max(Number(rawBreakdown.attributionContext ?? 0), 0), 15);
      const e = Math.min(Math.max(Number(rawBreakdown.emulationUtility ?? 0), 0), 20);
      const i = Math.min(Math.max(Number(rawBreakdown.iocVerifiability ?? 0), 0), 10);
      const computedTotal = p + a + at + e + i;
      scoreBreakdown = {
        proceduralDepth: p,
        attackProgression: a,
        attributionContext: at,
        emulationUtility: e,
        iocVerifiability: i,
        totalScore: Math.min(Math.max(Number(rawBreakdown.totalScore ?? computedTotal), 0), 100),
      };
    } else {
      const s = Math.min(Math.max(Number(parsed.passScore ?? 50), 0), 100);
      scoreBreakdown = {
        proceduralDepth: Math.round(s * 0.30),
        attackProgression: Math.round(s * 0.25),
        attributionContext: Math.round(s * 0.15),
        emulationUtility: Math.round(s * 0.20),
        iocVerifiability: Math.round(s * 0.10),
        totalScore: s,
      };
    }

    const passScore = scoreBreakdown.totalScore;
    const recommendApproval = Boolean(parsed.recommendApproval ?? (passScore >= 50));

    // Clean MITRE IDs
    const mitreTechniques: string[] = Array.isArray(parsed.mitreTechniques)
      ? parsed.mitreTechniques
          .map((t: any) => String(t).toUpperCase().trim())
          .filter((t: string) => /^T\d{4}(?:\.\d{3})?$/.test(t))
      : [];

    return {
      success: true,
      fallback: false,
      isRelevant: Boolean(parsed.isRelevant ?? (passScore >= 40)),
      passScore,
      recommendApproval,
      classification,
      resourceKind,
      threatActors: Array.isArray(parsed.threatActors) ? parsed.threatActors.map(String) : [],
      malwareFamilies: Array.isArray(parsed.malwareFamilies) ? parsed.malwareFamilies.map(String) : [],
      cves: Array.isArray(parsed.cves) ? parsed.cves.map(String) : [],
      mitreTechniques,
      stages: Array.isArray(parsed.stages) ? parsed.stages.map(String) : [],
      scoreBreakdown,
      rationale: parsed.rationale || "Evaluated by AGY Threat Intelligence Agent with 5-dimensional rubric",
    };
  } catch (err) {
    return {
      success: false,
      fallback: true,
      isRelevant: false,
      passScore: 0,
      recommendApproval: false,
      classification: "OTHER",
      resourceKind: "CAMPAIGN_INTEL",
      threatActors: [],
      malwareFamilies: [],
      cves: [],
      mitreTechniques: [],
      rationale: `Agent evaluation fallback: ${(err as Error).message}`,
      error: (err as Error).message,
    };
  }
}
