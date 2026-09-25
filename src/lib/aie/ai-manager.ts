/**
 * Unified AI Provider & Agent Orchestration Layer
 *
 * Provides a modular, provider-agnostic interface for AI operations across:
 * - Local CLI Agents (Antigravity AGY Agent in Docker Sandbox, WSL, Native)
 * - Direct REST API Providers (Google Gemini API, Anthropic Claude API, OpenAI/Local LLM API)
 *
 * Guiding Principles:
 * 1. Zero Single Point of Failure (Zero-SPOF): Any failure or timeout in any AI provider
 *    gracefully falls back to secondary provider or heuristic evaluation without blocking operations.
 * 2. Absolute backward compatibility: Antigravity AGY Agent remains 100% supported as default.
 * 3. Enforces model prefixing (e.g. `AGY: gemini-3.8-flash-low`, `Gemini API: gemini-2.5-flash`, `Claude API: claude-3-7-sonnet`).
 */

import {
  discoverAgentSources,
  evaluateResourceWithAgent,
  discoverDomainResourcesWithAgent,
  PREMIER_RESEARCH_LABS,
  type AgentEvaluationResult,
  type DiscoveredAgentSource,
  type DomainResourceHarvestResult,
  type DiscoveredDomainResource,
} from "./agy-agent";
import {
  getProviderAdapter,
  isRestApiProvider,
  type LLMGenerateResult,
} from "./providers";
import type { ResourceClassification } from "./qualification";
import type { AppSettings, ResourceKind, AgentScoreBreakdown, ReportListItem } from "./types";
import { mongoGetAppSettings, mongoGetMarketplaceIntegrations } from "../mongodb/repository.server";
import { executeInAgentSandbox, type ExecutionTrace } from "./agent-sandbox";
import { logger } from "./logger";

export type UnifiedDiscoveryParams = {
  existingDomains: string[];
  limit?: number;
  model?: string;
  timeoutSeconds?: number;
  providerId?: string;
};

export type UnifiedDiscoveryResult = {
  success: boolean;
  fallback: boolean;
  providerId: string;
  providerName: string;
  sources: DiscoveredAgentSource[];
  candidateCount?: number;
  candidateDomains?: string[];
  error?: string;
};

export type UnifiedEvaluationParams = {
  url: string;
  domain: string;
  title?: string;
  text: string;
  html?: string;
  model?: string;
  timeoutSeconds?: number;
  providerId?: string;
};

export type UnifiedDomainHarvestParams = {
  domain: string;
  baseUrl: string;
  htmlSnippet?: string;
  model?: string;
  timeoutSeconds?: number;
  providerId?: string;
};

export interface UnifiedChatParams {
  userMessage: string;
  groundedReports?: ReportListItem[];
  model?: string;
  providerId?: string;
  timeoutSeconds?: number;
}

export interface UnifiedChatResult {
  success: boolean;
  reply: string;
  model: string;
  providerId: string;
  latencyMs: number;
  error?: string;
  trace?: ExecutionTrace;
  tokens?: { inputTokens: number; outputTokens: number; totalTokens: number };
}

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

/**
 * Strips the provider prefix from model strings:
 * "AGY: gemini-3.8-flash-low" -> "gemini-3.8-flash-low"
 * "Gemini API: gemini-2.5-flash" -> "gemini-2.5-flash"
 * "Claude API: claude-3-7-sonnet" -> "claude-3-7-sonnet"
 */
export function stripModelPrefix(modelName?: string): string {
  if (!modelName) return "gemini-3.8-flash-low";
  const colonIdx = modelName.indexOf(":");
  if (colonIdx >= 0) {
    return modelName.slice(colonIdx + 1).trim();
  }
  return modelName.trim();
}

/**
 * Formats a raw model name with its provider prefix if not already present
 */
export function formatPrefixedModel(providerName: string, rawModel: string): string {
  if (rawModel.includes(":")) return rawModel;
  return `${providerName}: ${rawModel}`;
}

/**
 * Extracts clean JSON payload from raw LLM output, handling markdown code fences
 */
export function extractJsonFromLlmText(text: string): any {
  const raw = text.trim();
  if (!raw) throw new Error("Empty text received from LLM");

  // If inside an envelope
  try {
    const envelope = JSON.parse(raw);
    if (envelope && typeof envelope === "object") {
      if (envelope.structured_output) return envelope.structured_output;
      if (typeof envelope.response === "string") {
        return extractJsonFromLlmText(envelope.response);
      }
    }
  } catch {}

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
 * Retrieves the currently active AI provider, model, API keys, and configurations
 */
export async function getActiveAIProvider(): Promise<{
  providerId: string;
  providerName: string;
  model: string;
  rawModel: string;
  timeoutSeconds: number;
  apiKey?: string;
  endpointUrl?: string;
  isRest: boolean;
}> {
  try {
    const settings = await mongoGetAppSettings();
    const integrations = await mongoGetMarketplaceIntegrations();

    const providerId = settings.activeAgentProvider || "agy_agent";
    const integration = integrations.find((x) => x.id === providerId) || integrations[0];

    const providerName = integration ? integration.name : "Antigravity AGY Agent";
    const model = settings.agentModel || "AGY: gemini-3.8-flash-low";
    const rawModel = stripModelPrefix(model);
    const timeoutSeconds = settings.agentTimeoutSeconds || 45;

    // Resolve API key from integration config or environment variables
    const apiKey =
      integration?.config?.apiKey ||
      (providerId === "gemini_api"
        ? process.env.GEMINI_API_KEY
        : providerId === "claude_api"
        ? process.env.ANTHROPIC_API_KEY
        : providerId === "openai_api" || providerId === "codex_agent"
        ? process.env.OPENAI_API_KEY
        : undefined);

    const endpointUrl = integration?.endpointUrl;
    const isRest = isRestApiProvider(providerId);

    return {
      providerId,
      providerName,
      model,
      rawModel,
      timeoutSeconds,
      apiKey,
      endpointUrl,
      isRest,
    };
  } catch (err) {
    return {
      providerId: "agy_agent",
      providerName: "Antigravity AGY Agent",
      model: "AGY: gemini-3.8-flash-low",
      rawModel: "gemini-3.8-flash-low",
      timeoutSeconds: 45,
      isRest: false,
    };
  }
}

/**
 * Retrieves all available models across installed integrations
 */
export async function getAvailableAgentModels(): Promise<
  Array<{
    providerId: string;
    providerName: string;
    modelValue: string;
    label: string;
    isInstalled: boolean;
  }>
> {
  const integrations = await mongoGetMarketplaceIntegrations();
  const result: Array<{
    providerId: string;
    providerName: string;
    modelValue: string;
    label: string;
    isInstalled: boolean;
  }> = [];

  for (const item of integrations) {
    const isInstalled = item.status === "installed";
    for (const m of item.supportedModels) {
      result.push({
        providerId: item.id,
        providerName: item.name,
        modelValue: m,
        label: m,
        isInstalled,
      });
    }
  }

  return result;
}

/**
 * Executes autonomous source discovery through the active provider (REST or AGY CLI)
 */
export async function runUnifiedSourceDiscovery(
  params: UnifiedDiscoveryParams
): Promise<UnifiedDiscoveryResult> {
  const active = await getActiveAIProvider();
  const providerId = params.providerId || active.providerId;
  const rawModel = params.model ? stripModelPrefix(params.model) : active.rawModel;
  const timeoutSeconds = params.timeoutSeconds || active.timeoutSeconds;
  const limit = Math.min(Math.max(params.limit ?? 5, 1), 20);
  const knownDomains = params.existingDomains || [];

  logger.agent(
    "DISCOVERY",
    `[UnifiedAI] Starting source discovery via provider: ${active.providerName} (model: ${rawModel})`
  );

  // 1. Direct REST Provider execution (Gemini API, Claude API, OpenAI API)
  const adapter = getProviderAdapter(providerId);
  if (adapter && active.isRest) {
    const knownListSnippet =
      knownDomains.length > 0
        ? `\nALREADY KNOWN DOMAINS (DO NOT RETURN THESE):\n${knownDomains.slice(0, 60).map((d) => `- ${d}`).join("\n")}\n`
        : "";

    const prompt = `You are an Adversary Emulation Intelligence Source Hunter operating under the Resource Collection Skill.
Discover exactly ${limit} NEW, distinct, highly technical threat intelligence sources or research lab endpoints.
Objective: Authoritative technical publications documenting multi-stage intrusion flows, loader reverse engineering, incident response timelines, and ATT&CK-mapped TTPs.
${knownListSnippet}
OUTPUT FORMAT:
Return pure, valid JSON with this exact structure:
{
  "sources": [
    {
      "source_name": "Publisher Name (e.g. Check Point Research)",
      "domain": "research.checkpoint.com",
      "crawl_pattern": "https://research.checkpoint.com/*",
      "base_url": "https://research.checkpoint.com",
      "primary_content": ["Attack Chains", "Malware Analysis", "TTPs"],
      "why_crawl": "Publishes in-depth reverse engineering of zero-days and nation-state loaders"
    }
  ]
}
Return pure JSON only.`;

    try {
      const res = await adapter.generate({
        prompt,
        model: rawModel,
        apiKey: active.apiKey,
        timeoutMs: timeoutSeconds * 1000,
        responseFormat: "json",
      });

      if (res.success && res.text) {
        const payload = extractJsonFromLlmText(res.text);
        const rawList: any[] = Array.isArray(payload)
          ? payload
          : Array.isArray(payload?.sources)
          ? payload.sources
          : [];

        const existingSet = new Set(knownDomains.map((d) => d.toLowerCase().trim()));
        const validSources: DiscoveredAgentSource[] = [];

        for (const item of rawList) {
          if (!item || typeof item !== "object") continue;
          const rawDomain = (item.domain || item.source_domain || "").toLowerCase().trim().replace(/^www\./, "");
          if (!rawDomain || existingSet.has(rawDomain)) continue;

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
            why_crawl: item.why_crawl || "Discovered by AI Agent as high-value threat intelligence source",
            confidence: 0.92,
          });
          existingSet.add(rawDomain);
        }

        if (validSources.length > 0) {
          return {
            success: true,
            fallback: false,
            providerId,
            providerName: active.providerName,
            sources: validSources,
            candidateCount: validSources.length,
            candidateDomains: validSources.map((s) => s.domain),
          };
        }
      }
    } catch (restErr: any) {
      logger.agent("FAILSAFE", `REST provider discovery failed (${restErr?.message}), cascading to AGY/Premier labs`);
    }
  }

  // 2. AGY CLI Agent in Docker Sandbox
  try {
    const agyRes = await discoverAgentSources({
      existingDomains: params.existingDomains,
      limit,
      model: rawModel,
      timeoutSeconds,
    });

    return {
      success: !agyRes.error,
      fallback: Boolean(agyRes.error),
      providerId: "agy_agent",
      providerName: "Antigravity AGY Agent",
      sources: agyRes.sources || [],
      candidateCount: agyRes.candidateCount,
      candidateDomains: agyRes.candidateDomains,
      error: agyRes.error,
    };
  } catch (err: any) {
    logger.agent("FAILSAFE", `AGY discovery failed, returning Premier labs fallback: ${err.message}`);
    const existingSet = new Set(knownDomains.map((d) => d.toLowerCase().trim()));
    const fallbackSources: DiscoveredAgentSource[] = [];

    for (const lab of PREMIER_RESEARCH_LABS) {
      if (fallbackSources.length >= limit) break;
      if (!existingSet.has(lab.domain.toLowerCase())) {
        fallbackSources.push({
          source_name: lab.source_name,
          domain: lab.domain,
          crawl_pattern: lab.crawl_pattern,
          base_url: lab.base_url,
          primary_content: lab.primary_content,
          why_crawl: lab.why_crawl,
          confidence: 0.95,
        });
        existingSet.add(lab.domain.toLowerCase());
      }
    }

    return {
      success: true,
      fallback: true,
      providerId: "fallback_premier",
      providerName: "Curated Premier Threat Labs",
      sources: fallbackSources,
      candidateCount: fallbackSources.length,
      candidateDomains: fallbackSources.map((s) => s.domain),
    };
  }
}

/**
 * Executes coordinated target domain resource extraction through the active AI provider
 */
export async function runUnifiedDomainResourceDiscovery(
  params: UnifiedDomainHarvestParams
): Promise<DomainResourceHarvestResult> {
  const active = await getActiveAIProvider();
  const providerId = params.providerId || active.providerId;
  const rawModel = params.model ? stripModelPrefix(params.model) : active.rawModel;
  const timeoutSeconds = params.timeoutSeconds || active.timeoutSeconds;
  const domain = params.domain.toLowerCase().replace(/^www\./, "");
  const baseUrl = params.baseUrl.startsWith("http") ? params.baseUrl : `https://${domain}`;

  // 1. Direct REST Provider execution
  const adapter = getProviderAdapter(providerId);
  if (adapter && active.isRest) {
    const prompt = `You are the Adversary Emulation Domain Harvester operating under the domain-resource-discovery-intel skill.
TARGET DOMAIN: ${domain}
BASE URL: ${baseUrl}
CONTEXT / HTML EXCERPT:
${(params.htmlSnippet || "").slice(0, 4500)}

MISSION:
Identify all authoritative technical threat intelligence articles, research papers, malware reverse-engineering posts, and attack chain timelines hosted on this domain.
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
      const res = await adapter.generate({
        prompt,
        model: rawModel,
        apiKey: active.apiKey,
        timeoutMs: timeoutSeconds * 1000,
        responseFormat: "json",
      });

      if (res.success && res.text) {
        const parsed = extractJsonFromLlmText(res.text);
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
          } catch {}
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
    } catch (restErr: any) {
      logger.agent("FAILSAFE", `REST domain harvest failed (${restErr?.message}), cascading to AGY/anchor fallback`);
    }
  }

  // 2. Cascade to AGY CLI / anchor heuristic extractor
  return discoverDomainResourcesWithAgent({
    domain: params.domain,
    baseUrl: params.baseUrl,
    htmlSnippet: params.htmlSnippet,
    model: rawModel,
    timeoutSeconds,
  });
}

/**
 * Executes resource qualification and 5-dimensional ATT&CK tagging through the active provider
 */
export async function runUnifiedResourceEvaluation(
  params: UnifiedEvaluationParams
): Promise<AgentEvaluationResult> {
  const active = await getActiveAIProvider();
  const providerId = params.providerId || active.providerId;
  const rawModel = params.model ? stripModelPrefix(params.model) : active.rawModel;
  const timeoutSeconds = params.timeoutSeconds || active.timeoutSeconds;
  const textSnippet = params.text.slice(0, 4800);

  // 1. Direct REST Provider execution
  const adapter = getProviderAdapter(providerId);
  if (adapter && active.isRest) {
    const prompt = `You are the Senior Threat Intelligence Analysis & Adversary Emulation Evaluation Agent operating under the domain-resource-discovery-intel skill.
Analyze the following threat intelligence report snippet and determine whether it contains actionable adversary tradecraft, multi-stage attack chains, or emulation utility using a strict 5-dimensional scoring rubric.

TITLE: ${params.title || "Threat Report"}
URL: ${params.url}
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
   - "ADVERSARY_EMULATION", "ADVERSARY_SIMULATION", "ATTACK_CHAIN_REPORT", "INTRUSION_REPORT", "MALWARE_ANALYSIS", "THREAT_ACTOR_REPORT", "CAMPAIGN_REPORT", "VULNERABILITY_REPORT", "DETECTION_RESEARCH", "SECURITY_ADVISORY", "OTHER"

3. Assign exactly ONE ResourceKind from this STRICT taxonomy:
   - "FULL_ATTACK_CHAIN", "CAMPAIGN_INTEL", "PROCEDURE_DEEPDIVE", "MALWARE_ANALYSIS", "DETECTION_GUIDANCE", "VULNERABILITY_ADVISORY", "THREAT_ACTOR_DOSSIER"

OUTPUT FORMAT:
Return pure valid JSON with this exact structure:
{
  "isRelevant": true,
  "passScore": 86,
  "recommendApproval": true,
  "classification": "ATTACK_CHAIN_REPORT",
  "resourceKind": "FULL_ATTACK_CHAIN",
  "threatActors": ["Volt Typhoon"],
  "malwareFamilies": ["KV-botnet", "Fast Reverse Proxy"],
  "cves": ["CVE-2023-46805"],
  "mitreTechniques": ["T1190", "T1059.001", "T1078", "T1572"],
  "scoreBreakdown": {
    "proceduralDepth": 26,
    "attackProgression": 24,
    "attributionContext": 13,
    "emulationUtility": 15,
    "iocVerifiability": 8,
    "totalScore": 86
  },
  "rationale": "High-fidelity intrusion flow with concrete execution commands and persistence mechanics."
}
Return pure JSON only.`;

    try {
      const res = await adapter.generate({
        prompt,
        model: rawModel,
        apiKey: active.apiKey,
        timeoutMs: timeoutSeconds * 1000,
        responseFormat: "json",
      });

      if (res.success && res.text) {
        const parsed = extractJsonFromLlmText(res.text);

        let classification: ResourceClassification = "THREAT_REPORT";
        if (parsed.classification && VALID_CLASSIFICATIONS.has(parsed.classification as ResourceClassification)) {
          classification = parsed.classification as ResourceClassification;
        }

        let resourceKind: ResourceKind = "CAMPAIGN_INTEL";
        if (parsed.resourceKind && VALID_RESOURCE_KINDS.has(parsed.resourceKind as ResourceKind)) {
          resourceKind = parsed.resourceKind as ResourceKind;
        }

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
          cves: Array.isArray(parsed.cves) ? parsed.cves.map((c: any) => String(c).toUpperCase().trim()).filter((c: string) => /^CVE-\d{4}-\d+$/.test(c)) : [],
          mitreTechniques,
          rationale: parsed.rationale || "5-dimensional adversary procedure evaluation completed by AI provider.",
          scoreBreakdown,
          tokensUsed: res.tokensUsed,
          providerId,
          providerName: active.providerName,
        };
      }
    } catch (restErr: any) {
      logger.agent("FAILSAFE", `REST evaluation failed (${restErr?.message}), cascading to AGY sandbox`);
    }
  }

  // 2. Cascade to AGY CLI in Docker Sandbox
  return evaluateResourceWithAgent({
    url: params.url,
    domain: params.domain,
    title: params.title || "",
    text: params.text,
    model: rawModel,
    timeoutSeconds,
  });
}

/**
 * Unified Conversational RAG Engine supporting both REST providers and AGY Sandbox
 */
export async function chatWithUnifiedAgent(params: UnifiedChatParams): Promise<UnifiedChatResult> {
  const active = await getActiveAIProvider();
  const providerId = params.providerId || active.providerId;
  const rawModel = params.model ? stripModelPrefix(params.model) : active.rawModel;
  const timeoutSeconds = params.timeoutSeconds || 40;

  // Build Grounded Context from Local Library Reports
  let contextDocs = "";
  if (params.groundedReports && params.groundedReports.length > 0) {
    params.groundedReports.slice(0, 4).forEach((r, idx) => {
      const actors = (r.analysis?.threatActors || []).join(", ") || "Unspecified";
      const malware = (r.analysis?.malware || []).join(", ") || "Unspecified";
      const cves = (r.extractedEntities?.cves || []).join(", ") || "None";
      const techniques = (r.extractedEntities?.techniques || [])
        .map((t) => (typeof t === "string" ? t : `${t.id} ${t.name}`))
        .join(", ") || "None";

      contextDocs += `
[LOCAL INTEL REPORT #${idx + 1}]
ID: ${r.id}
Title: "${r.title}"
Publisher: ${r.publisher || r.sourceName} | Kind: ${r.resourceKind || "CAMPAIGN_INTEL"}
Threat Actors: ${actors} | Malware/Tooling: ${malware} | CVEs: ${cves}
MITRE ATT&CK Techniques: ${techniques}
Excerpt: "${(r.matchedSnippet || r.excerpt || "").slice(0, 450)}"
URL: ${r.canonicalUrl || r.url}
`;
    });
  }

  const systemInstruction = `You are the Lead Adversary Emulation & Cyber Threat Intelligence AI Specialist for the AIE Platform.
Ground your responses in verified CTI tradecraft, MITRE ATT&CK techniques (e.g. T1059.001), exact command-lines, and structured purple team emulation steps.
${contextDocs ? `\nVERIFIED GROUNDED LOCAL INTELLIGENCE FROM PLATFORM:\n${contextDocs}` : ""}`;

  // 1. Direct REST Provider execution
  const adapter = getProviderAdapter(providerId);
  if (adapter && active.isRest) {
    const res = await adapter.generate({
      prompt: params.userMessage,
      systemInstruction,
      model: rawModel,
      apiKey: active.apiKey,
      timeoutMs: timeoutSeconds * 1000,
    });

    return {
      success: res.success,
      reply: res.text || res.error || "No response produced by model.",
      model: rawModel,
      providerId,
      latencyMs: res.latencyMs,
      error: res.error,
      tokens: res.tokens,
    };
  }

  // 2. AGY CLI in Docker Sandbox
  const promptToSend = `${systemInstruction}\n\nUSER INQUIRY:\n${params.userMessage}`;
  const sandboxRes = await executeInAgentSandbox(
    ["--dangerously-skip-permissions", "--print", promptToSend, "--model", rawModel],
    { timeoutMs: timeoutSeconds * 1000, category: "agent" }
  );

  return {
    success: sandboxRes.success,
    reply: sandboxRes.output || sandboxRes.error || "Agent did not produce output.",
    model: rawModel,
    providerId: "agy_agent",
    latencyMs: sandboxRes.latencyMs,
    error: sandboxRes.error,
    trace: sandboxRes.trace,
  };
}
