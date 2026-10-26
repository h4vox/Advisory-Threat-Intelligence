/**
 * Unified AI Provider & Agent Orchestration Layer
 *
 * Provides a modular, provider-agnostic interface for AI operations across:
 * - Local CLI Agent (Antigravity AGY Agent, Docker sandbox container only — no host execution)
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
  REST_PROVIDER_META,
  type LLMGenerateResult,
} from "./providers";
import type { ResourceClassification } from "./qualification";
import type { AppSettings, ResourceKind, AgentScoreBreakdown, ReportListItem } from "./types";
import { mongoGetAppSettings, mongoGetMarketplaceIntegrations } from "../mongodb/repository.server";
import { probeAgySandboxUsable, type ExecutionTrace } from "./agent-sandbox";
import { logger } from "./logger";
import {
  sanitizeAgyModel,
  DEFAULT_AGY_MODEL,
  UNTRUSTED_CONTENT_NOTICE,
  wrapUntrustedContent,
} from "./agent-framework/types";
import { backgroundAgentService, warmAgentService } from "./warm-agent-service";
import { translateDocument, type ChunkTranslator, type DocumentTranslation } from "./translation";
import { ANALYSIS_SYSTEM, buildAnalysisPrompt, groundReportAnalysis, type AnalysisPromptInput, type ReportAiAnalysis } from "./report-ai-analysis";
import { sha256Hex } from "./retrieval";

export type UnifiedDiscoveryParams = {
  existingDomains: string[];
  limit?: number;
  model?: string;
  timeoutSeconds?: number;
  providerId?: string;
  /** False when the caller knows the AGY sandbox cannot answer: a REST failure then returns a fallback instead of cascading into it. */
  allowSandboxFallback?: boolean;
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
  /** False when the caller knows the AGY sandbox cannot answer: a REST failure then returns a fallback instead of cascading into it. */
  allowSandboxFallback?: boolean;
};

export type UnifiedDomainHarvestParams = {
  domain: string;
  baseUrl: string;
  htmlSnippet?: string;
  model?: string;
  timeoutSeconds?: number;
  providerId?: string;
  /** False when the caller knows the AGY sandbox cannot answer: a REST failure then returns a fallback instead of cascading into it. */
  allowSandboxFallback?: boolean;
};

export interface UnifiedChatParams {
  userMessage: string;
  history?: Array<{ sender: "user" | "agent"; text: string }>;
  groundedReports?: ReportListItem[];
  /**
   * Complete grounded prompt (passages + rules + history + question) from
   * `buildGroundedPrompt`. When set it is sent as-is and `groundedReports` /
   * `history` are ignored.
   */
  groundedPrompt?: string;
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
  /** SHA-256 of the exact instruction + prompt text sent (grounded path only). */
  promptSha256?: string;
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
  if (!modelName) return DEFAULT_AGY_MODEL;
  const colonIdx = modelName.indexOf(":");
  const cleaned = colonIdx >= 0 ? modelName.slice(colonIdx + 1).trim() : modelName.trim();
  return sanitizeAgyModel(cleaned);
}

/**
 * Formats a raw model name with its provider prefix if not already present
 */
export function formatPrefixedModel(providerName: string, rawModel: string): string {
  if (rawModel.includes(":")) return rawModel;
  return `${providerName}: ${rawModel}`;
}

/** Removes a "Provider: " display prefix without AGY model normalisation. */
function stripProviderPrefix(modelName: string): string {
  const colonIdx = modelName.indexOf(":");
  return (colonIdx >= 0 ? modelName.slice(colonIdx + 1) : modelName).trim();
}

// Defaults and model-recognition come from the provider registry (providers/index.ts), the single
// source of truth, so adding a provider there makes it work here with no change.
const REST_PROVIDER_DEFAULT_MODELS: Record<string, string> = Object.fromEntries(
  Object.values(REST_PROVIDER_META).map((m) => [m.id, m.defaultModel]),
);

const REST_PROVIDER_MODEL_PATTERNS: Record<string, RegExp> = Object.fromEntries(
  Object.values(REST_PROVIDER_META).map((m) => [m.id, m.modelPattern]),
);

/** True when `model` (prefix already stripped) is a model of `providerId`. */
function modelBelongsToProvider(providerId: string, model: string, supportedModels: string[] = []): boolean {
  if (!model) return false;
  const lower = model.toLowerCase();
  if (supportedModels.some((m) => stripProviderPrefix(m).toLowerCase() === lower)) return true;
  return REST_PROVIDER_MODEL_PATTERNS[providerId]?.test(model) ?? false;
}

/**
 * Resolve which model to use for the active provider.
 * - restModel: honours `requested` only if it belongs to the active REST
 *   provider; otherwise the provider's configured model. Never an AGY id for
 *   Claude/OpenAI.
 * - agyModel: a valid AGY sandbox model (used for the agent path and for the
 *   agent cascade after a REST failure).
 */
export function resolveProviderModels(
  active: { providerId: string; rawModel: string; isRest: boolean; supportedModels?: string[] },
  requested?: string
): { restModel: string; agyModel: string } {
  const requestedRaw = requested ? stripProviderPrefix(requested) : "";
  if (active.isRest) {
    const restModel =
      requestedRaw && modelBelongsToProvider(active.providerId, requestedRaw, active.supportedModels)
        ? requestedRaw
        : active.rawModel;
    const agyCandidate = requestedRaw && AGY_REQUEST_PREFIX.test(requested || "") ? requestedRaw : "";
    return { restModel, agyModel: sanitizeAgyModel(agyCandidate || DEFAULT_AGY_MODEL) };
  }
  const agyModel = requestedRaw ? sanitizeAgyModel(requestedRaw) : sanitizeAgyModel(active.rawModel);
  return { restModel: agyModel, agyModel };
}

const AGY_REQUEST_PREFIX = /^\s*AGY\s*:/i;

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
  } catch {
    // Not a JSON envelope: fall through to direct extraction below.
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
  supportedModels?: string[];
}> {
  try {
    const settings = await mongoGetAppSettings();
    const integrations = await mongoGetMarketplaceIntegrations();

    const providerId = settings.activeAgentProvider || "agy_agent";
    const integration = integrations.find((x) => x.id === providerId) || integrations[0];

    const providerName = integration ? integration.name : "Autonomous AI Agent Engine";
    const isRestProvider = isRestApiProvider(providerId);
    const supportedModels: string[] = Array.isArray(integration?.supportedModels) ? integration!.supportedModels : [];
    // REST providers use their own configured model; AGY ids are never sent to them.
    let model: string;
    if (isRestProvider) {
      const candidates = [integration?.config?.selectedModel, settings.agentModel];
      model =
        candidates
          .map((c) => (typeof c === "string" ? stripProviderPrefix(c) : ""))
          .find((c) => c && modelBelongsToProvider(providerId, c, supportedModels)) ||
        REST_PROVIDER_DEFAULT_MODELS[providerId] ||
        "";
    } else {
      model = sanitizeAgyModel(settings.agentModel);
    }
    const rawModel = isRestProvider ? model : stripModelPrefix(model);
    const timeoutSeconds = settings.agentTimeoutSeconds || 45;

    // Resolve API key from integration config or the provider's environment variables (registry-driven).
    const envKey = (REST_PROVIDER_META[providerId]?.envKeys ?? []).map((k) => process.env[k]?.trim()).find(Boolean);
    const apiKey = integration?.config?.apiKey || envKey;

    const endpointUrl = integration?.endpointUrl;
    const isRest = isRestProvider;

    return {
      providerId,
      providerName,
      model,
      rawModel,
      timeoutSeconds,
      apiKey,
      endpointUrl,
      isRest,
      supportedModels,
    };
  } catch (err) {
    return {
      providerId: "agy_agent",
      providerName: "Autonomous AI Agent Engine",
      model: DEFAULT_AGY_MODEL,
      rawModel: DEFAULT_AGY_MODEL,
      timeoutSeconds: 45,
      isRest: false,
    };
  }
}

export type CrawlerAiAvailability = {
  /** Some AI path can answer: a REST provider with a key, or a working sandbox agent. */
  usable: boolean;
  /** The sandbox agent can answer, so a REST failure may cascade to it. */
  sandbox: boolean;
  /** One line for the crawl log. */
  detail: string;
};

/**
 * Decided once per crawl: can AI qualification / discovery answer at all? A crawl must never stall on
 * a dead AI path. An unconfigured provider or an unusable sandbox is skipped up front and articles are
 * qualified by the heuristic engine, instead of every article waiting out an agent timeout (which,
 * with the default AGY provider and no working sandbox, used up whole crawl runs).
 */
export async function resolveCrawlerAiAvailability(): Promise<CrawlerAiAvailability> {
  const active = await getActiveAIProvider();
  const restReady = active.isRest && Boolean(active.apiKey) && Boolean(getProviderAdapter(active.providerId));
  const probe = await probeAgySandboxUsable();
  if (restReady) {
    return { usable: true, sandbox: probe.usable, detail: `${active.providerName} API${probe.usable ? " (sandbox fallback available)" : ""}` };
  }
  if (probe.usable) return { usable: true, sandbox: true, detail: `sandbox agent (${probe.detail})` };
  const why = active.isRest ? `${active.providerName} has no API key and ${probe.detail}` : `the sandbox agent is not usable: ${probe.detail}`;
  return { usable: false, sandbox: false, detail: why };
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
  const { restModel: rawModel, agyModel } = resolveProviderModels(active, params.model);
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
        ? `\nALREADY KNOWN DOMAINS (DO NOT RETURN THESE).\n${UNTRUSTED_CONTENT_NOTICE}\n${wrapUntrustedContent(knownDomains.slice(0, 60).map((d) => `- ${d}`).join("\n"))}\n`
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

  // 2. AGY CLI Agent in Docker Sandbox (skipped when the caller knows it cannot answer)
  try {
    if (params.allowSandboxFallback === false) throw new Error("AGY sandbox unavailable");
    const agyRes = await discoverAgentSources({
      existingDomains: params.existingDomains,
      limit,
      model: agyModel,
      timeoutSeconds,
    });

    return {
      success: !agyRes.error,
      fallback: Boolean(agyRes.error),
      providerId: "agy_agent",
      providerName: "Autonomous Threat Intelligence Agent",
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
  const { restModel: rawModel, agyModel } = resolveProviderModels(active, params.model);
  const timeoutSeconds = params.timeoutSeconds || active.timeoutSeconds;
  const domain = params.domain.toLowerCase().replace(/^www\./, "");
  const baseUrl = params.baseUrl.startsWith("http") ? params.baseUrl : `https://${domain}`;

  // 1. Direct REST Provider execution
  const adapter = getProviderAdapter(providerId);
  if (adapter && active.isRest) {
    const prompt = `You are the Adversary Emulation Domain Harvester operating under the domain-resource-discovery-intel skill.
TARGET DOMAIN: ${domain}
BASE URL: ${baseUrl}
${UNTRUSTED_CONTENT_NOTICE}
CONTEXT / HTML EXCERPT:
${wrapUntrustedContent(params.htmlSnippet || "", 4500)}

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
          } catch {
            // Agent returned a malformed URL: skip this item.
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
    } catch (restErr: any) {
      logger.agent("FAILSAFE", `REST domain harvest failed (${restErr?.message}), cascading to AGY/anchor fallback`);
    }
  }

  // 2. Cascade to AGY CLI / anchor heuristic extractor
  if (params.allowSandboxFallback === false) {
    return { success: false, domain, baseUrl, resources: [], totalExtracted: 0, error: "AI sandbox unavailable" };
  }
  return discoverDomainResourcesWithAgent({
    domain: params.domain,
    baseUrl: params.baseUrl,
    htmlSnippet: params.htmlSnippet,
    model: agyModel,
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
  const { restModel: rawModel, agyModel } = resolveProviderModels(active, params.model);
  const timeoutSeconds = params.timeoutSeconds || active.timeoutSeconds;
  const textSnippet = params.text.slice(0, 4800);

  // 1. Direct REST Provider execution
  const adapter = getProviderAdapter(providerId);
  if (adapter && active.isRest) {
    const prompt = `You are the Senior Threat Intelligence Analysis & Adversary Emulation Evaluation Agent operating under the domain-resource-discovery-intel skill.
Analyze the following threat intelligence report snippet and determine whether it contains actionable adversary tradecraft, multi-stage attack chains, or emulation utility using a strict 5-dimensional scoring rubric.

${UNTRUSTED_CONTENT_NOTICE}
REPORT UNDER EVALUATION (title, URL and content snippet):
${wrapUntrustedContent(`TITLE: ${params.title || "Threat Report"}\nURL: ${params.url}\nCONTENT SNIPPET:\n${textSnippet}`)}

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

        let classification: ResourceClassification = "OTHER";
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
          const s = Math.min(Math.max(Number(parsed.passScore ?? 0), 0), 100);
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
        const recommendApproval = Boolean(parsed.recommendApproval && (passScore >= 50));

        const mitreTechniques: string[] = Array.isArray(parsed.mitreTechniques)
          ? parsed.mitreTechniques
              .map((t: any) => String(t).toUpperCase().trim())
              .filter((t: string) => /^T\d{4}(?:\.\d{3})?$/.test(t))
          : [];

        return {
          success: true,
          fallback: false,
          isRelevant: Boolean(parsed.isRelevant && (passScore >= 50)),
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
          tokensUsed: res.tokensUsed || res.tokens,
          providerId,
          providerName: active.providerName,
        };
      }
    } catch (restErr: any) {
      logger.agent("FAILSAFE", `REST evaluation failed (${restErr?.message}), cascading to AGY sandbox`);
    }
  }

  // 2. Cascade to AGY CLI in Docker Sandbox
  if (params.allowSandboxFallback === false) {
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
      rationale: "AI evaluation unavailable; heuristic qualification applies.",
      error: "AI provider did not answer and the sandbox agent is unavailable",
    };
  }
  return evaluateResourceWithAgent({
    url: params.url,
    domain: params.domain,
    title: params.title || "",
    text: params.text,
    model: agyModel,
    timeoutSeconds,
  });
}

export type UnifiedTranslationResult = DocumentTranslation & { provider: string; model: string };

/**
 * Translates a non-English report into English through the active provider (REST API, or the AGY
 * agent in its sandbox). Each part is checked (./translation checkTranslation); a failed part fails
 * the whole translation, and the caller holds the report instead of storing a doubtful text.
 */
export async function runUnifiedTranslation(params: {
  title: string;
  text: string;
  lang: string;
  model?: string;
  timeoutSeconds?: number;
  allowSandboxFallback?: boolean;
  /** Epoch ms by which the whole translation must be done; parts are not started after it. */
  deadlineAt?: number;
  /** True once the caller no longer wants the result (a cancelled crawl). */
  cancelled?: () => boolean;
}): Promise<UnifiedTranslationResult> {
  const active = await getActiveAIProvider();
  const { restModel, agyModel } = resolveProviderModels(active, params.model);
  // A part is up to 6,000 characters out: allow more time than a short evaluation, but never past
  // the deadline.
  const perCallMs = Math.max(params.timeoutSeconds || active.timeoutSeconds, 90) * 1000;
  const callTimeout = () => (params.deadlineAt ? Math.max(15_000, Math.min(perCallMs, params.deadlineAt - Date.now())) : perCallMs);
  const stopReason = () =>
    params.cancelled?.()
      ? "the crawl was cancelled"
      : params.deadlineAt && Date.now() > params.deadlineAt - 15_000
        ? "the translation needed more time than the crawl allows for one report"
        : null;
  const adapter = active.isRest && active.apiKey ? getProviderAdapter(active.providerId) : undefined;
  let usedSandbox = !adapter;

  const viaSandbox = async (prompt: string, system: string) => {
    if (params.allowSandboxFallback === false) return { success: false, text: "", error: "the AI provider did not answer and the sandbox agent is unavailable" };
    usedSandbox = true;
    const res = await backgroundAgentService.executePrompt(`${system}\n\n${prompt}`, { model: agyModel, timeoutMs: callTimeout() });
    return { success: res.success, text: res.text, error: res.error };
  };
  const call: ChunkTranslator = async (prompt, system) => {
    if (!adapter) return viaSandbox(prompt, system);
    const res = await adapter.generate({
      prompt,
      systemInstruction: system,
      model: restModel,
      apiKey: active.apiKey,
      endpointUrl: active.endpointUrl,
      timeoutMs: callTimeout(),
      temperature: 0,
      maxTokens: 8192,
    });
    if (res.success || params.allowSandboxFallback === false) return { success: res.success, text: res.text, error: res.error };
    logger.agent("FAILSAFE", `REST translation failed (${res.error ?? "no answer"}), trying the sandbox agent`);
    return viaSandbox(prompt, system);
  };

  const result = await translateDocument({ title: params.title, text: params.text, lang: params.lang }, call, { stopReason });
  return usedSandbox
    ? { ...result, provider: active.isRest ? "Antigravity Agent (AGY)" : active.providerName, model: agyModel }
    : { ...result, provider: active.providerName, model: restModel };
}

/**
 * Grounded AI analysis of one report (./report-ai-analysis) through the active provider: the REST
 * API when one is configured, otherwise (or when it fails) the AGY agent in its sandbox. Every item
 * of the answer is checked against the report text before it is returned. Throws when no provider
 * answers or the answer is not JSON, so the caller can report the failure and change nothing.
 */
export async function runUnifiedReportAnalysis(
  input: AnalysisPromptInput & {
    techniqueName: (id: string) => string | undefined;
    timeoutSeconds?: number;
    allowSandboxFallback?: boolean;
    signal?: AbortSignal;
  },
): Promise<ReportAiAnalysis> {
  const active = await getActiveAIProvider();
  const { restModel, agyModel } = resolveProviderModels(active);
  const timeoutMs = Math.max(input.timeoutSeconds || active.timeoutSeconds, 90) * 1000;
  const { prompt, truncated } = buildAnalysisPrompt(input, (t) => wrapUntrustedContent(t), UNTRUSTED_CONTENT_NOTICE);
  const adapter = active.isRest && active.apiKey ? getProviderAdapter(active.providerId) : undefined;

  let answer: { text: string; provider: string; model: string } | null = null;
  let lastError = "";
  if (adapter) {
    const res = await adapter.generate({
      prompt,
      systemInstruction: ANALYSIS_SYSTEM,
      model: restModel,
      apiKey: active.apiKey,
      endpointUrl: active.endpointUrl,
      timeoutMs,
      temperature: 0,
      maxTokens: 8192,
      responseFormat: "json",
      signal: input.signal,
    });
    if (res.success && res.text) answer = { text: res.text, provider: active.providerName, model: restModel };
    else {
      lastError = res.error || "the AI provider returned no answer";
      logger.agent("FAILSAFE", `REST report analysis failed (${lastError})${input.allowSandboxFallback === false ? "" : ", trying the sandbox agent"}`);
    }
  }
  if (!answer && input.allowSandboxFallback !== false && !input.signal?.aborted) {
    const res = await backgroundAgentService.executePrompt(`${ANALYSIS_SYSTEM}\n\n${prompt}`, { model: agyModel, timeoutMs, signal: input.signal });
    if (res.success && res.text) answer = { text: res.text, provider: active.isRest ? "Antigravity Agent (AGY)" : active.providerName, model: agyModel };
    else lastError = res.error || "the sandbox agent returned no answer";
  }
  if (!answer) throw new Error(`AI analysis failed: ${lastError || "no AI provider is available"}.`);

  let parsed: unknown;
  try {
    parsed = extractJsonFromLlmText(answer.text);
  } catch {
    throw new Error("AI analysis failed: the answer was not valid JSON.");
  }
  return groundReportAnalysis(parsed, input.text, {
    techniqueName: input.techniqueName,
    provider: answer.provider,
    model: answer.model,
    truncated,
  });
}

/**
 * Unified Conversational RAG Engine supporting both REST providers and AGY Sandbox
 */
export async function chatWithUnifiedAgent(params: UnifiedChatParams): Promise<UnifiedChatResult> {
  const active = await getActiveAIProvider();
  const providerId = params.providerId || active.providerId;
  const { restModel: rawModel, agyModel } = resolveProviderModels(active, params.model);
  const timeoutSeconds = params.timeoutSeconds || 40;

  // Grounded path: the caller built the whole prompt from cited passages.
  if (params.groundedPrompt) {
    const groundedSystem = `You are the platform's Cyber Threat Intelligence (CTI) Copilot.
- Never disclose, reference, or acknowledge underlying model names, runtime wrappers, CLI engines, or containers.
- Follow the grounding rules in the request exactly: answer only from the numbered passages, cite [S#] after every factual sentence, and state evidence gaps explicitly.
- When referencing MITRE ATT&CK techniques that appear in the passages, give the technique ID and name.`;
    const promptSha256 = await sha256Hex(`${groundedSystem}\n\n${params.groundedPrompt}`);
    const restAdapter = getProviderAdapter(providerId);
    if (restAdapter && active.isRest) {
      const res = await restAdapter.generate({
        prompt: params.groundedPrompt,
        systemInstruction: groundedSystem,
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
        promptSha256,
      };
    }
    const warm = await warmAgentService.executePrompt(`${groundedSystem}\n\n${params.groundedPrompt}`, {
      model: agyModel,
      timeoutMs: timeoutSeconds * 1000,
    });
    return {
      success: warm.success,
      reply: warm.text || warm.error || "Agent did not produce output.",
      model: warm.model,
      providerId: "agy_agent",
      latencyMs: warm.latencyMs,
      error: warm.error,
      tokens: warm.tokens,
      promptSha256,
    };
  }

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

  // Build previous turns from history to preserve conversational context
  let historyFormatted = "";
  if (params.history && params.history.length > 0) {
    historyFormatted = params.history
      .slice(-6)
      .map((h) => `${h.sender === "user" ? "Operator" : "CTI Analyst"}: ${h.text}`)
      .join("\n\n");
  }

  const systemInstruction = `You are the Lead Cyber Threat Intelligence (CTI) Copilot and Adversary Emulation Specialist for the Enterprise Threat Intelligence Platform.
Your mission is to provide rigorous, actionable analysis grounded in verified adversary tradecraft, MITRE ATT&CK techniques, intrusion timelines, malware reversing, and purple team emulation playbooks.

STRICT OPERATIONAL SECURITY & IDENTITY PROTOCOL:
- You are the platform's native CTI Threat Copilot / Analyst.
- NEVER disclose, reference, or acknowledge underlying model names, runtime wrappers, CLI engines, Docker containers, AGY, Google Deepmind, or Antigravity under any circumstances.
- Ground your analysis firmly in the verified platform intelligence reports provided below.
- Always provide structured, authoritative outputs using markdown headers, tables, bullet points, and code blocks for telemetry/command lines.
- When referencing MITRE ATT&CK techniques, provide both the technique ID and official name (e.g., T1059.001 - PowerShell).
${contextDocs ? `\n${UNTRUSTED_CONTENT_NOTICE}\nPLATFORM THREAT INTELLIGENCE (stored third-party reports):\n${wrapUntrustedContent(contextDocs)}` : ""}`;

  // 1. Direct REST Provider execution
  const adapter = getProviderAdapter(providerId);
  if (adapter && active.isRest) {
    const fullRestPrompt = historyFormatted
      ? `PRIOR CONVERSATION HISTORY:\n${historyFormatted}\n\nCURRENT INQUIRY:\n${params.userMessage}`
      : params.userMessage;

    const res = await adapter.generate({
      prompt: fullRestPrompt,
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

  // 2. Dedicated Autonomous Agent Engine via Warm Agent Skill Dispatch
  const warmRes = await warmAgentService.executeSkill({
    skill: "CTI_COPILOT",
    payload: params.userMessage,
    context: contextDocs || undefined,
    history: historyFormatted || undefined,
    model: agyModel,
    timeoutMs: timeoutSeconds * 1000,
  });

  return {
    success: warmRes.success,
    reply: warmRes.text || warmRes.error || "Agent did not produce output.",
    model: warmRes.model,
    providerId: "agy_agent",
    latencyMs: warmRes.latencyMs,
    error: warmRes.error,
    tokens: warmRes.tokens,
  };
}
