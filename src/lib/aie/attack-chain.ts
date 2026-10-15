import type { AttackStep, IntelAnalysis } from "./types";
import { getActiveAIProvider, extractJsonFromLlmText, resolveProviderModels } from "./ai-manager";
import { getProviderAdapter } from "./providers";
import { runAgentPromptInSandbox } from "./agent-sandbox";
import { UNTRUSTED_CONTENT_NOTICE, wrapUntrustedContent } from "./agent-framework/types";
import { warmAgentService } from "./warm-agent-service";
import { logger } from "./logger";
import { buildEvidence, isMitigationSentence, labelSentences, PROCEDURE_RE } from "./evidence";
import { lookupAttackTechnique } from "./mitre-matrix";

/** Collapse whitespace and cap length for display summaries. */
function clip(s: string, max: number): string {
  const t = s.replace(/\s+/g, " ").trim();
  return t.length <= max ? t : `${t.slice(0, max - 1).trimEnd()}…`;
}

const ADVERSARY_LABELS = new Set(["observed", "inferred"]);

/**
 * Detection / hunting / emulation ideas keyed on techniques the report actually
 * supports with observed/inferred evidence. These are starting points, not rules.
 */
const TECHNIQUE_GUIDANCE: Array<{ ids: string[]; detection: string; hunting: string; emulation: string }> = [
  {
    ids: ["T1059.001"],
    detection: "Detection idea (T1059.001): PowerShell process with encoded or hidden-window arguments (EventID 4688 / Sysmon 1)",
    hunting: "Hunting: Search for powershell.exe where CommandLine contains base64 patterns or DownloadString",
    emulation: "Atomic Test: powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \"Write-Host 'Emulated Execution'\"",
  },
  {
    ids: ["T1003.001"],
    detection: "Detection idea (T1003.001): LSASS memory access or dump creation (Sysmon EventID 10 / comsvcs MiniDump)",
    hunting: "Hunting: Audit process handles granted to lsass.exe from untrusted binary directories",
    emulation: "Atomic Test: rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump (LSASS PID) dump.dmp full",
  },
  {
    ids: ["T1003.003"],
    detection: "Detection idea (T1003.003): ntdsutil / shadow-copy access to NTDS.dit on domain controllers",
    hunting: "Hunting: Query for ntdsutil.exe \"ac i ntds\" \"ifm\" or vssadmin create shadow on domain controllers",
    emulation: "Atomic Test: ntdsutil.exe \"ac i ntds\" \"ifm\" \"create full C:\\Temp\\ntds_emulation\" q q (lab DC only)",
  },
  {
    ids: ["T1021.002", "T1021.001"],
    detection: "Detection idea (T1021): Lateral movement via SMB admin share, PSEXESVC service creation (EventID 7045) or RDP",
    hunting: "Hunting: Correlate EventID 4624 (Logon Type 3/10) followed by administrative file writes in ADMIN$ or C$",
    emulation: "Atomic Test: Invoke-Command -ComputerName (Target) -ScriptBlock { whoami /all }",
  },
  {
    ids: ["T1486", "T1490"],
    detection: "Detection idea (T1490): Shadow copy deletion via vssadmin, wmic or bcdedit tampering (EventID 4688)",
    hunting: "Hunting: Query for vssadmin.exe delete shadows /all /quiet or bcdedit /set recoveryenabled no",
    emulation: "Atomic Test: vssadmin.exe list shadows (safe verification test without destructive action)",
  },
  {
    ids: ["T1562.001"],
    detection: "Detection idea (T1562.001): Defender/EDR tampering such as Set-MpPreference -DisableRealtimeMonitoring",
    hunting: "Hunting: Search for Set-MpPreference or service stop events against security products",
    emulation: "Atomic Test: Get-MpPreference | Select DisableRealtimeMonitoring (read-only verification)",
  },
  {
    ids: ["T1070.001"],
    detection: "Detection idea (T1070.001): Event log cleared (Security EventID 1102 / System EventID 104)",
    hunting: "Hunting: Search for wevtutil cl or Clear-EventLog command lines",
    emulation: "Atomic Test: wevtutil.exe cl Application (lab host only)",
  },
];

export function analyzeThreatIntelligence(text: string, title: string, classification: string): IntelAnalysis {
  const evidence = buildEvidence(text, { title, lookup: lookupAttackTechnique });

  const adversaryTechniques = evidence.techniques.filter((t) => ADVERSARY_LABELS.has(t.label));
  const ttps = adversaryTechniques.map((t) => `${t.id} - ${t.name}`);
  const threatActors = evidence.actors.filter((a) => ADVERSARY_LABELS.has(a.label)).map((a) => a.value);
  const malware = evidence.malware.filter((m) => ADVERSARY_LABELS.has(m.label)).map((m) => m.value);
  const vulnerabilities = Array.from(
    new Set((`${title}\n${text}`.match(/\bCVE-\d{4}-\d{4,7}\b/gi) ?? []).map((c) => c.toUpperCase())),
  );

  const techName = new Map(evidence.techniques.map((t) => [t.id, t.name]));
  const attackChain: AttackStep[] = evidence.chain.steps.map((step) => ({
    order: step.order,
    tactic: step.tactic,
    techniques: step.techniques.map((id) => `${id} - ${techName.get(id) ?? id}`),
    // The report's own words for this step; never canned text.
    summary: step.evidence[0] ? clip(step.evidence[0].quote, 240) : "",
  }));

  // IOAs: the behaviour the report describes, quoted, per supported technique.
  const ioas = adversaryTechniques.slice(0, 12).map((t) => `${t.id} ${t.name}: "${clip(t.evidence[0]?.quote ?? "", 160)}"`);

  const supported = new Set(adversaryTechniques.map((t) => t.id));
  const detections: string[] = [];
  const hunting: string[] = [];
  const emulation: string[] = [];
  for (const g of TECHNIQUE_GUIDANCE) {
    if (!g.ids.some((id) => supported.has(id))) continue;
    detections.push(g.detection);
    hunting.push(g.hunting);
    emulation.push(g.emulation);
  }

  return {
    method: "heuristic",
    classification,
    threatActors,
    malware,
    vulnerabilities,
    ttps,
    ioas,
    attackChain,
    detections,
    hunting,
    emulation,
    evidence,
  };
}

export function extractStructuredEntities(
  text: string,
  title: string,
  classification: string,
  analysis: IntelAnalysis,
): import("./types").ExtractedEntities {
  const sentences = labelSentences(text);

  // Procedures only from sentences that report adversary activity.
  const procedures: string[] = [];
  for (const s of sentences) {
    if (s.label !== "observed") continue;
    for (const m of s.text.match(new RegExp(PROCEDURE_RE.source, "gi")) ?? []) {
      const p = m.trim().replace(/^[`'"]+|[`'"]+$/g, "");
      if (p.length > 8 && !p.includes("<") && !p.includes(">") && !procedures.includes(p)) procedures.push(p);
    }
    if (procedures.length >= 15) break;
  }

  // Mitigations only from defender-advice sentences (never adversary actions or rule syntax).
  const mitigations: string[] = [];
  for (const s of sentences) {
    if (!isMitigationSentence(s)) continue;
    const t = s.text.replace(/\s+/g, " ").trim();
    if (!mitigations.includes(t)) mitigations.push(t);
    if (mitigations.length >= 6) break;
  }

  const evidence = analysis.evidence;
  const techniques = evidence
    ? evidence.techniques
        .filter((t) => ADVERSARY_LABELS.has(t.label))
        .map((t) => ({ id: t.id, name: t.name, tactic: t.tactic }))
    : analysis.attackChain.flatMap((s) =>
        s.techniques.map((t) => {
          const m = /^(T\d{4}(?:\.\d{3})?)\s*(?:[-:]\s*(.*))?$/.exec(String(t).trim());
          return { id: m?.[1] ?? String(t), name: m?.[2] || m?.[1] || String(t), tactic: s.tactic };
        }),
      );
  const tactics = analysis.attackChain.map((s) => s.tactic);

  // Detection *ideas* and hunting leads, not authored rules.
  const detectionRules = [...analysis.detections, ...analysis.hunting].map((d) => ({
    type: "hunting" as const,
    title: d.replace(/^(?:Sigma|Hunting|Detection idea(?: \([^)]*\))?):\s*/i, ""),
    query: d,
  }));

  const campaignMatch = title.match(/(?:Campaign\s+[A-Z0-9_-]+|Operation\s+[A-Z0-9_-]+|\b(?:202[3-6]|Q[1-4])\s+[A-Z0-9_-]+\s+Campaign)/i);
  const campaign = campaignMatch ? campaignMatch[0] : null;

  return {
    threatActors: analysis.threatActors,
    malwareFamilies: analysis.malware,
    cves: analysis.vulnerabilities,
    tactics,
    techniques,
    procedures,
    detectionRules,
    mitigations,
    campaign,
  };
}

/**
 * AI-Powered Attack Chain Re-synthesizer
 *
 * Employs the active AI provider (Gemini REST, Claude REST, OpenAI, or AGY Sandbox)
 * to perform deep chronological kill-chain reconstruction, extraction of concrete command lines,
 * generation of production-ready Sigma YAML detection rules, and Atomic Red Team test plans.
 *
 * Guarantees zero-SPOF: if AI times out or errors, automatically falls back to heuristic analysis.
 */
export async function synthesizeThreatIntelligenceWithAI(
  text: string,
  title: string,
  classification: string = "THREAT_REPORT",
  options?: { model?: string; timeoutSeconds?: number; providerId?: string }
): Promise<IntelAnalysis> {
  const heuristicFallback = analyzeThreatIntelligence(text, title, classification);
  const active = await getActiveAIProvider();
  const providerId = options?.providerId || active.providerId;
  const { restModel: rawModel, agyModel } = resolveProviderModels(active, options?.model);
  const timeoutSeconds = options?.timeoutSeconds || active.timeoutSeconds;
  const snippet = text.slice(0, 4800);

  const prompt = `You are the Lead Adversary Emulation & CTI Reconstruction Specialist operating under the AIE platform.
Analyze this threat intelligence report and synthesize a high-fidelity, chronological multi-stage attack chain with concrete procedures, MITRE ATT&CK techniques, detection rules, and purple team emulation commands.

${UNTRUSTED_CONTENT_NOTICE}
REPORT (title and content snippet):
${wrapUntrustedContent(`TITLE: ${title}\nCONTENT SNIPPET:\n${snippet}`)}

INSTRUCTIONS:
1. Reconstruct the CHRONOLOGICAL ATTACK CHAIN in sequential order (Stage 1 to N, e.g. Initial Access -> Execution -> Persistence -> Lateral Movement -> Impact).
2. For each stage, identify the exact MITRE ATT&CK tactic, technique IDs (e.g. T1059.001), and a technical summary.
3. Identify threat actors, malware families, CVEs, concrete procedures/commands, IOAs (Indicators of Attack), detection rules (Sigma/hunting), and emulation actions.

OUTPUT FORMAT:
Return pure valid JSON with this exact structure:
{
  "classification": "${classification}",
  "threatActors": ["Threat Actor Name"],
  "malware": ["Malware or Tool Name"],
  "vulnerabilities": ["CVE-YYYY-XXXXX"],
  "ttps": ["T1190: Exploit Public-Facing Application", "T1059.001: PowerShell"],
  "ioas": ["High-entropy process spawned from w3wp.exe"],
  "attackChain": [
    {
      "order": 1,
      "tactic": "Initial Access",
      "techniques": ["T1190"],
      "summary": "Weaponization of CVE-2023-46805 in perimeter gateway"
    },
    {
      "order": 2,
      "tactic": "Execution",
      "techniques": ["T1059.001"],
      "summary": "Execution of obfuscated base64 PowerShell downloader scriptlet"
    }
  ],
  "detections": [
    "Sigma: Suspicious PowerShell execution with encoded command arguments",
    "Hunting: Query for outbound C2 beacons to unclassified IP addresses"
  ],
  "hunting": [
    "Hunting: Inspect process handles granted to lsass.exe by non-system accounts"
  ],
  "emulation": [
    "Atomic Test: powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \\"Write-Host 'Emulated Execution'\\""
  ]
}
Return pure JSON only.`;

  try {
    const adapter = getProviderAdapter(providerId);
    let outputText = "";

    if (adapter && active.isRest) {
      const res = await adapter.generate({
        prompt,
        model: rawModel,
        apiKey: active.apiKey,
        timeoutMs: timeoutSeconds * 1000,
        responseFormat: "json",
      });
      if (res.success && res.text) {
        outputText = res.text;
      }
    } else {
      try {
        const warmRes = await warmAgentService.executeSkill({
          skill: "ATTACK_CHAIN",
          payload: `TITLE: ${title}\nCONTENT SNIPPET:\n${snippet}`,
          model: agyModel,
          timeoutMs: timeoutSeconds * 1000,
        });
        if (warmRes.success && warmRes.text) {
          outputText = warmRes.text;
        }
      } catch {
        // fall through to the sandbox / fallback path
      }

      if (!outputText) {
        const res = await runAgentPromptInSandbox(prompt, {
          model: agyModel,
          timeoutMs: timeoutSeconds * 1000,
          category: "agent",
        });
        if (res.success && res.text) {
          outputText = res.text;
        }
      }
    }

    if (outputText) {
      const parsed = extractJsonFromLlmText(outputText);
      if (parsed && Array.isArray(parsed.attackChain) && parsed.attackChain.length > 0) {
        const orderSteps: AttackStep[] = parsed.attackChain.map((s: any, idx: number) => ({
          order: typeof s.order === "number" ? s.order : idx + 1,
          tactic: String(s.tactic || "Unknown"),
          techniques: Array.isArray(s.techniques) ? s.techniques.map(String) : [],
          summary: String(s.summary || ""),
        }));

        logger.agent(
          "SYNTHESIS",
          `AI synthesized attack chain for "${title.slice(0, 40)}" (${orderSteps.length} stages via ${active.isRest ? rawModel : agyModel})`
        );

        // Take each list from the model when it returned one; otherwise fall back to the
        // heuristic and record that, so the result is never labelled purely "llm".
        const LIST_FIELDS = ["threatActors", "malware", "vulnerabilities", "ttps", "ioas", "detections", "hunting", "emulation"] as const;
        const fieldOrigins: NonNullable<IntelAnalysis["fieldOrigins"]> = {};
        const lists = {} as Record<(typeof LIST_FIELDS)[number], string[]>;
        for (const field of LIST_FIELDS) {
          const fromModel = parsed[field];
          if (Array.isArray(fromModel) && fromModel.length > 0) {
            lists[field] = fromModel.map(String);
            fieldOrigins[field] = "llm";
          } else {
            lists[field] = heuristicFallback[field];
            fieldOrigins[field] = "heuristic";
          }
        }
        const usedHeuristic = Object.values(fieldOrigins).includes("heuristic");

        return {
          method: usedHeuristic ? "mixed" : "llm",
          fieldOrigins,
          classification: parsed.classification || heuristicFallback.classification,
          ...lists,
          attackChain: orderSteps,
          // Fact-level evidence always comes from the deterministic analyzer.
          evidence: heuristicFallback.evidence,
        };
      }
    }
  } catch (err: any) {
    logger.agent("FAILSAFE", `AI attack chain synthesis failed (${err.message}), returned heuristic analysis.`);
  }

  return heuristicFallback;
}

/**
 * Generates a production-ready Sigma YAML detection rule for observed adversary procedures
 */
export async function generateSigmaRuleWithAI(params: {
  title: string;
  techniques: string[];
  procedures?: string[];
  textSnippet?: string;
  model?: string;
}): Promise<{ success: boolean; sigmaYaml: string; title: string; level: string; error?: string }> {
  const active = await getActiveAIProvider();
  const { restModel: rawModel, agyModel } = resolveProviderModels(active, params.model);
  const prompt = `You are a Lead Detection Engineer.
Generate a valid, production-ready Sigma detection rule in standard Sigma YAML format based on the following threat intelligence report and adversary techniques.

${UNTRUSTED_CONTENT_NOTICE}
${wrapUntrustedContent(
  `TITLE: ${params.title}\nTECHNIQUES: ${params.techniques.join(", ")}\nOBSERVED PROCEDURES: ${(params.procedures || []).join("\n")}\nCONTEXT: ${(params.textSnippet || "").slice(0, 2000)}`
)}

INSTRUCTIONS:
1. Output MUST be valid Sigma YAML (logsource: category: process_creation, detection, condition, tags, level: high/critical).
2. Include concrete command-line substrings or process image matches matching the observed tradecraft.
3. Return pure JSON with:
{
  "title": "Rule Title",
  "level": "high",
  "sigmaYaml": "title: ...\\nlogsource: ...\\ndetection: ...\\ncondition: ...\\nlevel: high"
}
Return pure JSON only.`;

  try {
    const adapter = getProviderAdapter(active.providerId);
    let output = "";
    if (adapter && active.isRest) {
      const res = await adapter.generate({
        prompt,
        model: rawModel,
        apiKey: active.apiKey,
        responseFormat: "json",
      });
      if (res.success) output = res.text;
    } else {
      try {
        const warmRes = await warmAgentService.executePrompt(prompt, {
          model: agyModel,
          timeoutMs: 35000,
        });
        if (warmRes.success && warmRes.text) {
          output = warmRes.text;
        }
      } catch {
        // fall through to the sandbox / fallback path
      }

      if (!output) {
        const res = await runAgentPromptInSandbox(prompt, {
          model: agyModel,
          timeoutMs: 35000,
          category: "agent",
        });
        if (res.success) output = res.text;
      }
    }

    if (output) {
      const parsed = extractJsonFromLlmText(output);
      return {
        success: true,
        sigmaYaml: parsed.sigmaYaml || output,
        title: parsed.title || `Detection for ${params.title}`,
        level: parsed.level || "high",
      };
    }
  } catch (err: any) {
    return {
      success: false,
      sigmaYaml: "",
      title: params.title,
      level: "medium",
      error: err.message,
    };
  }

  return {
    success: false,
    sigmaYaml: "",
    title: params.title,
    level: "medium",
    error: "Model did not return Sigma rule output.",
  };
}

/**
 * Generates an Atomic Red Team adversary emulation blueprint with concrete execution commands
 */
export async function generateEmulationPlanWithAI(params: {
  title: string;
  techniques: string[];
  procedures?: string[];
  platform?: "windows" | "linux" | "macos";
  model?: string;
}): Promise<{ success: boolean; testName: string; executor: string; command: string; cleanupCommand?: string; description: string }> {
  const active = await getActiveAIProvider();
  const { restModel: rawModel, agyModel } = resolveProviderModels(active, params.model);
  const platform = params.platform || "windows";

  const prompt = `You are a Red Team / Adversary Emulation Specialist.
Generate a safe, executable Atomic Red Team style emulation test procedure targeting the adversary TTPs described below.

PLATFORM: ${platform}
${UNTRUSTED_CONTENT_NOTICE}
${wrapUntrustedContent(
  `TITLE: ${params.title}\nTECHNIQUES: ${params.techniques.join(", ")}\nPROCEDURES: ${(params.procedures || []).join("\n")}`
)}

INSTRUCTIONS:
1. Provide a non-destructive emulation command line that exercises the telemetry detection opportunity without harming systems.
2. Provide executor ("powershell" or "bash" or "sh").
3. Provide cleanup command if artifacts are created.
4. Return pure JSON:
{
  "testName": "Emulate T1059.001 Execution",
  "executor": "powershell",
  "command": "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \\"Write-Host 'Emulated adversary telemetry execution'\\"",
  "cleanupCommand": "",
  "description": "Validates EDR and Sysmon EventID 1 process creation logging for high-entropy arguments."
}
Return pure JSON only.`;

  try {
    const adapter = getProviderAdapter(active.providerId);
    let output = "";
    if (adapter && active.isRest) {
      const res = await adapter.generate({
        prompt,
        model: rawModel,
        apiKey: active.apiKey,
        responseFormat: "json",
      });
      if (res.success) output = res.text;
    } else {
      try {
        const warmRes = await warmAgentService.executePrompt(prompt, {
          model: agyModel,
          timeoutMs: 35000,
        });
        if (warmRes.success && warmRes.text) {
          output = warmRes.text;
        }
      } catch {
        // fall through to the sandbox / fallback path
      }

      if (!output) {
        const res = await runAgentPromptInSandbox(prompt, {
          model: agyModel,
          timeoutMs: 35000,
          category: "agent",
        });
        if (res.success) output = res.text;
      }
    }

    if (output) {
      const parsed = extractJsonFromLlmText(output);
      return {
        success: true,
        testName: parsed.testName || `Emulation of ${params.techniques[0] || params.title}`,
        executor: parsed.executor || (platform === "windows" ? "powershell" : "bash"),
        command: parsed.command || `echo "Emulating ${params.techniques[0]}"`,
        cleanupCommand: parsed.cleanupCommand || "",
        description: parsed.description || "Adversary emulation procedure generated by AI specialist.",
      };
    }
  } catch {
    // fall through to the default fallback below
  }

  return {
    success: false,
    testName: `Emulation of ${params.techniques[0] || "TTP"}`,
    executor: platform === "windows" ? "powershell" : "bash",
    command: `echo "Emulating ${params.techniques[0] || "TTP"}"`,
    description: "Default fallback emulation placeholder.",
  };
}

