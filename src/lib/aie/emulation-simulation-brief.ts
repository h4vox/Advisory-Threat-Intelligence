/**
 * Emulation & simulation brief: a report retold the way emulation / simulation-focused analysts
 * share research —
 *
 *   [THREAT CAMPAIGN] DCRat Deployment: Obfuscated VBS + Payloads Appended to PNGs
 *   ℹ️ What the research found (two or three sentences).
 *   📍 INFECTION CHAIN
 *   • PowerShell downloads IconEdit2Turb.msi through a decimal-IP URL.
 *   • msiexec.exe installs it silently using /qn and /norestart.
 *   …
 *   🆕 What is new …
 *   🛡️ VALIDATE: event IDs, log sources, detections and C2 behaviour a simulation should trigger
 *   📌 Source: Forescout
 *   🔗 https://www.forescout[.]com/blog/romulus-…
 *
 * Built only from the report: the steps are sentences quoted from the text (the AI's verified steps
 * when the report was analysed, otherwise the procedure steps ./emulation-simulation found), the summary
 * is the grounded AI summary or the report's own opening. Nothing is written that the report does
 * not say. The link is defanged, as in shared intel posts.
 *
 * Pure module so it runs under `node --test` and in the browser.
 */
import type { EmulationSimulationGrade, EmulationSimulationSummary } from "./emulation-simulation.ts";
import type { ReportAiAnalysis } from "./report-ai-analysis.ts";

export type BriefCategory =
  | "THREAT CAMPAIGN"
  | "MALWARE ANALYSIS"
  | "THREAT TTPs"
  | "ATTACK INFRASTRUCTURE"
  | "INCIDENT ANALYSIS"
  | "VULNERABILITY EXPLOITATION"
  | "THREAT REPORT";

export type EmulationSimulationBrief = {
  category: BriefCategory;
  title: string;
  about: string[];
  chainHeading: string;
  steps: string[];
  /** Where the steps come from. */
  stepsFrom: "ai" | "rules" | "none";
  novel: string[];
  /** Telemetry, detections and C2 behaviour to validate a simulation against (quoted). */
  validate: string[];
  source: string;
  link: string;
  grade: EmulationSimulationGrade | null;
  /** The brief as plain text, ready to copy. */
  text: string;
};

export type BriefInput = {
  title: string;
  url: string;
  publisher?: string | null;
  docTypes?: readonly string[];
  classification?: string | null;
  extractedText?: string | null;
  emulationSimulation?: EmulationSimulationSummary | null;
  aiAnalysis?: Pick<ReportAiAnalysis, "summary" | "emulationSimulation"> | null;
};

/** Defangs a URL the way shared intel does (https://host[.]tld/path). */
export function defangUrl(url: string): string {
  try {
    const u = new URL(url);
    const host = u.hostname.replace(/\.(?=[^.]+$)/, "[.]");
    return `${u.protocol}//${host}${u.pathname}${u.search}`;
  } catch {
    return url.replace(/\.(?=[a-z]{2,}(?:\/|$))/i, "[.]");
  }
}

function categoryOf(input: BriefInput, steps: number): BriefCategory {
  const types = new Set(input.docTypes ?? []);
  const cls = (input.classification ?? "").toUpperCase();
  const t = `${input.title}`.toLowerCase();
  if (types.has("INCIDENT_REPORT") || types.has("DFIR_REPORT") || /INTRUSION/.test(cls) || /\b(?:incident|intrusion|dfir|case study)\b/.test(t)) return "INCIDENT ANALYSIS";
  if (/\b(?:infrastructure|botnet|proxy network|orb network|delivery platform|panel|c2 servers?)\b/.test(t)) return "ATTACK INFRASTRUCTURE";
  if (types.has("VULNERABILITY_ADVISORY") || /VULNERABILITY/.test(cls) || /\b(?:cve-\d{4}|zero-day|0-day|exploit(?:ed|ation)?)\b/.test(t)) return "VULNERABILITY EXPLOITATION";
  if (types.has("CAMPAIGN_REPORT") || /CAMPAIGN/.test(cls) || /\bcampaign\b/.test(t)) return "THREAT CAMPAIGN";
  if (types.has("MALWARE_REPORT") || /MALWARE/.test(cls) || /\b(?:malware|backdoor|loader|stealer|rat|ransomware|implant)\b/.test(t)) return "MALWARE ANALYSIS";
  if (steps > 0 || /\b(?:technique|ttps?|tradecraft|abus(?:e|es|ing))\b/.test(t)) return "THREAT TTPs";
  return "THREAT REPORT";
}

/** The report's own opening sentences, when there is no AI summary. */
function opening(text: string, max = 2): string[] {
  const out: string[] = [];
  for (const line of text.split("\n")) {
    const l = line.trim();
    if (l.length < 60 || /^(?:by |posted |published |share|table of contents|figure \d)/i.test(l)) continue;
    for (const s of l.split(/(?<=[.!?])\s+(?=[A-Z])/)) {
      if (s.length >= 50 && s.length <= 400) out.push(s.trim());
      if (out.length >= max) return out;
    }
  }
  return out;
}

function sentences(text: string, max: number): string[] {
  return text
    .split(/(?<=[.!?])\s+(?=[A-Z])/)
    .map((s) => s.trim())
    .filter(Boolean)
    .slice(0, max);
}

export function buildEmulationSimulationBrief(input: BriefInput): EmulationSimulationBrief {
  const ai = input.aiAnalysis ?? null;
  const aiSteps = ai?.emulationSimulation?.steps ?? [];
  const ruleSteps = input.emulationSimulation?.steps ?? [];
  const stepsFrom: EmulationSimulationBrief["stepsFrom"] = aiSteps.length >= 2 ? "ai" : ruleSteps.length ? "rules" : aiSteps.length ? "ai" : "none";
  const steps = (stepsFrom === "ai" ? aiSteps.map((s) => s.quote) : ruleSteps).slice(0, 12);
  const novel = [...new Set([...(ai?.emulationSimulation?.novel ?? []).map((n) => n.quote), ...(input.emulationSimulation?.novelty ?? [])])].slice(0, 3);
  const validate = [...new Set([...(ai?.emulationSimulation?.detections ?? []).map((d) => d.quote), ...(input.emulationSimulation?.validate ?? [])])].slice(0, 6);
  const about = ai?.summary ? sentences(ai.summary, 3) : opening(input.extractedText ?? "");
  const category = categoryOf(input, steps.length);
  const source = (input.publisher ?? "").trim() || (() => {
    try {
      return new URL(input.url).hostname.replace(/^www\./, "");
    } catch {
      return "";
    }
  })();
  const link = defangUrl(input.url);
  const chainHeading = category === "INCIDENT ANALYSIS" ? "INTRUSION CHAIN" : category === "THREAT TTPs" ? "PROCEDURE" : "INFECTION CHAIN";
  const grade = input.emulationSimulation ? (input.emulationSimulation.ai?.grade ?? input.emulationSimulation.grade) : (ai?.emulationSimulation?.grade ?? null);

  const lines = [`[${category}] ${input.title.trim()}`, ""];
  for (const a of about) lines.push(`ℹ️ ${a}`, "");
  if (steps.length) {
    lines.push(`📍 ${chainHeading}`, "");
    for (const s of steps) lines.push(`• ${s}`);
    lines.push("");
  }
  if (novel.length) {
    lines.push("🆕 WHAT IS NEW", "");
    for (const n of novel) lines.push(`• ${n}`);
    lines.push("");
  }
  if (validate.length) {
    lines.push("🛡️ VALIDATE (what defenders should see when it is simulated)", "");
    for (const v of validate) lines.push(`• ${v}`);
    lines.push("");
  }
  if (source) lines.push(`📌 Source: ${source}`);
  lines.push(`🔗 ${link}`);

  return { category, title: input.title.trim(), about, chainHeading, steps, stepsFrom, novel, validate, source, link, grade, text: lines.join("\n") };
}
