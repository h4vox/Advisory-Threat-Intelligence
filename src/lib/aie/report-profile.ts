/**
 * One report's adversary & attack profile, as every view should show it: who, with what, how
 * (attack chain), which vulnerabilities and which indicators.
 *
 * Sources, best first:
 *   1. the grounded AI analysis (./report-ai-analysis: every step carries a verified quote, every
 *      name appears in the report);
 *   2. the evidence-backed analysis facts labelled observed or inferred;
 *   3. the older analysis lists.
 * Whatever the source, a name, CVE or indicator is kept only when the report text contains it
 * (defanged forms included), so nothing from outside the document — ATT&CK aliases, a model's
 * guess — is presented as part of it. ATT&CK techniques and CVEs are their own sections, never
 * "indicators of compromise". Pure; unit-tested.
 */
import type { IntelAnalysis, IocHit } from "./types.ts";
import type { ReportAiAnalysis } from "./report-ai-analysis.ts";

export type ProfileStep = { order: number; tactic: string; techniques: string[]; summary: string; quote?: string };

export type ReportProfile = {
  /** Where the actors, malware and chain came from. */
  source: "ai" | "evidence" | "analysis" | "none";
  actors: string[];
  malware: string[];
  tools: string[];
  chain: ProfileStep[];
  /** True when every chain step carries a quote from the report. */
  chainQuoted: boolean;
  vulnerabilities: string[];
  /** Network and file indicators only (no techniques, no CVEs). */
  indicators: Array<{ kind: string; value: string; role?: string }>;
  /** Names the sources listed that the report text does not contain (dropped). */
  dropped: string[];
};

const ACTIVITY = new Set(["observed", "inferred"]);
const NOT_INDICATORS = new Set(["technique", "cve"]);

/** Lower-cased text with defanging undone ("hxxp", "[.]", "(dot)"), for containment checks. */
export function normalizeForMatch(s: string): string {
  return s
    .toLowerCase()
    .replace(/hxxp/g, "http")
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/g, ".")
    .replace(/\[:\]/g, ":")
    .replace(/\s+/g, " ");
}

function makeInText(text: string) {
  const hay = normalizeForMatch(text);
  return (value: string) => {
    const v = normalizeForMatch(value).trim();
    if (v.length < 2) return false;
    // Whole-word match for short names ("APT1" must not match inside "APT10").
    if (v.length <= 6) return new RegExp(`(?:^|[^a-z0-9])${v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?:$|[^a-z0-9])`).test(hay);
    return hay.includes(v);
  };
}

function uniq(list: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of list) {
    const v = raw.replace(/\s+/g, " ").trim();
    const k = v.toLowerCase();
    if (!v || seen.has(k)) continue;
    seen.add(k);
    out.push(v);
  }
  return out;
}

export function reportProfile(input: { extractedText?: string | null; analysis?: IntelAnalysis | null; aiAnalysis?: ReportAiAnalysis | null; iocs?: IocHit[] | null }): ReportProfile {
  const text = input.extractedText ?? "";
  const inText = makeInText(text);
  const hasText = text.trim().length > 0;
  const keep = (list: string[], dropped: string[]) =>
    uniq(list).filter((v) => {
      if (!hasText || inText(v)) return true;
      dropped.push(v);
      return false;
    });

  const a = input.analysis ?? null;
  const ev = a?.evidence;
  const ai = input.aiAnalysis ?? null;
  const dropped: string[] = [];

  // Who and with what: every source contributes, the text decides.
  const adv = ai?.adversary;
  const actors = keep(
    [
      ...(adv ? [adv.name, ...adv.aliases] : []),
      ...(ev?.actors ?? []).filter((f) => ACTIVITY.has(f.label)).map((f) => f.value),
      ...(a?.threatActors ?? []),
    ],
    dropped,
  );
  const tools = keep(adv?.tools ?? [], dropped);
  const toolSet = new Set(tools.map((t) => t.toLowerCase()));
  const malware = keep([...(adv?.malware ?? []), ...(ev?.malware ?? []).filter((f) => ACTIVITY.has(f.label)).map((f) => f.value), ...(a?.malware ?? [])], dropped).filter(
    (m) => !toolSet.has(m.toLowerCase()),
  );

  // How: the AI chain carries verified quotes; otherwise the analysis chain, limited to techniques
  // the evidence supports when evidence exists.
  let chain: ProfileStep[] = [];
  let source: ReportProfile["source"] = "none";
  if (ai?.attackChain?.length) {
    source = "ai";
    chain = ai.attackChain.map((s, i) => ({
      order: i + 1,
      tactic: s.stage,
      techniques: s.technique ? [`${s.technique.id} - ${s.technique.name}`] : [],
      summary: s.summary,
      quote: s.quote || undefined,
    }));
  } else if (a?.attackChain?.length) {
    source = ev ? "evidence" : "analysis";
    const supported = ev ? new Set(ev.techniques.filter((t) => ACTIVITY.has(t.label)).map((t) => t.id.toUpperCase())) : null;
    chain = a.attackChain
      .map((s) => ({
        order: s.order,
        tactic: s.tactic,
        techniques: s.techniques.filter((t) => !supported || supported.has((t.match(/T\d{4}(?:\.\d{3})?/i)?.[0] ?? "").toUpperCase())),
        summary: s.summary,
      }))
      .filter((s) => s.techniques.length || !supported)
      .map((s, i) => ({ ...s, order: i + 1 }));
  }
  if (source === "none" && (actors.length || malware.length)) source = adv ? "ai" : ev ? "evidence" : "analysis";

  // Vulnerabilities: CVE IDs any source names that the report contains.
  const cves = [
    ...(input.iocs ?? []).filter((i) => i.kind === "cve").map((i) => i.value),
    ...(a?.vulnerabilities ?? []).flatMap((v) => v.match(/CVE-\d{4}-\d{4,7}/gi) ?? []),
    ...(ai?.iocs ?? []).filter((i) => i.type === "cve").map((i) => i.value),
  ].map((c) => c.toUpperCase());
  const vulnerabilities = keep(cves, dropped);

  // Indicators: network and file indicators found in the text (the extractor's, then the AI's).
  const indicators: ReportProfile["indicators"] = [];
  const seen = new Set<string>();
  for (const i of input.iocs ?? []) {
    if (NOT_INDICATORS.has(i.kind)) continue;
    const key = `${i.kind}:${i.value.toLowerCase()}`;
    if (seen.has(key)) continue;
    if (hasText && !inText(i.value) && !(i.original && inText(i.original))) {
      dropped.push(i.value);
      continue;
    }
    seen.add(key);
    indicators.push({ kind: i.kind, value: i.value, ...(i.role ? { role: i.role } : {}) });
  }
  for (const i of ai?.iocs ?? []) {
    if (i.type === "cve") continue;
    const key = `${i.type}:${i.value.toLowerCase()}`;
    if (seen.has(key) || (hasText && !inText(i.value))) continue;
    seen.add(key);
    indicators.push({ kind: i.type, value: i.value, ...(i.context ? { role: i.context } : {}) });
  }

  return { source, actors, malware, tools, chain, chainQuoted: chain.length > 0 && chain.every((s) => s.quote), vulnerabilities, indicators, dropped: uniq(dropped) };
}
