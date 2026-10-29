/**
 * Relevance pre-scoring BEFORE the full fetch (AIE Web Extraction spec §16–17).
 *
 * Scores a frontier candidate from what the listing already tells us (title, feed summary, URL)
 * plus the source's history, so the crawler spends fetches on adversary-behaviour intelligence
 * and skips webinars, product launches, hiring posts and other junk with a recorded reason.
 *
 * Positive: ATT&CK groups / software / campaigns (bundled knowledge, findEntitiesInText), CVE and
 * technique IDs, actor naming schemes (UNC####, DEV-####, Storm-####, TA###, APT##, FIN##,
 * weather / animal cryptonyms), intrusion vocabulary.
 * Negative: webinar, podcast, award, hiring, product launch, partnership, earnings, event recap,
 * marketing.
 * Context: per-source historical acceptance rate, source tier.
 *
 * SERVER ONLY (imports the ATT&CK knowledge index).
 */
import { findEntitiesInText } from "../attack-knowledge.ts";

export type RelevanceSignal = { polarity: "positive" | "negative" | "context"; label: string; weight: number; evidence?: string };

export type RelevanceInput = {
  title?: string | null;
  summary?: string | null;
  url?: string | null;
  /** Historical decisions for the source the candidate came from. */
  sourceHistory?: { accepted: number; rejected: number } | null;
  sourceTier?: 1 | 2 | 3 | 4 | null;
};

export type RelevanceResult = {
  score: number;
  decision: "fetch" | "skip";
  /** Hard evidence of adversary content (entity, CVE, technique or actor naming scheme). */
  strongPositive: boolean;
  signals: RelevanceSignal[];
  /** One line for the crawl job log. */
  reason: string;
};

export const RELEVANCE_SKIP_THRESHOLD = 0.3;
const BASE = 0.35;

const ACTOR_SCHEMES: Array<{ re: RegExp; label: string }> = [
  { re: /\bUNC\d{3,5}\b/, label: "Mandiant UNC cluster" },
  { re: /\b(?:DEV|Storm)-\d{3,4}\b/i, label: "Microsoft DEV/Storm cluster" },
  { re: /\bTA\d{3,4}\b/, label: "Proofpoint TA cluster" },
  { re: /\bAPT[- ]?\d{1,3}\b/, label: "APT designation" },
  { re: /\bFIN\d{1,2}\b/, label: "FIN designation" },
  { re: /\b(?:UAC|UAT|TAG|CL-(?:STA|CRI|UNK))-?\d{2,5}\b/, label: "tracked cluster" },
  {
    re: /\b[A-Z][a-z]+ (?:Typhoon|Blizzard|Sandstorm|Sleet|Tempest|Hail|Rain|Flood|Cyclone|Tsunami|Dust|Lightning)\b/,
    label: "Microsoft weather cryptonym",
  },
  { re: /\b[A-Z][a-z]+ (?:Panda|Bear|Kitten|Chollima|Spider|Jackal|Buffalo|Leopard|Tiger|Ocelot)\b/, label: "CrowdStrike cryptonym" },
];

const INTRUSION_TERMS: Array<[RegExp, string]> = [
  [/\binitial access\b/i, "initial access"],
  [/\blateral movement\b/i, "lateral movement"],
  [/\bransomware\b/i, "ransomware"],
  [/\b(?:c2|c&c|command[- ]and[- ]control)\b/i, "C2"],
  [/\biocs?\b|\bindicators? of compromise\b/i, "IOCs"],
  [/\bttps?\b/i, "TTPs"],
  [/\bcampaigns?\b/i, "campaign"],
  [/\bintrusions?\b/i, "intrusion"],
  [/\bexploit(?:s|ed|ing|ation)?\b/i, "exploitation"],
  [/\bthreat actors?\b/i, "threat actor"],
  [/\bdfir\b|\bincident response\b/i, "DFIR"],
  [/\badvisor(?:y|ies)\b/i, "advisory"],
  [/\bbackdoors?\b|\bimplants?\b|\bloaders?\b|\bdroppers?\b|\brats?\b/i, "malware tooling"],
  [/\b(?:info)?stealers?\b|\bwipers?\b|\brootkits?\b|\bbotnets?\b|\bwebshells?\b|\bweb shells?\b/i, "malware family type"],
  [/\bmalware\b/i, "malware"],
  [/\bzero[- ]day\b|\b0[- ]day\b/i, "zero-day"],
  [/\bespionage\b|\bstate[- ]sponsored\b|\bnation[- ]state\b/i, "espionage"],
  [/\bphishing\b|\bspear[- ]?phishing\b|\bsmishing\b|\bvishing\b/i, "phishing"],
  [/\bpersistence\b|\bprivilege escalation\b|\bcredential (?:access|theft|dumping)\b|\bexfiltrat\w*/i, "post-compromise behaviour"],
  [/\bsupply[- ]chain (?:attack|compromise)\b/i, "supply-chain attack"],
  [/\bmalvertising\b|\bseo[- ]poison\w*|\bfake (?:browser )?updates?\b|\bdrive[- ]by\b|\bwatering[- ]hole\b/i, "delivery technique"],
  [/\btargets?\b|\btargeting\b|\btargeted\b/i, "targeting"],
  [/\bthreat hunting\b|\bhunt(?:ing)? for\b|\bdetection (?:opportunities|engineering|rules?)\b|\bsigma\b|\byara\b/i, "detection / hunting"],
  [/\badversary emulation\b|\bemulation plan\b|\bred team\b|\bpurple team\b|\batomic\b/i, "emulation"],
  [/\battack simulation\b|\bbreach and attack simulation\b|\bbas\b|\bsimulat(?:e|ed|ing|ion) (?:the )?(?:attack|adversary|intrusion|ransomware)\b|\bdetection opportunit(?:y|ies)\b/i, "simulation / detection validation"],
  [/\bvulnerabilit(?:y|ies)\b|\brce\b|\bremote code execution\b/i, "vulnerability"],
  [/\bbreach(?:ed|es)?\b|\bcompromis(?:e|ed|es)\b/i, "compromise"],
  [/\bdeep[- ]dive\b|\banalysis\b|\bdissect\w*\b|\breverse[- ]engineer\w*/i, "technical analysis"],
  // --- Targeted TTP / tradecraft / novelty signals (high value for emulation & simulation) ---
  [/\bnovel\b|\bnew (?:technique|method|variant|tooling|malware|loader|backdoor)\b|\bpreviously (?:un)?(?:documented|seen|reported)\b|\bnewly (?:discovered|identified|observed)\b|\bfirst (?:observed|seen|documented)\b|\bemerging\b/i, "novel technique / tradecraft"],
  [/\bprocedures?\b|\btradecraft\b|\bmodus operandi\b|\bplaybook\b|\bhands?-on-keyboard\b/i, "procedure / tradecraft"],
  [/\bliving[- ]off[- ]the[- ]land\b|\blol ?bins?\b|\blol ?bas\b|\blol ?scripts?\b/i, "living-off-the-land"],
  [/\bprocess (?:injection|hollowing|doppelg(?:ä|a)nging)\b|\bdll (?:side[- ]?loading|search[- ]?order hijack\w*|injection)\b|\breflective (?:dll )?loading\b|\bshellcode\b|\bcode injection\b/i, "injection / loading technique"],
  [/\b(?:byovd|bring your own vulnerable driver)\b|\bamsi bypass\b|\betw (?:bypass|patch\w*)\b|\bedr (?:bypass|evasion|unhook\w*)\b|\buac bypass\b|\bdirect syscalls?\b|\bunhook\w*\b|\bdefense evasion\b/i, "defence evasion / bypass"],
  [/\b(?:cobalt strike|sliver|brute ?ratel|metasploit|meterpreter|havoc|mythic|covenant|nighthawk)\b|\bbeacons?\b|\bc2 framework\b/i, "offensive C2 tooling"],
  [/\btoken (?:impersonation|theft)\b|\bkerberoast\w*|\bpass[- ]the[- ](?:hash|ticket)\b|\bgolden ticket\b|\bntlm relay\b|\bdcsync\b|\blsass\b|\bmimikatz\b/i, "credential-access technique"],
  [/\bactively exploited\b|\bexploited in (?:the wild|attacks|campaigns)\b|\bin[- ]the[- ]wild\b|\bexploitation in the wild\b|\bn[- ]day\b|\bpatch bypass\b|\bproof[- ]of[- ]concept\b|\bpo[cC]\b/i, "active / in-the-wild exploitation"],
  [/\bmalware analysis report\b|\bmar\b|\btechnical (?:analysis|report)\b|\bthreat (?:report|intelligence report)\b|\bincident report\b/i, "technical threat report"],
  [/\bkill[- ]chain\b|\battack[- ]chain\b|\bexecution chain\b|\binfection chain\b|\bmitre att&?ck\b/i, "attack chain / ATT&CK"],
  [/\bdetection (?:rule|logic|signatures?|content)\b|\bhunting (?:quer(?:y|ies)|hypothes[ei]s)\b|\bsnort\b|\bsuricata\b|\bsigma rule\b|\byara rule\b/i, "detection content"],
  [/\bmulti[- ]stage\b|\bdelivery (?:chain|platform|framework)\b|\bstep[- ]by[- ]step\b|\bclickfix\b|\bsteganograph\w*|\bfileless\b|\bin[- ]memory (?:execution|payload|loader)\b|\bsideload\w*/i, "chain / delivery tradecraft"],
];

const NEGATIVE_TERMS: Array<[RegExp, string, number]> = [
  [/\bwebinars?\b|\bweb ?cast\b|\blive stream\b|\bon[- ]demand session\b/i, "webinar", 0.42],
  [/\bpodcasts?\b|\bepisode \d+\b|\bep\.? ?\d+\b/i, "podcast", 0.42],
  [/\bawards?\b|\bawarded\b|\bnamed (?:a |the )?leader\b|\brecogni[sz]ed (?:as|by|in)\b|\bmagic quadrant\b|\bforrester wave\b|\bgartner\b/i, "award / analyst ranking", 0.4],
  [/\bhiring\b|\bcareers?\b|\bjoin (?:our|the) team\b|\bwe'?re hiring\b|\bjob openings?\b|\binternships?\b/i, "hiring", 0.42],
  [/\b(?:product )?launch(?:es|ed)?\b|\bintroduc(?:es|ing)\b|\bunveil(?:s|ed)?\b|\bnow available\b|\bgeneral availability\b|\bnew features?\b|\brelease notes\b|\bwhat'?s new\b/i, "product launch", 0.32],
  [/\bpartner(?:s|ship|ships)? with\b|\bpartnership\b|\bteams up with\b|\bacquires?\b|\bacquisition of\b|\bstrategic alliance\b/i, "partnership / M&A", 0.38],
  [/\bearnings\b|\bquarterly results\b|\bfinancial results\b|\bfiscal (?:year|q[1-4])\b|\bq[1-4] \d{4} results\b|\binvestor\b|\bfunding round\b|\bseries [a-e] funding\b|\braises \$/i, "earnings / funding", 0.45],
  [/\brecap\b|\bhighlights from\b|\bsee you at\b|\bmeet us at\b|\bjoin us at\b|\bvisit (?:us|our booth)\b|\bbooth\b|\bkeynote\b|\bsummit 20\d\d\b|\bconference 20\d\d\b|\b(?:your )?guide to [\w ]{0,40}\bat (?:microsoft |google |aws |the )?(?:ignite|build|rsac|rsa conference|black hat|def ?con|re:?invent|cloud next|summit|conference)\b|\b(?:ignite|rsac|re:?invent|cloud next|black hat (?:usa|europe|asia)) 20\d\d\b/i, "event / recap", 0.36],
  [/\bciso perspectives?\b|\bthought leadership\b|\bin the age of ai\b|\blessons (?:from|for) (?:security )?leaders\b|\bboard(?:room)? conversations?\b|\bsecurity leaders? (?:should|must)\b/i, "thought leadership", 0.24],
  [/\bregister (?:now|today)\b|\bsign up\b|\bfree trial\b|\bbook a demo\b|\brequest a demo\b|\bget started\b|\bpricing\b|\bdiscount\b|\bcoupon\b|\bblack friday\b/i, "marketing call to action", 0.4],
  [/\bcustomer (?:story|success)\b|\btestimonial\b|\bcase study:? how [a-z]+ (?:uses|chose|saved)\b|\bwhy (?:customers|teams) choose\b|\broi\b/i, "customer marketing", 0.36],
  [/\bpress release\b|\bannounc(?:es|ed|ement)\b|\bappoint(?:s|ed|ment)\b|\bjoins (?:the )?board\b|\bnames new\b|\bchief [a-z]+ officer\b/i, "corporate announcement", 0.34],
  [/\bnewsletter\b|\bweekly (?:digest|roundup)\b|\bthis week in\b|\bmonthly roundup\b/i, "newsletter / roundup", 0.22],
  [/\btips\b|\bbest practices\b|\bhow to choose\b|\bbuyer'?s guide\b|\bchecklist\b|\bwhy you need\b|\bmyths?\b/i, "generic advice", 0.16],
  [/\bhow to protect (?:yourself|your(?:self| family| business| organi[sz]ation)?)\b|\bunderstanding (?:the|what|how|why)\b|\bwhat is (?:a |an )?\b|\bexplained\b|\b101\b|\bbeginner'?s guide\b/i, "awareness explainer", 0.16],
  [/\bculture\b|\bemployee spotlight\b|\bmeet the team\b|\bdiversity\b|\bcharity\b|\bholiday season\b/i, "company culture", 0.36],
  // --- Vendor marketing collateral & opinion that is not a report (title / summary level).
  // Listing / share / cookie chrome is handled by the extraction (boilerplate strip) and the library
  // gate's page-type rule, not here, so a sparse feed title like "Read more" is never pre-skipped. ---
  // "sponsored post/content" only — never bare "sponsored", which would wrongly hit "state-sponsored".
  [/\bsponsored (?:post|content|article)\b|\bsponsor(?:ed)? content\b|\badvertisement\b|\bpromoted (?:post|content)\b|\baffiliate link\b/i, "sponsored / advertorial", 0.34],
  [/\bultimate guide\b|\bcomplete guide\b|\beverything you need to know\b|\btop \d+ (?:tools|vendors|solutions|tips|ways|reasons)\b|\bbest \d+ (?:tools|vendors|solutions|antivirus|vpns?)\b|\bbuyer'?s guide\b|\bmagic quadrant\b|\bforrester waves? report\b/i, "buyer's guide / comparison", 0.3],
  [/\bstate of (?:[a-z ]+ )?(?:security|ransomware|threats?|the [a-z]+) (?:report )?20\d\d\b|\bannual (?:threat )?report 20\d\d\b|\btrends to watch\b|\bpredictions for 20\d\d\b|\byear in review\b/i, "vendor trend / predictions report", 0.22],
  [/\bop-?ed\b|\bcommentary\b|\bmy take\b|\bhot take\b/i, "opinion / commentary", 0.2],
  // Vendor patch / update notices: a CVE in the title still fetches them, the emulation-simulation floor decides.
  [/\b(?:patch(?:es|ed)? (?:released|available|now)|(?:releases?|issues?|ships?) (?:a )?(?:patch|fix|security update)s?|security updates? (?:for|address)|update now|patch tuesday|fixes (?:critical|high|\d+)|patched (?:in|by)|hotfix)\b/i, "patch / update notice", 0.26],
  [/\bdata privacy day\b|\bcyber(?:security)? awareness month\b|\bworld (?:password|backup) day\b|\bstay safe online\b|\bpassword (?:hygiene|tips)\b/i, "awareness campaign", 0.3],
];

const URL_NEGATIVE: Array<[RegExp, string]> = [
  [/\/(?:webinars?|webcasts?|podcasts?|events?|press(?:-releases?)?|news-?releases?|newsroom|careers?|jobs|awards?|customers?|customer-stories|partners?|pricing|demo|trial|resources\/(?:webinars?|ebooks?|datasheets?))(?:\/|$)/i, "non-research URL section"],
  [/\/(?:company|about|investor|ir|culture|life-at)(?:\/|$)/i, "corporate URL section"],
  [/\/(?:security-news|cyber-news|news-digest|daily-news|weekly-news)(?:\/|$)/i, "news section URL"],
];
const URL_POSITIVE: Array<[RegExp, string]> = [
  [/\/(?:threat-?intel(?:ligence)?|threat-research|research|labs|advisor(?:y|ies)|reports?|dfir|incident-response|security-research|threats?|malware|apt|unit42|talos)(?:\/|$)/i, "research URL section"],
  [/cve-\d{4}-\d{4,7}/i, "CVE in URL"],
];

function clamp(n: number) {
  return Math.max(0, Math.min(1, n));
}

export function scoreRelevance(input: RelevanceInput, threshold = RELEVANCE_SKIP_THRESHOLD): RelevanceResult {
  const title = (input.title ?? "").replace(/\s+/g, " ").trim();
  const summary = (input.summary ?? "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, 1200);
  const url = input.url ?? "";
  const text = `${title}\n${summary}`;
  const signals: RelevanceSignal[] = [];
  let score = BASE;
  let strongPositive = false;

  const add = (s: RelevanceSignal) => {
    signals.push(s);
    score += s.polarity === "negative" ? -s.weight : s.weight;
  };

  // 1. ATT&CK entities (bundled knowledge; generic words are skipped by findEntitiesInText).
  const entities = text.trim() ? findEntitiesInText(text, { limit: 6 }) : [];
  const groups = entities.filter((e) => e.kind === "group" || e.kind === "campaign");
  const software = entities.filter((e) => e.kind === "software");
  if (groups.length) {
    strongPositive = true;
    add({ polarity: "positive", label: "ATT&CK actor / campaign", weight: 0.3 + Math.min(groups.length - 1, 2) * 0.05, evidence: groups.map((g) => `${g.name} ${g.id}`).join(", ") });
  }
  if (software.length) {
    strongPositive = true;
    add({ polarity: "positive", label: "ATT&CK software", weight: 0.22, evidence: software.map((s) => `${s.name} ${s.id}`).join(", ") });
  }

  // 2. IDs and naming schemes.
  const cves = [...new Set(text.match(/\bCVE-\d{4}-\d{4,7}\b/gi) ?? [])];
  if (cves.length) {
    strongPositive = true;
    add({ polarity: "positive", label: "CVE ID", weight: 0.22, evidence: cves.slice(0, 3).join(", ") });
  }
  const techniques = [...new Set(text.match(/\bT1\d{3}(?:\.\d{3})?\b/g) ?? [])];
  if (techniques.length) {
    strongPositive = true;
    add({ polarity: "positive", label: "ATT&CK technique ID", weight: 0.2, evidence: techniques.slice(0, 3).join(", ") });
  }
  const schemes = ACTOR_SCHEMES.map((s) => ({ s, m: text.match(s.re) })).filter((x) => x.m);
  if (schemes.length && !groups.length) {
    strongPositive = true;
    add({ polarity: "positive", label: "actor naming scheme", weight: 0.26, evidence: schemes.map((x) => `${x.m![0]} (${x.s.label})`).join(", ") });
  }

  // 3. Intrusion vocabulary (distinct terms, diminishing).
  const vocab = INTRUSION_TERMS.filter(([re]) => re.test(text)).map(([, label]) => label);
  if (vocab.length) {
    add({ polarity: "positive", label: "intrusion vocabulary", weight: Math.min(0.09 * vocab.length, 0.34), evidence: vocab.slice(0, 6).join(", ") });
  }

  // 4. Negative (title weighs fully, summary-only hits at half weight).
  for (const [re, label, w] of NEGATIVE_TERMS) {
    const inTitle = re.test(title);
    const inSummary = !inTitle && re.test(summary);
    if (inTitle || inSummary) {
      const m = (inTitle ? title : summary).match(re)?.[0];
      add({ polarity: "negative", label, weight: inTitle ? w : w / 2, evidence: m });
    }
  }

  // 5. URL.
  for (const [re, label] of URL_NEGATIVE) {
    if (re.test(url)) {
      add({ polarity: "negative", label, weight: 0.24, evidence: url.match(re)?.[0] });
      break;
    }
  }
  for (const [re, label] of URL_POSITIVE) {
    if (re.test(url)) {
      add({ polarity: "positive", label, weight: 0.08, evidence: url.match(re)?.[0] });
      break;
    }
  }

  // 6. Source context.
  const h = input.sourceHistory;
  if (h && h.accepted + h.rejected >= 5) {
    const rate = (h.accepted + 1) / (h.accepted + h.rejected + 2);
    const w = Math.round((rate - 0.5) * 0.3 * 100) / 100;
    if (w !== 0) {
      signals.push({ polarity: "context", label: `source acceptance ${Math.round(rate * 100)}%`, weight: w, evidence: `${h.accepted} accepted / ${h.rejected} rejected` });
      score += w;
    }
  }
  if (input.sourceTier === 1 || input.sourceTier === 2) {
    signals.push({ polarity: "context", label: `tier ${input.sourceTier} source`, weight: 0.1 });
    score += 0.1;
  }

  score = Math.round(clamp(score) * 100) / 100;
  const decision: RelevanceResult["decision"] = score < threshold ? "skip" : "fetch";
  return { score, decision, strongPositive, signals, reason: summarizeRelevance(score, decision, signals, threshold) };
}

export function summarizeRelevance(score: number, decision: "fetch" | "skip", signals: RelevanceSignal[], threshold = RELEVANCE_SKIP_THRESHOLD): string {
  const neg = signals.filter((s) => s.polarity === "negative").map((s) => s.label);
  const pos = signals.filter((s) => s.polarity === "positive").map((s) => (s.evidence ? `${s.label}: ${s.evidence}` : s.label));
  if (decision === "skip") {
    return `Low relevance pre-score ${score.toFixed(2)} (< ${threshold.toFixed(2)})${neg.length ? ` · ${neg.join(", ")}` : ""}${pos.length ? "" : " · no ATT&CK entity, CVE, technique or intrusion term in title/summary"}`;
  }
  return `Relevance pre-score ${score.toFixed(2)}${pos.length ? ` · ${pos.slice(0, 3).join("; ")}` : ""}${neg.length ? ` · despite ${neg.join(", ")}` : ""}`;
}
