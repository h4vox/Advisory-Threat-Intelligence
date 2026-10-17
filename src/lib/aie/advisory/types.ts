/**
 * Advisory simulation contract.
 *
 * The workflow the AIE briefs describe: public threat intelligence → grounded intelligence →
 * advisory → candidate behaviours → scoped simulation → detection / response validation →
 * findings and recommendations. An advisory is an evidence-grounded document about one threat
 * (actor, campaign, vulnerability, malware or a set of reports): every fact cites the library report
 * and passage it came from, and what the sources do not say is listed as a known gap. Its
 * simulation scope is a purple path; simulation runs record what each step did in the analyst's
 * environment, and findings follow from those outcomes.
 *
 * Pure types; safe to import from components.
 */
import type { EvidenceLabel, SourceTier, TargetingFact } from "../types.ts";
import type { PurplePath, PurplePlatform } from "../purple/types.ts";

export type AdvisorySubjectKind = "actor" | "campaign" | "vulnerability" | "malware" | "reports";

export type AdvisorySubject = {
  kind: AdvisorySubjectKind;
  /** G-ID, C-ID, S-ID, an actor slug, the first CVE id, or "reports". */
  id: string;
  name: string;
  attackId?: string;
  attackUrl?: string;
  aliases: string[];
  description?: string;
  cveIds?: string[];
  reportIds?: string[];
};

/** What the analyst asked for; kept so the advisory can be rebuilt from the current library. */
export type AdvisoryInputSpec = {
  kind: AdvisorySubjectKind;
  /** Actor / campaign / malware name or ATT&CK id. */
  value?: string;
  cveIds?: string[];
  reportIds?: string[];
};

export type AdvisoryStatus = "draft" | "review" | "published" | "simulating" | "closed";
export const ADVISORY_STATUSES: ReadonlyArray<{ value: AdvisoryStatus; label: string }> = [
  { value: "draft", label: "Draft" },
  { value: "review", label: "In review" },
  { value: "published", label: "Published" },
  { value: "simulating", label: "Simulating" },
  { value: "closed", label: "Closed" },
];

/** FIRST Traffic Light Protocol 2.0. */
export type Tlp = "CLEAR" | "GREEN" | "AMBER" | "AMBER+STRICT" | "RED";
export const TLP_LEVELS: ReadonlyArray<{ value: Tlp; label: string; hint: string }> = [
  { value: "CLEAR", label: "TLP:CLEAR", hint: "No limit on disclosure" },
  { value: "GREEN", label: "TLP:GREEN", hint: "Community-wide, not public" },
  { value: "AMBER", label: "TLP:AMBER", hint: "Organisation and its clients, need to know" },
  { value: "AMBER+STRICT", label: "TLP:AMBER+STRICT", hint: "Organisation only" },
  { value: "RED", label: "TLP:RED", hint: "Named recipients only" },
];

export type AdvisorySeverity = "critical" | "high" | "medium" | "low";

export type CitationLabel = Extract<EvidenceLabel, "observed" | "inferred" | "defensive"> | "mapped" | TargetingFact["status"];

/** One library report backing a fact, with the verbatim passage when the analysis kept one. */
export type SourceCitation = {
  reportId: string;
  title: string;
  publisher: string;
  publishedAt: string | null;
  label?: CitationLabel;
  quote?: string;
  section?: string;
};

export type AdvisoryBehaviour = {
  techniqueId: string;
  name: string;
  tactic: string;
  /** Reports that describe the behaviour as observed / inferred / only list it (mapped). */
  observedIn: number;
  inferredIn: number;
  mappedIn: number;
  attributedByAttack: boolean;
  /** Part of the generated simulation path. */
  inPath: boolean;
  citations: SourceCitation[];
  mitigations: Array<{ id: string; name: string }>;
};

export type AdvisoryTargeting = {
  kind: TargetingFact["kind"];
  value: string;
  /** Strongest status any source gives (compromised > targeted > at risk > mentioned). */
  status: TargetingFact["status"];
  reports: number;
  citations: SourceCitation[];
};

export type KevDetails = {
  vendor: string;
  product: string;
  name: string;
  dateAdded: string;
  dueDate?: string;
  ransomwareUse?: string;
  requiredAction?: string;
};

export type AdvisoryVulnerability = { cveId: string; citations: SourceCitation[]; kev?: KevDetails };

export type AdvisoryIndicator = {
  kind: string;
  /** Normalised value. */
  value: string;
  /** As the source printed it (defanged when it was). */
  display: string;
  role?: string;
  firstSeen: string | null;
  reports: number;
  citations: SourceCitation[];
};

export type AdvisoryDetection = {
  techniqueId: string;
  name: string;
  tactic: string;
  telemetry: string[];
  hypothesis: string;
  /** Always a skeleton; never presented as a production rule. */
  queryTemplate: string;
};

export type AdvisoryRecommendation =
  | { kind: "patch"; cveId: string; action: string; dueDate?: string; source: "CISA KEV" }
  | { kind: "attack_mitigation"; id: string; name: string; description: string; techniques: string[] }
  | { kind: "source_guidance"; text: string; citation: SourceCitation };

export type AdvisoryGap = { key: string; text: string; impact: "high" | "medium" | "low" };

export type AdvisorySource = {
  reportId: string;
  title: string;
  publisher: string;
  publishedAt: string | null;
  tier?: SourceTier;
  confidence?: number;
  url?: string;
};

/** Everything generated from the library and ATT&CK; rebuilt on "Regenerate". */
export type AdvisoryContent = {
  version: 1;
  generatedAt: string;
  attackVersion: string | null;
  subject: AdvisorySubject;
  title: string;
  severity: AdvisorySeverity;
  severityReasons: string[];
  /** Bottom line up front: facts only, each traceable to the sections below. */
  summary: string;
  keyPoints: string[];
  activity: { firstSeen: string | null; lastSeen: string | null; reports: number; publishers: string[] };
  behaviours: AdvisoryBehaviour[];
  /** Techniques ATT&CK attributes to the subject that no library report describes. */
  attackOnlyBehaviours: Array<{ techniqueId: string; name: string; tactic: string }>;
  targeting: AdvisoryTargeting[];
  vulnerabilities: AdvisoryVulnerability[];
  indicators: AdvisoryIndicator[];
  indicatorTotal: number;
  detections: AdvisoryDetection[];
  recommendations: AdvisoryRecommendation[];
  gaps: AdvisoryGap[];
  sources: AdvisorySource[];
  /** The simulation scope candidates (purple path). */
  path: PurplePath;
  emulationSynced: boolean;
  kevSynced: boolean;
};

export type AdvisoryOptions = { platforms: PurplePlatform[]; excludeHighRisk: boolean; maxSteps: number };

export type AdvisoryRecord = {
  id: string;
  /** ADV-2026-0001 */
  number: string;
  status: AdvisoryStatus;
  tlp: Tlp;
  createdAt: string;
  updatedAt: string;
  createdBy: string | null;
  updatedBy?: string | null;
  /** Analyst edits; they survive regeneration. */
  overrides: { title?: string; severity?: AdvisorySeverity; severityNote?: string; summary?: string; notes?: string };
  /** Technique ids of the path steps in scope for simulation. */
  scope: string[];
  options: AdvisoryOptions;
  input: AdvisoryInputSpec;
  content: AdvisoryContent;
};

// ---------------------------------------------------------------------------
// Simulation runs (detection / response validation)
// ---------------------------------------------------------------------------

export type StepOutcome = "prevented" | "detected" | "logged" | "missed" | "not_run" | "not_applicable";

export const STEP_OUTCOMES: ReadonlyArray<{ value: StepOutcome; label: string; hint: string; tone: "success" | "info" | "warning" | "danger" | "neutral" }> = [
  { value: "prevented", label: "Prevented", hint: "A control blocked the behaviour", tone: "success" },
  { value: "detected", label: "Detected", hint: "An alert fired and reached the SOC", tone: "info" },
  { value: "logged", label: "Logged only", hint: "Telemetry exists but nothing alerted", tone: "warning" },
  { value: "missed", label: "Not detected", hint: "No block, no alert, no usable telemetry", tone: "danger" },
  { value: "not_run", label: "Not run", hint: "Not executed yet", tone: "neutral" },
  { value: "not_applicable", label: "Not applicable", hint: "Out of scope for this environment", tone: "neutral" },
];

export type StepResult = {
  techniqueId: string;
  outcome: StepOutcome;
  notes?: string;
  /** Alert id, ticket, screenshot link, log query… */
  evidenceRef?: string;
  /** Control or product that prevented / detected it. */
  detectedBy?: string;
  recordedAt: string;
  recordedBy: string | null;
};

export type SimulationRun = {
  id: string;
  advisoryId: string;
  /** 1, 2, 3… within the advisory. */
  number: number;
  name: string;
  environment?: string;
  status: "in_progress" | "completed";
  startedAt: string;
  completedAt?: string | null;
  startedBy: string | null;
  /** Technique ids in scope when the run started. */
  scope: string[];
  results: Record<string, StepResult>;
};

export type RunMetrics = {
  total: number;
  executed: number;
  prevented: number;
  detected: number;
  logged: number;
  missed: number;
  notRun: number;
  notApplicable: number;
  /** Shares of executed steps (0..1); null before anything was executed. */
  preventionRate: number | null;
  /** Prevented or detected. */
  detectionRate: number | null;
  /** Prevented, detected or at least logged. */
  visibilityRate: number | null;
  byTactic: Array<{ tactic: string; total: number } & Record<StepOutcome, number>>;
};

export type FindingSeverity = "critical" | "high" | "medium" | "low";

export type AdvisoryFinding = {
  id: string;
  techniqueId: string;
  name: string;
  tactic: string;
  outcome: Extract<StepOutcome, "missed" | "logged">;
  severity: FindingSeverity;
  severityReason: string;
  title: string;
  /** Why it matters, from the advisory evidence. */
  context: string;
  detection: { telemetry: string[]; hypothesis: string; queryTemplate: string };
  mitigations: Array<{ id: string; name: string }>;
  notes?: string;
  /** Change versus the previous completed run. */
  trend?: "new" | "unchanged" | "regressed";
};

export type RunComparison = {
  previousRun: number;
  improved: Array<{ techniqueId: string; from: StepOutcome; to: StepOutcome }>;
  regressed: Array<{ techniqueId: string; from: StepOutcome; to: StepOutcome }>;
};

export type AdvisorySummary = {
  id: string;
  number: string;
  title: string;
  subject: { kind: AdvisorySubjectKind; name: string; attackId?: string };
  status: AdvisoryStatus;
  tlp: Tlp;
  severity: AdvisorySeverity;
  behaviours: number;
  scopedSteps: number;
  sources: number;
  gaps: number;
  createdAt: string;
  updatedAt: string;
  createdBy: string | null;
  latestRun?: { number: number; status: SimulationRun["status"]; detectionRate: number | null; missed: number; executed: number; total: number };
};
