/**
 * Purple path contract (spec §32–36, MVP 5 §60).
 *
 * A purple path turns intelligence (an actor, a report, a campaign or a hand-picked technique list)
 * into an ordered set of simulation steps, each with a §33 simulation object, §36 hunting
 * hypotheses and an honest §35 detection status. Planning only: nothing here executes anything.
 *
 * Pure types; safe to import from components.
 */
import type { EmulationOption } from "../types.ts";

export type PurplePlatform = "windows" | "linux" | "macos" | "cloud" | "saas" | "identity" | "network";

/** Environment choices → ATT&CK platform names (v18+ naming). */
export const PURPLE_PLATFORMS: ReadonlyArray<{ id: PurplePlatform; label: string; attack: readonly string[] }> = [
  { id: "windows", label: "Windows", attack: ["Windows"] },
  { id: "linux", label: "Linux", attack: ["Linux", "ESXi"] },
  { id: "macos", label: "macOS", attack: ["macOS"] },
  { id: "cloud", label: "Cloud / IaaS", attack: ["IaaS", "Containers"] },
  { id: "saas", label: "SaaS", attack: ["SaaS", "Office Suite"] },
  { id: "identity", label: "Identity", attack: ["Identity Provider"] },
  { id: "network", label: "Network", attack: ["Network Devices"] },
];

export type PurpleSourceKind = "actor" | "report" | "campaign" | "custom";

export type PurpleOptions = {
  /** Empty = every platform. */
  platforms: PurplePlatform[];
  excludeHighRisk: boolean;
  maxSteps: number;
};

export const DEFAULT_PURPLE_OPTIONS: PurpleOptions = { platforms: [], excludeHighRisk: false, maxSteps: 12 };

/** Technique facts the generator needs (same shape as the bundled ATT&CK knowledge). */
export type KbTechnique = {
  id: string;
  name: string;
  tactics: string[];
  platforms: string[];
  dataSources: string[];
};

export type ObservationLabel = "observed" | "inferred" | "mapped";

/** One technique as a library report describes it. */
export type ObservedTechnique = {
  id: string;
  label: ObservationLabel;
  tactic?: string;
  /** Evidence quotes from the stored report text (verbatim). */
  quotes: string[];
  /** Position in the source-reported sequence (0-based), when the report gives one. */
  position?: number;
};

/** A library report reduced to what the generator scores on. */
export type LibraryEvidence = {
  reportId: string;
  title: string;
  publishedAt: string | null;
  /** 0..1 (spec §42). */
  sourceConfidence: number;
  techniques: ObservedTechnique[];
};

/** Resolved input for the generator (the server builds it from an actor / report / campaign / list). */
export type PurpleSeed = {
  kind: PurpleSourceKind;
  /** G-ID, actor slug, report id, C-ID, or "custom". */
  id: string;
  name: string;
  /** Techniques ATT&CK attributes to the group / campaign. */
  attributed: string[];
  /** Who attributes them, for the reason text and refs ("ATT&CK G0016"). */
  attributedBy?: { id: string; url: string };
  /** Analyst-selected techniques (custom input). */
  custom?: string[];
  /** Library reports relevant to the seed. */
  reports: LibraryEvidence[];
  /** True when generated from a single report whose evidence records a source-reported order. */
  reportedOrder?: boolean;
  /** CTID (or other) emulation plans written for this adversary, when synced. */
  emulationPlans?: Array<{ reportId: string; title: string; techniques: string[] }>;
};

export type EmulationContext = {
  /** False until an emulation library (Atomic / CTID / CALDERA / Attack Flow) has been synced. */
  synced: boolean;
  options: Record<string, EmulationOption[]>;
};

export type RiskLevel = "low" | "medium" | "high";
export type Priority = "high" | "medium" | "low";

export type ExecutionMethod = {
  kind: EmulationOption["kind"];
  summary: string;
  /** Matching library procedures (platform-filtered, at most 5). */
  options: EmulationOption[];
};

export type SourceRef =
  | { kind: "report"; reportId: string; title: string; publishedAt: string | null; label: ObservationLabel; quotes: string[] }
  | { kind: "attack"; id: string; url: string; note: string }
  | { kind: "analyst"; note: string };

/** Spec §33 normalized simulation object. */
export type SimulationObject = {
  simulationId: string;
  scenario: string;
  objective: string;
  ttp: { id: string; name: string; tactic: string };
  prerequisites: string[];
  targetPlatforms: string[];
  requiredTelemetry: string[];
  execution: ExecutionMethod;
  expectedBehaviour: string;
  expectedDetection: string;
  successCriteria: string[];
  cleanup: string[];
  risk: { level: RiskLevel; reason: string };
  sourceRefs: SourceRef[];
};

/** Spec §36 hunting hypothesis. The query is a skeleton and always labelled as a template. */
export type HuntHypothesis = {
  huntId: string;
  techniqueId: string;
  hypothesis: string;
  telemetry: string[];
  query: { language: "pseudo-sql"; isTemplate: true; text: string };
};

export type DetectionCoverage = { status: "unknown"; note: string };

export type PurpleStep = {
  order: number;
  phase: string;
  technique: KbTechnique;
  score: number;
  priority: Priority;
  /** Each scoring factor as a short phrase ("Observed in 3 reports in the last 90 days"). */
  reasons: string[];
  reasonText: string;
  stats: {
    reports: number;
    recentReports: number;
    lastSeen: string | null;
    attributed: boolean;
    atomicTests: number;
    libraryOptions: number;
    inEmulationPlan: boolean;
    platformFit: string[];
  };
  simulation: SimulationObject;
  hunts: HuntHypothesis[];
  detection: DetectionCoverage;
};

export type PurplePath = {
  version: 1;
  id: string;
  generatedAt: string;
  source: { kind: PurpleSourceKind; id: string; name: string };
  options: PurpleOptions;
  orderBasis: "reported" | "tactic";
  orderNote: string;
  emulationSynced: boolean;
  steps: PurpleStep[];
  phases: Array<{ tactic: string; steps: number }>;
  /** Candidate techniques left out, with the reason (platform, risk, step limit, unknown id). */
  excluded: Array<{ id: string; name: string; reason: string }>;
  candidateCount: number;
  libraryReports: number;
  disclaimer: string;
};

export const PURPLE_DISCLAIMER =
  "Planning artefact only. AIE never executes procedures. Review every step and run it only in an authorised, isolated lab.";
export const DETECTION_UNKNOWN = "Unknown; connect a detection repository";
