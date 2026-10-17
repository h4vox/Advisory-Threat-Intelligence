/**
 * Threat-actor view models shared by the actor server functions and the /actors UI.
 * Pure types only (safe to import from components).
 */
import type { EvidenceLabel } from "../types.ts";

export type ActorSort = "recent" | "reports" | "techniques" | "name";

/** Emulation availability for an actor. `synced: false` = the structured sources are not synced here. */
export type ActorEmulationSummary =
  | { synced: false }
  | {
      synced: true;
      /** CTID adversary emulation plans whose adversary resolves to this group. */
      ctidPlans: number;
      /** Techniques (attributed or observed) with at least one Atomic Red Team test. */
      atomicCovered: number;
      techniqueTotal: number;
    };

export type ActorRow = {
  /** ATT&CK group ID (G1024) or a stable slug for actors not in ATT&CK ("x-storm-1234"). */
  id: string;
  attackId: string | null;
  name: string;
  aliases: string[];
  inAttack: boolean;
  /** Seen in at least one library report. */
  observed: boolean;
  reportCount: number;
  firstSeen: string | null;
  lastSeen: string | null;
  publishers: string[];
  attributedTechniques: number;
  observedTechniques: number;
  /** Observed techniques that ATT&CK does not attribute to the group (exact or parent/sub). */
  newTechniques: number;
  software: number;
  campaigns: number;
  topTactics: Array<{ tactic: string; count: number }>;
  activityScore: number;
  emulation: ActorEmulationSummary;
};

export type ActorListKpis = {
  attackGroups: number;
  observedInLibrary: number;
  notInAttack: number;
  /** Distinct techniques observed across actor-linked library reports. */
  techniquesObserved: number;
  lastActivity: string | null;
  libraryReports: number;
};

export type ActorListResult = {
  rows: ActorRow[];
  /** Rows matching the filters (before paging). */
  total: number;
  kpis: ActorListKpis;
  attackVersion: string | null;
  emulationSynced: boolean;
};

export type ActorReportRef = {
  id: string;
  title: string;
  publisher: string;
  publishedAt: string | null;
  ingestedAt: string;
  url: string;
  /** How the actor was linked to the report. */
  matchedBy: "analysis" | "text";
  /** Surface form that matched ("PUNK SPIDER", "Akira"). */
  matched: string;
  techniqueCount: number;
  qualityScore: number;
};

export type ActorTechniqueEvidence = {
  quote: string;
  label: EvidenceLabel;
  reportId: string;
  reportTitle: string;
  section?: string;
};

export type ActorTechniqueRow = {
  id: string;
  name: string;
  tactics: string[];
  /** Tactic used for colour / ordering (report tactic when given, else first ATT&CK tactic). */
  tactic: string | null;
  source: "attack" | "observed" | "both";
  /** Library reports linked to the actor that mention the technique. */
  observedReports: number;
  evidenceCount: number;
  labels: EvidenceLabel[];
  /** Observed in the library but not attributed to the group by ATT&CK (also no parent/sub match). */
  isNew: boolean;
  evidence: ActorTechniqueEvidence[];
  /** null = emulation index not synced. */
  atomic: boolean | null;
};

export type ActorCampaignRow = {
  id: string;
  name: string;
  aliases: string[];
  firstSeen: string | null;
  lastSeen: string | null;
  techniqueCount: number;
  softwareCount: number;
  description: string;
};

export type ActorSoftwareRow = {
  id: string | null;
  name: string;
  type: "malware" | "tool" | null;
  platforms: string[];
  techniqueCount: number;
  attributed: boolean;
  /** Library reports linked to the actor that mention the software. */
  observedReports: number;
};

export type ActorCtidPlan = {
  reportId: string;
  title: string;
  url: string;
  planType: "full" | "micro";
  techniques: number;
};

export type ActorProfile = {
  row: ActorRow;
  description: string | null;
  attackUrl: string | null;
  techniques: ActorTechniqueRow[];
  reports: ActorReportRef[];
  campaigns: ActorCampaignRow[];
  software: ActorSoftwareRow[];
  cves: Array<{ id: string; reports: number }>;
  tacticCoverage: Array<{ tactic: string; attributed: number; observed: number }>;
  attackVersion: string | null;
  attackSnapshotDate: string | null;
  emulation: { synced: boolean; plans: ActorCtidPlan[] };
};

export type ActorSuggestion = {
  id: string;
  name: string;
  matched: string;
  inAttack: boolean;
  observed: boolean;
};
