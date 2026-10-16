import type { ComponentType, ReactNode } from "react";
import {
  Bug,
  Crosshair,
  FileText,
  FlaskConical,
  GitBranch,
  Globe2,
  Hash,
  Layers,
  Megaphone,
  Radar,
  ScrollText,
  ShieldAlert,
  Siren,
  Swords,
  Target,
  Users,
  Workflow,
} from "lucide-react";
import { cn } from "@/lib/cn";
import type { DocType } from "@/lib/aie/types";

/**
 * Coloured entity / document-type language shared across the product.
 * Each family has one hue (tokens --color-cat-* in styles.css), used for the
 * icon well and a subtle tint — never for large fills.
 */

type IconType = ComponentType<{ className?: string; strokeWidth?: number }>;

export type EntityKind = "actor" | "malware" | "technique" | "cve" | "ioc" | "source" | "advisory" | "emulation" | "flow";

const KIND: Record<EntityKind, { icon: IconType; color: string; label: string }> = {
  actor: { icon: Users, color: "var(--color-cat-actor)", label: "Threat actor" },
  malware: { icon: Bug, color: "var(--color-cat-malware)", label: "Malware / tool" },
  technique: { icon: Layers, color: "var(--color-cat-technique)", label: "Technique" },
  cve: { icon: ShieldAlert, color: "var(--color-cat-cve)", label: "Vulnerability" },
  ioc: { icon: Hash, color: "var(--color-cat-ioc)", label: "Indicator" },
  source: { icon: Globe2, color: "var(--color-cat-source)", label: "Source" },
  advisory: { icon: Megaphone, color: "var(--color-cat-advisory)", label: "Advisory" },
  emulation: { icon: FlaskConical, color: "var(--color-cat-emulation)", label: "Emulation" },
  flow: { icon: Workflow, color: "var(--color-cat-flow)", label: "Attack flow" },
};

export function entityMeta(kind: EntityKind) {
  return KIND[kind];
}

/** Square tinted icon well (Hadrian-style coloured glyph). */
export function EntityIcon({ kind, size = "md", icon }: { kind: EntityKind; size?: "sm" | "md" | "lg"; icon?: IconType }) {
  const meta = KIND[kind];
  const Icon = icon ?? meta.icon;
  const box = size === "sm" ? "size-6" : size === "lg" ? "size-10" : "size-8";
  const glyph = size === "sm" ? "size-3.5" : size === "lg" ? "size-5" : "size-4";
  return (
    <span
      aria-hidden
      className={cn("inline-flex shrink-0 items-center justify-center rounded-lg", box)}
      style={{ color: meta.color, backgroundColor: `color-mix(in oklab, ${meta.color} 16%, transparent)` }}
    >
      <Icon className={glyph} strokeWidth={1.9} />
    </span>
  );
}

/** Compact coloured chip for a named entity (actor, malware, CVE…). */
export function EntityChip({ kind, children, title }: { kind: EntityKind; children: ReactNode; title?: string }) {
  const meta = KIND[kind];
  return (
    <span
      title={title ?? meta.label}
      className="inline-flex max-w-full items-center gap-1.5 truncate rounded-md px-2 py-0.5 text-xs font-medium"
      style={{ color: meta.color, backgroundColor: `color-mix(in oklab, ${meta.color} 14%, transparent)` }}
    >
      <span className="size-1.5 shrink-0 rounded-full" style={{ backgroundColor: meta.color }} />
      <span className="truncate">{children}</span>
    </span>
  );
}

// ---------------------------------------------------------------------------
// Document types
// ---------------------------------------------------------------------------

export const DOC_TYPE_META: Record<DocType, { label: string; short: string; kind: EntityKind; icon: IconType }> = {
  THREAT_REPORT: { label: "Threat report", short: "Threat report", kind: "technique", icon: Radar },
  THREAT_ADVISORY: { label: "Threat advisory", short: "Advisory", kind: "advisory", icon: Megaphone },
  INCIDENT_REPORT: { label: "Incident report", short: "Incident", kind: "actor", icon: Siren },
  DFIR_REPORT: { label: "DFIR report", short: "DFIR", kind: "actor", icon: Siren },
  MALWARE_REPORT: { label: "Malware analysis", short: "Malware", kind: "malware", icon: Bug },
  VULNERABILITY_ADVISORY: { label: "Vulnerability advisory", short: "Vulnerability", kind: "cve", icon: ShieldAlert },
  CAMPAIGN_REPORT: { label: "Campaign report", short: "Campaign", kind: "actor", icon: Target },
  MITRE_GROUP: { label: "ATT&CK group", short: "Group", kind: "actor", icon: Users },
  MITRE_SOFTWARE: { label: "ATT&CK software", short: "Software", kind: "malware", icon: Bug },
  MITRE_CAMPAIGN: { label: "ATT&CK campaign", short: "Campaign", kind: "actor", icon: Target },
  MITRE_TECHNIQUE: { label: "ATT&CK technique", short: "Technique", kind: "technique", icon: Layers },
  ADVERSARY_EMULATION_PLAN: { label: "Adversary emulation plan", short: "Emulation plan", kind: "emulation", icon: Swords },
  MICRO_EMULATION_PLAN: { label: "Micro emulation plan", short: "Micro emulation", kind: "emulation", icon: FlaskConical },
  ATTACK_FLOW: { label: "Attack flow", short: "Attack flow", kind: "flow", icon: GitBranch },
  ATOMIC_TEST: { label: "Atomic test", short: "Atomic test", kind: "emulation", icon: FlaskConical },
  CALDERA_ABILITY: { label: "CALDERA ability", short: "CALDERA", kind: "emulation", icon: Crosshair },
  PURPLE_TEAM_REPORT: { label: "Purple team report", short: "Purple team", kind: "emulation", icon: Swords },
  DETECTION_RESEARCH: { label: "Detection research", short: "Detection", kind: "ioc", icon: ScrollText },
  THREAT_HUNTING_REPORT: { label: "Threat hunting", short: "Hunting", kind: "ioc", icon: Radar },
  KEV_ENTRY: { label: "Known exploited vulnerability", short: "KEV", kind: "cve", icon: ShieldAlert },
  OTHER: { label: "Other", short: "Other", kind: "source", icon: FileText },
};

export function DocTypeBadge({ type }: { type: DocType }) {
  const meta = DOC_TYPE_META[type] ?? DOC_TYPE_META.OTHER;
  const color = entityMeta(meta.kind).color;
  return (
    <span
      className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-md px-2 py-0.5 text-xs font-medium"
      style={{ color, backgroundColor: `color-mix(in oklab, ${color} 14%, transparent)` }}
    >
      <meta.icon className="size-3.5" strokeWidth={1.9} />
      {meta.short}
    </span>
  );
}
