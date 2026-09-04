/**
 * Unified Adversary Intelligence Engine (AIE) ID Standard
 *
 * Provides standardized, category-prefixed, deterministic, and human-friendly
 * identifiers across all CTI pipeline resources, ingestion states, and audit trails.
 *
 * Prefixes:
 *  - RPT-XXXXXX  : Library Reports & Intelligence Dossiers (Green)
 *  - ING-XXXXXX  : Acquired & Ingested Pipeline Resources (Green)
 *  - DUP-XXXXXX  : Deduplicated Candidate URLs & Duplicate Hits (Amber)
 *  - REJ-XXXXXX  : Quality-Filtered / Noise / Low-Score Rejections (Red)
 *  - FAIL-XXXXXX : Network Fetch / TLS / Extraction Failures (Red)
 *  - DISC-XXXXXX : Candidate Resources in Discovery Queue (Cyan)
 *  - SRC-XXXXXX  : Registered & Discovered Threat Intel Sources (Sage/Purple)
 *  - DOM-XXXXXX  : Clean Domain Identifiers (Neutral)
 *  - ORG-XXXXXX  : Origin Provenance Tags (SEED, CRAWL, MANUAL, PASTE)
 *  - JOB-XXXXXX  : Crawl Engine Job Executions (Neutral/Green)
 *  - AUD-XXXXXX  : Pipeline Audit Progression Events (Neutral)
 *  - EDG-XXXXXX  : Citation & Outlink Knowledge Graph Edges (Neutral)
 */

export type IdCategory =
  | "report"
  | "ingested"
  | "duplicate"
  | "rejected"
  | "failed"
  | "discovered"
  | "source"
  | "domain"
  | "origin"
  | "job"
  | "audit"
  | "edge";

export type IdTone = "sage" | "warn" | "danger" | "accent" | "neutral" | "purple";

/**
 * Fast deterministic 8-character hex hash from any string (URL, title, etc.)
 */
export function deterministicHash(input: string): string {
  let hash = 5381;
  for (let i = 0; i < input.length; i++) {
    hash = ((hash << 5) + hash) ^ input.charCodeAt(i);
  }
  return (hash >>> 0).toString(16).padStart(8, "0").toUpperCase();
}

/**
 * Clean and uppercase a raw database ID into a standardized prefixed display ID
 */
export function formatSystemId(
  category: IdCategory,
  rawId?: string | null,
  fallbackSeed?: string,
): string {
  const prefixMap: Record<IdCategory, string> = {
    report: "RPT",
    ingested: "ING",
    duplicate: "DUP",
    rejected: "REJ",
    failed: "FAIL",
    discovered: "DISC",
    source: "SRC",
    domain: "DOM",
    origin: "ORG",
    job: "JOB",
    audit: "AUD",
    edge: "EDG",
  };

  const targetPrefix = prefixMap[category] || "AIE";

  if (!rawId && fallbackSeed) {
    return `${targetPrefix}-${deterministicHash(fallbackSeed)}`;
  }

  if (!rawId) {
    const rand = Math.floor(Math.random() * 0xffffffff).toString(16).padStart(8, "0").toUpperCase();
    return `${targetPrefix}-${rand}`;
  }

  const clean = rawId.trim();

  // If already formatted like RPT-XXXXXX, normalize case
  const prefixMatch = clean.match(/^([A-Za-z]+)[-_](.+)$/);
  if (prefixMatch) {
    const existingPrefix = prefixMatch[1].toUpperCase();
    const body = prefixMatch[2].replace(/[^a-zA-Z0-9]/g, "").slice(0, 12).toUpperCase();

    // If existing prefix is equivalent (e.g. RPT, ING, DUP, REJ, FAIL, SRC, JOB, AUD, EDG, DSC)
    if (existingPrefix === "RPT" || existingPrefix === "REPORT") {
      return `RPT-${body}`;
    }
    if (existingPrefix === "ING" || existingPrefix === "INGEST") {
      return `ING-${body}`;
    }
    if (existingPrefix === "DUP" || existingPrefix === "DUPLICATE") {
      return `DUP-${body}`;
    }
    if (existingPrefix === "REJ" || existingPrefix === "REJECTED") {
      return `REJ-${body}`;
    }
    if (existingPrefix === "FAIL" || existingPrefix === "FAILED" || existingPrefix === "ERR") {
      return `FAIL-${body}`;
    }
    if (existingPrefix === "DISC" || existingPrefix === "DSC" || existingPrefix === "CAND") {
      return `DISC-${body}`;
    }
    if (existingPrefix === "SRC" || existingPrefix === "SOURCE") {
      return `SRC-${body}`;
    }
    if (existingPrefix === "JOB") {
      return `JOB-${body}`;
    }
    if (existingPrefix === "AUD" || existingPrefix === "EVT") {
      return `AUD-${body}`;
    }
    if (existingPrefix === "EDG" || existingPrefix === "EDGE") {
      return `EDG-${body}`;
    }
    return `${targetPrefix}-${body}`;
  }

  // Pure alphanumeric or slug
  const alphaBody = clean.replace(/[^a-zA-Z0-9]/g, "").slice(0, 10).toUpperCase();
  return `${targetPrefix}-${alphaBody || deterministicHash(clean)}`;
}

/**
 * Format an Outcome / Pipeline Event into a dedicated, categorized ID structure
 */
export function formatOutcomeId(
  outcome: string,
  rawId?: string | null,
  fallbackUrl?: string,
): {
  id: string;
  category: IdCategory;
  tone: IdTone;
  label: string;
  badgeClass: string;
} {
  const norm = (outcome || "").toLowerCase().trim();

  // 1. Green items: Ingested, Acquired, Seeded
  if (norm === "ingested" || norm === "acquired" || norm === "seeded" || norm === "success" || norm === "completed") {
    const id = formatSystemId("ingested", rawId, fallbackUrl);
    return {
      id,
      category: "ingested",
      tone: "sage",
      label: "INGESTED",
      badgeClass: "border-emerald-500/30 bg-emerald-500/10 text-emerald-400",
    };
  }

  // 2. Amber items: Duplicate
  if (norm === "duplicate" || norm === "deduped" || norm === "already_stored") {
    const id = formatSystemId("duplicate", rawId, fallbackUrl);
    return {
      id,
      category: "duplicate",
      tone: "warn",
      label: "DUPLICATE",
      badgeClass: "border-amber-500/30 bg-amber-500/10 text-amber-400",
    };
  }

  // 3. Red items: Rejected
  if (norm === "rejected" || norm === "low_quality" || norm === "noise" || norm === "filtered") {
    const id = formatSystemId("rejected", rawId, fallbackUrl);
    return {
      id,
      category: "rejected",
      tone: "danger",
      label: "REJECTED",
      badgeClass: "border-rose-500/30 bg-rose-500/10 text-rose-400",
    };
  }

  // 4. Red items: Failed
  if (norm === "failed" || norm === "error" || norm === "timeout" || norm === "fetch_error" || norm === "blocked") {
    const id = formatSystemId("failed", rawId, fallbackUrl);
    return {
      id,
      category: "failed",
      tone: "danger",
      label: "FAILED",
      badgeClass: "border-red-600/30 bg-red-600/10 text-red-400",
    };
  }

  // 5. Cyan items: Qualified / Awaiting Approval / Discovered Queue
  const id = formatSystemId("discovered", rawId, fallbackUrl);
  return {
    id,
    category: "discovered",
    tone: "accent",
    label: "CANDIDATE",
    badgeClass: "border-cyan-500/30 bg-cyan-500/10 text-cyan-400",
  };
}

/**
 * Format domain identifier (e.g. "DOM-attack-mitre-org")
 */
export function formatDomainId(domain: string): string {
  if (!domain) return "DOM-UNKNOWN";
  const clean = domain
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .split("/")[0]
    .replace(/[^a-z0-9]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
  return `DOM-${clean || "EXTERNAL"}`;
}

/**
 * Format source origin identifier (e.g. "ORG-CRAWL", "ORG-SEED", "ORG-PASTE")
 */
export function formatOriginId(origin?: string): string {
  if (!origin) return "ORG-UNKNOWN";
  const norm = origin.toUpperCase().trim();
  switch (norm) {
    case "LIVE":
    case "ORG-LIVE":
      return "ORG-LIVE";
    case "CRAWL":
    case "AUTONOMOUS":
    case "ORG-CRAWL":
      return "ORG-CRAWL";
    case "SEED":
    case "ORG-SEED":
      return "ORG-SEED";
    case "PASTE":
    case "ORG-PASTE":
      return "ORG-PASTE";
    case "MANUAL":
    case "ORG-MANUAL":
      return "ORG-MANUAL";
    case "SEARCH":
    case "HUNT":
    case "ORG-SEARCH":
      return "ORG-SEARCH";
    default:
      return `ORG-${norm.replace(/[^A-Z0-9]/g, "-").slice(0, 10)}`;
  }
}

/**
 * Format Job ID with execution tag (e.g. "JOB-MAN-4A8E2B" or "JOB-SCHED-91C2")
 */
export function formatJobId(jobId: string, trigger?: string): string {
  const base = formatSystemId("job", jobId);
  if (!trigger) return base;
  const trg = trigger.toUpperCase().slice(0, 3);
  return base.replace(/^JOB-/, `JOB-${trg}-`);
}

/**
 * Format Library Report ID
 */
export function formatReportId(reportId?: string | null, fallbackUrl?: string): string {
  return formatSystemId("report", reportId, fallbackUrl);
}

/**
 * Format Source Registry ID
 */
export function formatSourceId(sourceId?: string | null, fallbackSlug?: string): string {
  return formatSystemId("source", sourceId, fallbackSlug);
}

/**
 * Format Audit Event ID
 */
export function formatAuditId(eventId?: string | null, fallbackUrl?: string): string {
  return formatSystemId("audit", eventId, fallbackUrl);
}

/**
 * Format Citation Graph Edge ID
 */
export function formatEdgeId(edgeId?: string | null, fallbackKey?: string): string {
  return formatSystemId("edge", edgeId, fallbackKey);
}
