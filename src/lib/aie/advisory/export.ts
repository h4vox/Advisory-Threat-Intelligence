/**
 * Advisory export — pure rendering of an {@link AdvisoryRecord} to shareable formats.
 *
 * Two formats, no I/O and no secrets:
 *  - `renderAdvisoryMarkdown` → a complete, professional advisory document.
 *  - `renderAdvisoryJson` → stable machine-readable JSON (analyst overrides applied).
 *
 * Analyst overrides (title, severity, severity note, summary, notes) always win over the generated
 * content, so an exported advisory matches what the analyst approved, not the raw regeneration.
 */
import type {
  AdvisoryContent,
  AdvisoryRecord,
  AdvisorySeverity,
  SourceCitation,
} from "./types.ts";

const SEVERITY_LABEL: Record<AdvisorySeverity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

// --- effective (override-aware) accessors -----------------------------------

export function effectiveTitle(record: AdvisoryRecord): string {
  return record.overrides.title?.trim() || record.content.title;
}

export function effectiveSeverity(record: AdvisoryRecord): AdvisorySeverity {
  return record.overrides.severity ?? record.content.severity;
}

export function effectiveSummary(record: AdvisoryRecord): string {
  return record.overrides.summary?.trim() || record.content.summary;
}

/** A filesystem-safe export name, e.g. `ADV-2026-0001.md`. */
export function advisoryExportFilename(record: AdvisoryRecord, ext: "md" | "json"): string {
  const base = (record.number || record.id || "advisory").replace(/[^A-Za-z0-9._-]+/g, "-");
  return `${base}.${ext}`;
}

// --- small formatting helpers ------------------------------------------------

function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "—";
  return new Date(t).toISOString().slice(0, 10);
}

/** Escape the pipe and newline characters that would break a Markdown table cell. */
function cell(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\r?\n/g, " ").trim();
}

function citeShort(citations: SourceCitation[]): string {
  if (!citations || citations.length === 0) return "—";
  const first = citations[0];
  const who = [first.publisher, fmtDate(first.publishedAt)].filter((p) => p && p !== "—").join(", ");
  const extra = citations.length > 1 ? ` (+${citations.length - 1} more)` : "";
  return `${who || first.title}${extra}`;
}

function heading(lines: string[], text: string): void {
  lines.push("", `## ${text}`, "");
}

// --- Markdown ----------------------------------------------------------------

export function renderAdvisoryMarkdown(record: AdvisoryRecord): string {
  const c: AdvisoryContent = record.content;
  const lines: string[] = [];
  const title = effectiveTitle(record);
  const severity = effectiveSeverity(record);
  const summary = effectiveSummary(record);

  lines.push(`# ${record.number} — ${title}`);
  lines.push("");

  // Metadata table.
  lines.push("| Field | Value |", "| --- | --- |");
  lines.push(`| TLP | ${record.tlp} |`);
  lines.push(`| Severity | ${SEVERITY_LABEL[severity]} |`);
  lines.push(`| Status | ${record.status} |`);
  lines.push(`| Subject | ${cell(`${c.subject.name} (${c.subject.kind})`)} |`);
  lines.push(`| Created | ${fmtDate(record.createdAt)} |`);
  lines.push(`| Updated | ${fmtDate(record.updatedAt)} |`);
  if (c.attackVersion) lines.push(`| ATT&CK version | ${c.attackVersion} |`);

  // BLUF.
  heading(lines, "Summary");
  lines.push(summary || "_No summary available._");

  if (record.overrides.severityNote?.trim()) {
    lines.push("", `**Severity note:** ${record.overrides.severityNote.trim()}`);
  } else if (c.severityReasons.length > 0) {
    lines.push("", `**Severity basis:** ${c.severityReasons.join("; ")}`);
  }

  if (c.keyPoints.length > 0) {
    heading(lines, "Key points");
    for (const p of c.keyPoints) lines.push(`- ${p}`);
  }

  // Activity.
  heading(lines, "Activity");
  lines.push(`- First seen: ${fmtDate(c.activity.firstSeen)}`);
  lines.push(`- Last seen: ${fmtDate(c.activity.lastSeen)}`);
  lines.push(`- Reports: ${c.activity.reports}`);
  if (c.activity.publishers.length > 0) {
    lines.push(`- Publishers: ${c.activity.publishers.join(", ")}`);
  }

  // Behaviours (ATT&CK).
  if (c.behaviours.length > 0) {
    heading(lines, "Observed behaviours (MITRE ATT&CK)");
    lines.push("| Technique | Tactic | Evidence | In scope | Sources |", "| --- | --- | --- | --- | --- |");
    const scope = new Set(record.scope);
    for (const b of c.behaviours) {
      const evidence = [
        b.observedIn ? `${b.observedIn} observed` : "",
        b.inferredIn ? `${b.inferredIn} inferred` : "",
        b.mappedIn ? `${b.mappedIn} mapped` : "",
      ]
        .filter(Boolean)
        .join(", ") || "—";
      const inScope = scope.has(b.techniqueId) ? "yes" : b.inPath ? "path" : "—";
      lines.push(
        `| ${cell(`${b.techniqueId} ${b.name}`)} | ${cell(b.tactic)} | ${cell(evidence)} | ${inScope} | ${cell(citeShort(b.citations))} |`,
      );
    }
  }

  if (c.attackOnlyBehaviours.length > 0) {
    heading(lines, "ATT&CK-attributed techniques without library evidence");
    for (const b of c.attackOnlyBehaviours) {
      lines.push(`- ${b.techniqueId} ${b.name} (${b.tactic})`);
    }
  }

  // Targeting.
  if (c.targeting.length > 0) {
    heading(lines, "Targeting");
    lines.push("| Target | Type | Status | Reports |", "| --- | --- | --- | --- |");
    for (const t of c.targeting) {
      lines.push(`| ${cell(t.value)} | ${cell(t.kind)} | ${cell(t.status)} | ${t.reports} |`);
    }
  }

  // Vulnerabilities.
  if (c.vulnerabilities.length > 0) {
    heading(lines, "Vulnerabilities");
    for (const v of c.vulnerabilities) {
      const kev = v.kev
        ? ` — CISA KEV: ${v.kev.vendor} ${v.kev.product} (added ${fmtDate(v.kev.dateAdded)}${v.kev.dueDate ? `, due ${fmtDate(v.kev.dueDate)}` : ""})`
        : "";
      lines.push(`- **${v.cveId}**${kev} — ${citeShort(v.citations)}`);
    }
  }

  // Indicators.
  if (c.indicators.length > 0) {
    heading(lines, `Indicators of compromise (${c.indicatorTotal})`);
    lines.push("| Type | Indicator | Role | First seen |", "| --- | --- | --- | --- |");
    for (const ind of c.indicators) {
      lines.push(`| ${cell(ind.kind)} | \`${cell(ind.display)}\` | ${cell(ind.role || "—")} | ${fmtDate(ind.firstSeen)} |`);
    }
    if (c.indicatorTotal > c.indicators.length) {
      lines.push("", `_Showing ${c.indicators.length} of ${c.indicatorTotal} indicators._`);
    }
  }

  // Detection guidance.
  if (c.detections.length > 0) {
    heading(lines, "Detection guidance");
    for (const d of c.detections) {
      lines.push(`### ${d.techniqueId} ${d.name}`);
      lines.push(`- Tactic: ${d.tactic}`);
      if (d.telemetry.length > 0) lines.push(`- Telemetry: ${d.telemetry.join(", ")}`);
      lines.push(`- Hypothesis: ${d.hypothesis}`);
      lines.push("- Query (template — validate before use):");
      lines.push("", "```", d.queryTemplate, "```", "");
    }
  }

  // Recommendations.
  if (c.recommendations.length > 0) {
    heading(lines, "Recommendations");
    for (const r of c.recommendations) {
      if (r.kind === "patch") {
        lines.push(`- **Patch ${r.cveId}** — ${r.action}${r.dueDate ? ` (due ${fmtDate(r.dueDate)}, ${r.source})` : ` (${r.source})`}`);
      } else if (r.kind === "attack_mitigation") {
        lines.push(`- **${r.id} ${r.name}** — ${r.description} (${r.techniques.join(", ")})`);
      } else {
        lines.push(`- ${r.text} — ${citeShort([r.citation])}`);
      }
    }
  }

  // Gaps.
  if (c.gaps.length > 0) {
    heading(lines, "Intelligence gaps");
    for (const g of c.gaps) lines.push(`- [${g.impact}] ${g.text}`);
  }

  // Analyst notes.
  if (record.overrides.notes?.trim()) {
    heading(lines, "Analyst notes");
    lines.push(record.overrides.notes.trim());
  }

  // Sources.
  if (c.sources.length > 0) {
    heading(lines, "Sources");
    c.sources.forEach((s, i) => {
      const date = fmtDate(s.publishedAt);
      const url = s.url ? ` <${s.url}>` : "";
      lines.push(`${i + 1}. ${s.title} — ${s.publisher}${date !== "—" ? `, ${date}` : ""}${url}`);
    });
  }

  lines.push("", "---", "");
  lines.push(
    `_Generated ${fmtDate(c.generatedAt)} from public CTI. TLP:${record.tlp}. Detection queries are templates and must be validated before production use._`,
  );

  return lines.join("\n");
}

// --- JSON --------------------------------------------------------------------

/** Structured export object with analyst overrides applied over the generated content. */
export function advisoryToExportObject(record: AdvisoryRecord): {
  number: string;
  status: AdvisoryRecord["status"];
  tlp: AdvisoryRecord["tlp"];
  title: string;
  severity: AdvisorySeverity;
  summary: string;
  createdAt: string;
  updatedAt: string;
  subject: AdvisoryContent["subject"];
  scope: string[];
  content: AdvisoryContent;
} {
  return {
    number: record.number,
    status: record.status,
    tlp: record.tlp,
    title: effectiveTitle(record),
    severity: effectiveSeverity(record),
    summary: effectiveSummary(record),
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    subject: record.content.subject,
    scope: record.scope,
    content: record.content,
  };
}

export function renderAdvisoryJson(record: AdvisoryRecord): string {
  return JSON.stringify(advisoryToExportObject(record), null, 2);
}
