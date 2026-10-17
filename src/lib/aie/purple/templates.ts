/**
 * Wording templates for simulation objects and hunting hypotheses (spec §33, §36).
 *
 * Everything here is generic per tactic / technique and built from ATT&CK facts. Nothing invents
 * indicators, commands or tooling: execution detail only ever comes from a synced emulation library.
 */
import type { KbTechnique, RiskLevel } from "./types.ts";

type TacticTemplate = {
  verb: string;
  prerequisites: string[];
  cleanup: string[];
};

const BASE_PREREQS = ["Written authorisation and an agreed test window", "Isolated lab or approved test segment with endpoint and log telemetry enabled"];
const BASE_CLEANUP = ["Stop any test processes and delete files the test created", "Record what ran, when and on which host, for the detection review"];

const TACTIC_TEMPLATES: Record<string, TacticTemplate> = {
  Reconnaissance: {
    verb: "gathering information about the target",
    prerequisites: ["Scope limited to assets the test team owns"],
    cleanup: [],
  },
  "Resource Development": {
    verb: "staging infrastructure or capabilities",
    prerequisites: ["Test-owned infrastructure (domains, hosts, accounts) registered for the exercise"],
    cleanup: ["Decommission test infrastructure created for the exercise"],
  },
  "Initial Access": {
    verb: "gaining a first foothold",
    prerequisites: ["A designated entry point (test mailbox, exposed lab service or test account) agreed with the owner"],
    cleanup: ["Disable test accounts and remove any access granted for the exercise"],
  },
  Execution: {
    verb: "running adversary-controlled code",
    prerequisites: ["Lab host with process creation and script logging enabled"],
    cleanup: [],
  },
  Persistence: {
    verb: "keeping access across restarts or credential changes",
    prerequisites: ["Snapshot of the lab host taken before the test"],
    cleanup: ["Remove every persistence artefact created (services, tasks, run keys, accounts) and confirm removal"],
  },
  "Privilege Escalation": {
    verb: "gaining higher-level permissions",
    prerequisites: ["Low-privileged test account on the lab host", "Snapshot of the lab host taken before the test"],
    cleanup: ["Revert permission or group changes and restore the snapshot if the host changed"],
  },
  "Defense Evasion": {
    verb: "avoiding detection",
    prerequisites: ["Snapshot of the lab host taken before the test"],
    cleanup: ["Restore any security setting the test changed and confirm sensors report again"],
  },
  Stealth: {
    verb: "hiding activity from defenders",
    prerequisites: ["Baseline of normal activity on the lab host"],
    cleanup: ["Remove renamed, hidden or obfuscated test artefacts"],
  },
  "Defense Impairment": {
    verb: "weakening or disabling defences",
    prerequisites: ["Disposable lab host; security team on standby to re-enable controls", "Snapshot of the lab host taken before the test"],
    cleanup: ["Re-enable every control the test touched and confirm sensors report again", "Restore the host from snapshot"],
  },
  "Credential Access": {
    verb: "obtaining account credentials",
    prerequisites: ["Seeded test accounts with non-production credentials"],
    cleanup: ["Delete any credential material captured", "Rotate or disable the test credentials used"],
  },
  Discovery: {
    verb: "learning about the environment",
    prerequisites: ["Domain-joined or representative lab host"],
    cleanup: [],
  },
  "Lateral Movement": {
    verb: "moving between systems",
    prerequisites: ["Two or more lab hosts in the same segment or domain", "Test account with access to the destination host"],
    cleanup: ["Remove remote sessions, services or shares created on the destination host"],
  },
  Collection: {
    verb: "gathering data of interest",
    prerequisites: ["Synthetic test data in place of real business data"],
    cleanup: ["Delete staged archives and collected test data"],
  },
  "Command and Control": {
    verb: "communicating with controlled systems",
    prerequisites: ["Test-owned destination approved for outbound traffic from the lab"],
    cleanup: ["Stop the channel and remove agents or tunnels the test installed"],
  },
  Exfiltration: {
    verb: "moving data out of the environment",
    prerequisites: ["Synthetic test data only", "Test-owned destination approved for outbound transfer"],
    cleanup: ["Delete transferred test data from the destination"],
  },
  Impact: {
    verb: "disrupting availability or integrity",
    prerequisites: ["Disposable lab host restored from snapshot afterwards", "Explicit sign-off for impact testing"],
    cleanup: ["Restore the host from snapshot and confirm services recover"],
  },
};

export function tacticTemplate(tactic: string): TacticTemplate {
  return TACTIC_TEMPLATES[tactic] ?? { verb: "adversary behaviour", prerequisites: [], cleanup: [] };
}

export function prerequisitesFor(tactic: string, platforms: string[]): string[] {
  const t = tacticTemplate(tactic);
  const host = platforms.length ? [`Target platform available in the lab: ${platforms.join(", ")}`] : [];
  return [...BASE_PREREQS, ...host, ...t.prerequisites];
}

export function cleanupFor(tactic: string): string[] {
  return [...tacticTemplate(tactic).cleanup, ...BASE_CLEANUP];
}

// ---------------------------------------------------------------------------------------------
// Risk heuristic
// ---------------------------------------------------------------------------------------------

const HIGH_RISK_TACTICS = new Set(["Impact", "Exfiltration", "Defense Impairment"]);
const MEDIUM_RISK_TACTICS = new Set(["Lateral Movement", "Persistence", "Privilege Escalation", "Credential Access", "Initial Access", "Command and Control", "Defense Evasion"]);
/** Technique families that are destructive or touch real secrets regardless of tactic. */
const HIGH_RISK_PREFIXES = ["T1003", "T1485", "T1486", "T1490", "T1489", "T1561", "T1529", "T1491", "T1531", "T1495", "T1499", "T1498", "T1562", "T1070"];
const HIGH_RISK_NAME = /credential dumping|data destruction|wipe|encrypted for impact|inhibit system recovery|impair defenses|disable or modify|indicator removal/i;

export function riskFor(t: Pick<KbTechnique, "id" | "name">, tactic: string): { level: RiskLevel; reason: string } {
  const base = t.id.split(".")[0];
  if (HIGH_RISK_PREFIXES.includes(base) || HIGH_RISK_NAME.test(t.name)) {
    return { level: "high", reason: "Destructive, defence-impairing or credential-dumping technique; run only on a disposable lab host" };
  }
  if (HIGH_RISK_TACTICS.has(tactic)) {
    return { level: "high", reason: `${tactic} can cause lasting damage or data loss; use synthetic data and a disposable host` };
  }
  if (MEDIUM_RISK_TACTICS.has(tactic)) {
    return { level: "medium", reason: `${tactic} changes host or account state; needs cleanup and a snapshot` };
  }
  return { level: "low", reason: `${tactic || "This"} activity is largely read-only and leaves little lasting change` };
}

// ---------------------------------------------------------------------------------------------
// Hunting query skeletons (always templates)
// ---------------------------------------------------------------------------------------------

type FieldFamily = { match: RegExp; source: string; fields: string[] };
const FIELD_FAMILIES: FieldFamily[] = [
  { match: /process|command|script|module|os api/i, source: "process_events", fields: ["host", "user", "process_name", "parent_process_name", "command_line"] },
  { match: /network|traffic|connection|flow/i, source: "network_events", fields: ["src_host", "dst_ip", "dst_port", "protocol", "bytes_out"] },
  { match: /file/i, source: "file_events", fields: ["host", "user", "file_path", "action", "process_name"] },
  { match: /registry/i, source: "registry_events", fields: ["host", "user", "registry_key", "registry_value", "process_name"] },
  { match: /logon|authentication|account|credential|session|user/i, source: "authentication_events", fields: ["account", "src_host", "dst_host", "logon_type", "result"] },
  { match: /service|scheduled job|task/i, source: "service_events", fields: ["host", "service_name", "image_path", "user"] },
  { match: /cloud|instance|storage|application log|api/i, source: "cloud_audit_events", fields: ["principal", "operation", "resource", "source_ip"] },
];

export function querySkeleton(t: Pick<KbTechnique, "id" | "name">, telemetry: string[]): string {
  const fam = FIELD_FAMILIES.find((f) => telemetry.some((d) => f.match.test(d))) ?? {
    source: "security_events",
    fields: ["host", "user", "event_name"],
  };
  return [
    "-- TEMPLATE: query skeleton only. Map table and field names to your SIEM/EDR before use.",
    `-- Technique: ${t.id} ${t.name}`,
    `-- Telemetry: ${telemetry.length ? telemetry.join(", ") : "not listed in ATT&CK"}`,
    `SELECT ${["timestamp", ...fam.fields].join(", ")}`,
    `FROM ${fam.source}`,
    `WHERE <condition describing ${t.name} behaviour>`,
    "  AND timestamp > now() - interval '30 days'",
    "ORDER BY timestamp DESC;",
  ].join("\n");
}
