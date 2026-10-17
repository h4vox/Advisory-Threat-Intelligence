/** Field syntax the engine understands (shown as hints and offered on focus). */
export const SYNTAX_HINTS: Array<{ field: string; example: string; help: string }> = [
  { field: "actor:", example: 'actor:"Cozy Bear"', help: "Threat actor or alias (filter)" },
  { field: "malware:", example: "malware:BRICKSTORM", help: "Malware or tool" },
  { field: "campaign:", example: "campaign:C0024", help: "ATT&CK campaign" },
  { field: "technique:", example: "technique:T1003.001", help: "Technique id or name" },
  { field: "tactic:", example: "tactic:lateral-movement", help: "ATT&CK tactic" },
  { field: "cve:", example: "cve:CVE-2024-3400", help: "Vulnerability id" },
  { field: "type:", example: "type:advisory,dfir", help: "Document type" },
  { field: "tier:", example: "tier:1,2", help: "Source tier 1–4" },
  { field: "publisher:", example: "publisher:microsoft", help: "Publisher contains" },
  { field: "since:", example: "since:2025-06", help: "Published on or after" },
  { field: "until:", example: "until:2024", help: "Published on or before" },
  { field: "has:", example: "has:iocs", help: "iocs, emulation or evidence" },
  { field: '"…"', example: '"living off the land"', help: "Exact phrase" },
  { field: "-", example: "-phishing", help: "Exclude a word or phrase" },
];

