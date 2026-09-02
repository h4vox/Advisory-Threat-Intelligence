import { createHash } from "node:crypto";
import type { IocHit, QualityReason } from "./types";

export const MAX_BYTES = 1_500_000;

export function sha256Hex(input: string | Uint8Array): string {
  return createHash("sha256").update(input).digest("hex");
}

export function canonicalizeUrl(raw: string): string {
  const u = new URL(raw.trim());
  u.hash = "";
  if (u.pathname.endsWith("/") && u.pathname.length > 1) {
    u.pathname = u.pathname.slice(0, -1);
  }
  u.hostname = u.hostname.toLowerCase();
  return u.toString();
}

export function htmlToText(html: string): { title: string; text: string } {
  const title =
    html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1]?.replace(/\s+/g, " ").trim() ??
    html.match(/<h1[^>]*>([\s\S]*?)<\/h1>/i)?.[1]?.replace(/<[^>]+>/g, "").replace(/\s+/g, " ").trim() ??
    "Untitled report";

  const stripped = html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<noscript[\s\S]*?<\/noscript>/gi, " ")
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<(nav|footer|header|aside|form|svg|iframe)[\s\S]*?<\/\1>/gi, " ")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(p|div|h1|h2|h3|h4|li|tr|section|article)>/gi, "\n")
    .replace(/<li[^>]*>/gi, "• ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&/g, "&")
    .replace(/</g, "<")
    .replace(/>/g, ">")
    .replace(/"/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .replace(/[ \t]{2,}/g, " ")
    .trim();

  return { title: decodeEntities(title).slice(0, 240), text: decodeEntities(stripped) };
}

function decodeEntities(s: string): string {
  return s.replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)));
}

const TECH_RE = /\bT1[0-9]{3}(?:\.[0-9]{3})?\b/g;
const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;
const SHA256_RE = /\b[a-fA-F0-9]{64}\b/g;
const MD5_RE = /\b[a-fA-F0-9]{32}\b/g;
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;

export function harvestIocs(text: string): IocHit[] {
  const seen = new Set<string>();
  const out: IocHit[] = [];
  const push = (kind: IocHit["kind"], value: string) => {
    const key = `${kind}:${value.toLowerCase()}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ kind, value });
  };

  for (const m of text.match(CVE_RE) ?? []) push("cve", m.toUpperCase());
  for (const m of text.match(TECH_RE) ?? []) push("technique", m.toUpperCase());
  for (const m of text.match(SHA256_RE) ?? []) {
    if (!/^[0]+$/.test(m) && !/^[fF]+$/.test(m)) push("sha256", m.toLowerCase());
  }
  for (const m of text.match(MD5_RE) ?? []) {
    if (m.length === 32) push("md5", m.toLowerCase());
  }
  for (const m of text.match(IPV4_RE) ?? []) {
    if (!m.startsWith("0.") && !m.startsWith("127.") && !m.startsWith("255.")) {
      push("ipv4", m);
    }
  }
  return out.slice(0, 80);
}

const SIGNAL_WORDS = [
  "ransomware",
  "credential",
  "lateral movement",
  "persistence",
  "command and control",
  "exfiltration",
  "initial access",
  "privilege escalation",
  "defense evasion",
  "att&ck",
  "mitre",
  "powershell",
  "mimikatz",
  "ntds.dit",
  "rdp",
  "cobalt strike",
  "c2",
  "ioc",
  "ttp",
];

export function scoreQuality(text: string, title: string): {
  score: number;
  reasons: QualityReason[];
  wordCount: number;
} {
  const reasons: QualityReason[] = [];
  const body = `${title}\n${text}`.toLowerCase();
  const wordCount = text.split(/\s+/).filter(Boolean).length;

  if (wordCount >= 2500) reasons.push({ label: "Long-form technical depth", delta: 0.28 });
  else if (wordCount >= 1200) reasons.push({ label: "Substantial article length", delta: 0.2 });
  else if (wordCount >= 500) reasons.push({ label: "Minimum length met", delta: 0.1 });
  else reasons.push({ label: "Short document", delta: -0.15 });

  const hits = SIGNAL_WORDS.filter((w) => body.includes(w));
  if (hits.length >= 8) reasons.push({ label: `Dense adversary vocabulary (${hits.length})`, delta: 0.28 });
  else if (hits.length >= 4) reasons.push({ label: `Relevant threat terms (${hits.length})`, delta: 0.18 });
  else if (hits.length >= 2) reasons.push({ label: "Some threat terms", delta: 0.08 });
  else reasons.push({ label: "Weak threat vocabulary", delta: -0.12 });

  if (/\bstage\s*[123]|infection chain|attack chain|kill chain/i.test(body)) {
    reasons.push({ label: "Named stages / attack chain language", delta: 0.16 });
  }
  if (/\bT1\d{3}\b/.test(text) || /att&ck/.test(body)) {
    reasons.push({ label: "ATT&CK identifiers present", delta: 0.12 });
  }
  if (/CVE-\d{4}-\d+/.test(text)) {
    reasons.push({ label: "CVE references", delta: 0.08 });
  }

  const score = Math.max(0, Math.min(1, reasons.reduce((s, r) => s + r.delta, 0.25)));
  return { score: Math.round(score * 100) / 100, reasons, wordCount };
}

export function excerptOf(text: string, n = 220): string {
  const t = text.replace(/\s+/g, " ").trim();
  return t.length <= n ? t : `${t.slice(0, n).trim()}…`;
}

export function toIsoString(val: unknown): string | null {
  if (!val) return null;
  if (val instanceof Date) return val.toISOString();
  return String(val);
}

export function formatDateTime(val: unknown, fallback = "—"): string {
  if (!val) return fallback;
  if (val instanceof Date) return val.toISOString().replace("T", " ").slice(0, 16);
  const s = String(val);
  return s.replace("T", " ").slice(0, 16);
}

