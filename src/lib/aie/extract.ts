import type { IocHit, QualityReason } from "./types";
export { formatDateTime, toIsoString } from "./format";

export const MAX_BYTES = 1_500_000;

function rightRotate(value: number, amount: number): number {
  return (value >>> amount) | (value << (32 - amount));
}

export function sha256Hex(input: string | Uint8Array): string {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];

  let H0 = 0x6a09e667, H1 = 0xbb67ae85, H2 = 0x3c6ef372, H3 = 0xa54ff53a;
  let H4 = 0x510e527f, H5 = 0x9b05688c, H6 = 0x1f83d9ab, H7 = 0x5be0cd19;

  const bitLength = bytes.length * 8;
  const newByteLength = (((bytes.length + 8) >> 6) + 1) << 6;
  const padded = new Uint8Array(newByteLength);
  padded.set(bytes);
  padded[bytes.length] = 0x80;

  const view = new DataView(padded.buffer);
  view.setUint32(newByteLength - 4, bitLength, false);

  const W = new Uint32Array(64);

  for (let i = 0; i < newByteLength; i += 64) {
    for (let t = 0; t < 16; t++) {
      W[t] = view.getUint32(i + t * 4, false);
    }
    for (let t = 16; t < 64; t++) {
      const s0 = rightRotate(W[t - 15], 7) ^ rightRotate(W[t - 15], 18) ^ (W[t - 15] >>> 3);
      const s1 = rightRotate(W[t - 2], 17) ^ rightRotate(W[t - 2], 19) ^ (W[t - 2] >>> 10);
      W[t] = (W[t - 16] + s0 + W[t - 7] + s1) | 0;
    }

    let a = H0, b = H1, c = H2, d = H3, e = H4, f = H5, g = H6, h = H7;

    for (let t = 0; t < 64; t++) {
      const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[t] + W[t]) | 0;
      const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) | 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) | 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) | 0;
    }

    H0 = (H0 + a) | 0;
    H1 = (H1 + b) | 0;
    H2 = (H2 + c) | 0;
    H3 = (H3 + d) | 0;
    H4 = (H4 + e) | 0;
    H5 = (H5 + f) | 0;
    H6 = (H6 + g) | 0;
    H7 = (H7 + h) | 0;
  }

  return [H0, H1, H2, H3, H4, H5, H6, H7]
    .map((h) => (h >>> 0).toString(16).padStart(8, "0"))
    .join("");
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

export function decodeEntities(s: string): string {
  if (!s) return "";
  return s
    .replace(/&#x([0-9a-fA-F]+);/g, (_, n) => {
      try {
        return String.fromCodePoint(parseInt(n, 16));
      } catch {
        return "";
      }
    })
    .replace(/&#([0-9]+);/g, (_, n) => {
      try {
        return String.fromCodePoint(parseInt(n, 10));
      } catch {
        return "";
      }
    })
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#39;/g, "'")
    .replace(/&lsquo;/g, "‘")
    .replace(/&rsquo;/g, "’")
    .replace(/&ldquo;/g, "“")
    .replace(/&rdquo;/g, "”")
    .replace(/&mdash;/g, "—")
    .replace(/&ndash;/g, "–")
    .replace(/&hellip;/g, "…")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&");
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

