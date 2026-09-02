import type { AttackStep, IntelAnalysis, IocHit } from "./types";
import { decodeEntities } from "./extract";

export type DocumentPrintMetadata = {
  id: string;
  title: string;
  url: string;
  canonicalUrl: string;
  publisher: string;
  author: string;
  publishedAt: string | null;
  ingestedAt: string;
  classification: string;
  rawHash: string;
  textHash: string;
  qualityScore: number;
  wordCount: number;
  iocs: IocHit[];
  analysis?: IntelAnalysis | null;
};

export function extractMainContentHtml(rawHtml: string, baseUrl?: string): string {
  if (!rawHtml || rawHtml.trim().length === 0) return "";

  // Check if input contains HTML markup (tags like <p>, <div>, <article>, <img>, <blockquote>, etc.)
  const isHtml = /<[a-z][\s\S]*>/i.test(rawHtml) || /<(?:p|div|article|main|section|blockquote|img|table|h[1-6]|ul|ol|li|pre|code|a|strong|em)\b/i.test(rawHtml);

  if (!isHtml) {
    // Plain text: decode entities and wrap as styled paragraphs
    return `
      <div class="content-body">
        ${decodeEntities(rawHtml)
          .split(/\n\n+/)
          .map((p) => `<p>${escapeHtml(p.trim())}</p>`)
          .join("\n")}
      </div>
    `;
  }

  // Remove scripts, styles, iframes, and noisy UI elements
  let cleaned = rawHtml
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "")
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, "")
    .replace(/<noscript\b[^<]*(?:(?!<\/noscript>)<[^<]*)*<\/noscript>/gi, "")
    .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, "")
    .replace(/<svg\b[^<]*(?:(?!<\/svg>)<[^<]*)*<\/svg>/gi, "")
    .replace(/<(?:nav|header|footer|aside|form)\b[^<]*(?:(?!<\/(?:nav|header|footer|aside|form)>)<[^<]*)*<\/(?:nav|header|footer|aside|form)>/gi, "");

  // Match main content container if full page was provided
  let mainBody = "";
  const articleMatch = cleaned.match(/<article[^>]*>([\s\S]*?)<\/article>/i);
  if (articleMatch && articleMatch[1].length > 300) {
    mainBody = articleMatch[1];
  }

  if (!mainBody) {
    const mainMatch = cleaned.match(/<main[^>]*>([\s\S]*?)<\/main>/i);
    if (mainMatch && mainMatch[1].length > 300) {
      mainBody = mainMatch[1];
    }
  }

  if (!mainBody) {
    const postMatch = cleaned.match(
      /<div[^>]*class=["'][^"']*(?:entry-content|post-content|article-content|gh-content|post-body|c-blog-post|single-content|rich-text|post-full-content)[^"']*["'][^>]*>([\s\S]*?)<\/div>/i,
    );
    if (postMatch && postMatch[1].length > 300) {
      mainBody = postMatch[1];
    }
  }

  if (!mainBody) {
    const bodyMatch = cleaned.match(/<body[^>]*>([\s\S]*?)<\/body>/i);
    if (bodyMatch && bodyMatch[1].length > 200) {
      mainBody = bodyMatch[1];
    } else {
      mainBody = cleaned;
    }
  }

  // Decode stray entities in the HTML text (like &#x2019; -> ’)
  mainBody = decodeEntities(mainBody);

  // Resolve relative images and links if baseUrl is provided
  if (baseUrl) {
    try {
      const base = new URL(baseUrl);
      mainBody = mainBody
        .replace(/<img\b([^>]*?)\bsrc=["']([^"']+)["']/gi, (match, attrs, src) => {
          try {
            const abs = new URL(src, base).href;
            return `<img${attrs}src="${abs}" loading="lazy"`;
          } catch {
            return match;
          }
        })
        .replace(/<a\b([^>]*?)\bhref=["']([^"']+)["']/gi, (match, attrs, href) => {
          try {
            const abs = new URL(href, base).href;
            return `<a${attrs}href="${abs}" target="_blank" rel="noreferrer"`;
          } catch {
            return match;
          }
        });
    } catch {
      /* ignore */
    }
  }

  return mainBody;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export function buildPristineDocumentHtml(
  rawContentOrHtml: string,
  meta: DocumentPrintMetadata,
): string {
  const mainContent = extractMainContentHtml(rawContentOrHtml, meta.canonicalUrl);

  const iocRows = meta.iocs.slice(0, 30).map(
    (ioc) => `
      <tr>
        <td class="ioc-kind"><code>${escapeHtml(ioc.kind)}</code></td>
        <td class="ioc-val"><code>${escapeHtml(ioc.value)}</code></td>
      </tr>
    `,
  ).join("");

  const threatActors = meta.analysis?.threatActors?.length
    ? meta.analysis.threatActors.map((a) => `<span class="tag tag-actor">${escapeHtml(a)}</span>`).join(" ")
    : '<span class="text-muted">Unattributed / Not Specified</span>';

  const malware = meta.analysis?.malware?.length
    ? meta.analysis.malware.map((m) => `<span class="tag tag-malware">${escapeHtml(m)}</span>`).join(" ")
    : '<span class="text-muted">None Identified</span>';

  const attackSteps = meta.analysis?.attackChain?.length
    ? meta.analysis.attackChain.map((s) => `
        <div class="step-card">
          <div class="step-num">${s.order}</div>
          <div class="step-details">
            <div class="step-tactic">${escapeHtml(s.tactic)}</div>
            <div class="step-summary">${escapeHtml(s.summary)}</div>
            <div class="step-techs">
              ${s.techniques.map((t) => `<span class="tag tag-tech">${escapeHtml(t)}</span>`).join(" ")}
            </div>
          </div>
        </div>
      `).join("")
    : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${escapeHtml(meta.title)} - Threat Intelligence Report</title>
  <style>
    @page {
      size: A4 portrait;
      margin: 1.6cm 1.4cm 1.8cm 1.4cm;
      @bottom-right {
        content: "Page " counter(page) " of " counter(pages);
        font-family: monospace;
        font-size: 8pt;
        color: #666;
      }
    }

    * {
      box-sizing: border-box;
      -webkit-print-color-adjust: exact;
      print-color-adjust: exact;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      font-size: 10pt;
      line-height: 1.55;
      color: #1a1a1a;
      background: #ffffff;
      margin: 0;
      padding: 24px;
    }

    .report-container {
      max-width: 900px;
      margin: 0 auto;
    }

    /* Executive Header Banner */
    .header-banner {
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 18px 22px;
      background: #f8fafc;
      margin-bottom: 24px;
    }

    .meta-top {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 10px;
    }

    .badge {
      display: inline-block;
      font-family: monospace;
      font-size: 8pt;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      padding: 3px 8px;
      border-radius: 4px;
      border: 1px solid #cbd5e1;
      background: #ffffff;
    }

    .badge-class {
      background: #e0f2fe;
      color: #0369a1;
      border-color: #bae6fd;
    }

    .doc-title {
      font-size: 18pt;
      font-weight: 700;
      line-height: 1.25;
      color: #0f172a;
      margin: 8px 0 12px 0;
    }

    .meta-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 8px 16px;
      font-size: 8pt;
      font-family: monospace;
      color: #475569;
      border-top: 1px solid #e2e8f0;
      padding-top: 12px;
      margin-top: 12px;
    }

    .meta-item b {
      color: #1e293b;
      font-weight: 600;
    }

    .provenance-box {
      font-size: 7.5pt;
      font-family: monospace;
      background: #f1f5f9;
      border-radius: 4px;
      padding: 8px 12px;
      margin-top: 12px;
      word-break: break-all;
      color: #334155;
    }

    /* Threat Intel Summary Section */
    .section-title {
      font-size: 12pt;
      font-weight: 700;
      color: #0f172a;
      border-bottom: 2px solid #0f172a;
      padding-bottom: 4px;
      margin: 24px 0 12px 0;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .intel-summary {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
      margin-bottom: 20px;
    }

    .intel-card {
      border: 1px solid #e2e8f0;
      border-radius: 6px;
      padding: 10px 14px;
      background: #ffffff;
    }

    .intel-card h4 {
      margin: 0 0 6px 0;
      font-size: 8pt;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: #64748b;
    }

    .tag {
      display: inline-block;
      font-size: 7.5pt;
      font-family: monospace;
      padding: 2px 6px;
      border-radius: 3px;
      margin: 2px 2px 2px 0;
    }

    .tag-actor { background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; font-weight: 600; }
    .tag-malware { background: #fef3c7; color: #92400e; border: 1px solid #fde68a; font-weight: 600; }
    .tag-tech { background: #f1f5f9; color: #334155; border: 1px solid #cbd5e1; }

    /* Attack Chain Steps */
    .step-card {
      display: flex;
      gap: 12px;
      border: 1px solid #e2e8f0;
      border-left: 4px solid #0284c7;
      border-radius: 4px;
      padding: 10px 14px;
      margin-bottom: 8px;
      background: #fafafa;
      page-break-inside: avoid;
    }

    .step-num {
      width: 24px;
      height: 24px;
      border-radius: 50%;
      background: #0284c7;
      color: #ffffff;
      font-size: 9pt;
      font-weight: bold;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }

    .step-details { flex: 1; }
    .step-tactic { font-weight: 700; font-size: 9pt; color: #0f172a; margin-bottom: 2px; }
    .step-summary { font-size: 8.5pt; color: #475569; margin-bottom: 6px; }

    /* IOC Table */
    .ioc-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 8pt;
      margin-bottom: 20px;
    }

    .ioc-table th {
      background: #f1f5f9;
      border: 1px solid #cbd5e1;
      padding: 6px 10px;
      text-align: left;
      font-family: monospace;
      text-transform: uppercase;
    }

    .ioc-table td {
      border: 1px solid #e2e8f0;
      padding: 5px 10px;
    }

    .ioc-kind { width: 120px; font-weight: 600; }
    .ioc-val { font-family: monospace; word-break: break-all; color: #0f172a; }

    /* Main Extracted Article Content */
    .content-body {
      font-size: 9.5pt;
      color: #1e293b;
      margin-top: 16px;
    }

    .content-body h1, .content-body h2, .content-body h3, .content-body h4 {
      color: #0f172a;
      margin-top: 18px;
      margin-bottom: 8px;
      page-break-after: avoid;
    }

    .content-body h2 { font-size: 13pt; border-bottom: 1px solid #e2e8f0; padding-bottom: 4px; }
    .content-body h3 { font-size: 11pt; }

    .content-body p {
      margin: 0 0 10px 0;
      line-height: 1.6;
    }

    .content-body pre {
      background: #0f172a;
      color: #f8fafc;
      font-family: "Cascadia Code", "Fira Code", Consolas, monospace;
      font-size: 8pt;
      padding: 12px 16px;
      border-radius: 6px;
      overflow-x: auto;
      margin: 12px 0;
      white-space: pre-wrap;
      word-break: break-all;
      page-break-inside: avoid;
    }

    .content-body code {
      font-family: monospace;
      background: #f1f5f9;
      color: #b91c1c;
      padding: 2px 4px;
      border-radius: 3px;
      font-size: 8.5pt;
    }

    .content-body pre code {
      background: transparent;
      color: inherit;
      padding: 0;
    }

    .content-body table {
      width: 100%;
      border-collapse: collapse;
      margin: 14px 0;
      font-size: 8pt;
      page-break-inside: avoid;
    }

    .content-body th, .content-body td {
      border: 1px solid #cbd5e1;
      padding: 6px 10px;
      text-align: left;
    }

    .content-body th { background: #f8fafc; font-weight: 600; }

    .content-body blockquote {
      border-left: 4px solid #0284c7;
      background: #f8fafc;
      margin: 14px 0;
      padding: 12px 18px;
      border-radius: 0 6px 6px 0;
      color: #334155;
      font-style: italic;
    }

    .content-body img {
      max-width: 100%;
      height: auto;
      border-radius: 6px;
      margin: 16px auto;
      display: block;
      box-shadow: 0 2px 8px rgba(0,0,0,0.08);
      page-break-inside: avoid;
    }

    .content-body ul, .content-body ol {
      margin: 10px 0 14px 24px;
      padding: 0;
    }

    .content-body li {
      margin-bottom: 6px;
      line-height: 1.6;
    }

    .content-body a {
      color: #0284c7;
      text-decoration: underline;
      word-break: break-word;
    }

    .content-body strong, .content-body b {
      color: #0f172a;
      font-weight: 600;
    }

    .content-body hr {
      border: none;
      border-top: 1px solid #e2e8f0;
      margin: 24px 0;
    }

    /* Print Specific Rules */
    @media print {
      body { padding: 0; }
      .no-print { display: none !important; }
      .header-banner { break-inside: avoid; }
    }
  </style>
</head>
<body>
  <div class="report-container">
    <!-- Executive Header Banner -->
    <div class="header-banner">
      <div class="meta-top">
        <div>
          <span class="badge badge-class">${escapeHtml(meta.classification)}</span>
          <span class="badge">${escapeHtml(meta.publisher || "Verified Publisher")}</span>
        </div>
        <span class="badge">EVIDENCE VERIFIED</span>
      </div>

      <div class="doc-title">${escapeHtml(meta.title)}</div>

      <div class="meta-grid">
        <div class="meta-item"><b>Source:</b> ${escapeHtml(meta.publisher)}</div>
        <div class="meta-item"><b>Published:</b> ${escapeHtml(meta.publishedAt || "Not specified")}</div>
        <div class="meta-item"><b>Acquired:</b> ${escapeHtml(meta.ingestedAt.slice(0, 16).replace("T", " "))}</div>
        <div class="meta-item"><b>Quality Gate:</b> ${Math.round(meta.qualityScore * 100)}%</div>
        <div class="meta-item"><b>Word Count:</b> ${meta.wordCount}</div>
        <div class="meta-item"><b>IOC Count:</b> ${meta.iocs.length}</div>
      </div>

      <div class="provenance-box">
        <div><b>Canonical URL:</b> ${escapeHtml(meta.canonicalUrl)}</div>
        <div><b>Raw SHA-256:</b> ${escapeHtml(meta.rawHash)}</div>
        <div><b>Text SHA-256:</b> ${escapeHtml(meta.textHash)}</div>
      </div>
    </div>

    <!-- Threat Intelligence Profile Summary -->
    <div class="section-title">Adversary & Attack Profile</div>
    <div class="intel-summary">
      <div class="intel-card">
        <h4>Attributed Adversary Groups / Threat Actors</h4>
        <div>${threatActors}</div>
      </div>
      <div class="intel-card">
        <h4>Malware Families & Offensive Toolsets</h4>
        <div>${malware}</div>
      </div>
    </div>

    <!-- Attack Chain Sequence (if reconstructed) -->
    ${meta.analysis?.attackChain?.length ? `
      <div class="section-title">Reconstructed Attack Chain Flow</div>
      <div class="attack-chain-box">
        ${attackSteps}
      </div>
    ` : ""}

    <!-- Harvested IOCs Table (if present) -->
    ${meta.iocs.length ? `
      <div class="section-title">Indicators of Compromise (IOC Harvest)</div>
      <table class="ioc-table">
        <thead>
          <tr>
            <th>Type</th>
            <th>Indicator Value</th>
          </tr>
        </thead>
        <tbody>
          ${iocRows}
        </tbody>
      </table>
    ` : ""}

    <!-- Preserved Primary Article Content -->
    <div class="section-title">Extracted Document Body</div>
    <div class="content-body">
      ${mainContent}
    </div>
  </div>
</body>
</html>`;
}
