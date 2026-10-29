/**
 * Stored plain-text extraction → HTML for the document view. Pure (no imports) so it is unit-tested.
 */
const escapeHtml = (str: string) => str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");

/**
 * The stored plain-text extraction as HTML: ``` fences become <pre><code> blocks (line breaks and
 * indentation kept), "# Heading" lines become headings, blank lines separate paragraphs and single
 * line breaks inside a paragraph stay line breaks (lists, step-by-step chains).
 */
export function plainTextToHtml(text: string): string {
  const out: string[] = [];
  let para: string[] = [];
  let code: string[] | null = null;
  const flush = () => {
    if (para.length) out.push(`<p>${para.map(escapeHtml).join("<br>")}</p>`);
    para = [];
  };
  for (const raw of text.replace(/\r\n?/g, "\n").split("\n")) {
    const fence = /^\s*```/.test(raw);
    if (code) {
      if (fence) {
        out.push(`<pre><code>${escapeHtml(code.join("\n"))}</code></pre>`);
        code = null;
      } else code.push(raw);
      continue;
    }
    if (fence) {
      flush();
      // Text on the fence line itself (```""" Author …) belongs to the code.
      const rest = raw.replace(/^\s*```[\w-]*\s?/, "");
      code = rest.trim() ? [rest] : [];
      if (/```\s*$/.test(rest) && rest.trim() !== "```") {
        out.push(`<pre><code>${escapeHtml(rest.replace(/```\s*$/, ""))}</code></pre>`);
        code = null;
      }
      continue;
    }
    const heading = raw.match(/^(#{1,6})\s+(.+)$/);
    if (heading) {
      flush();
      const level = Math.min(4, heading[1].length + 1);
      out.push(`<h${level}>${escapeHtml(heading[2].trim())}</h${level}>`);
      continue;
    }
    if (!raw.trim()) flush();
    else para.push(raw.trim());
  }
  if (code) out.push(`<pre><code>${escapeHtml(code.join("\n"))}</code></pre>`);
  flush();
  return out.join("\n");
}

