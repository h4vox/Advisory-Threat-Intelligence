/**
 * Hardening for crawled third-party HTML rendered via `<iframe srcDoc>`.
 *
 * Pair with `sandbox=""` on the iframe (no scripts, no same-origin, no forms,
 * no top navigation). The injected CSP additionally blocks network fetches
 * other than images/fonts, so archived pages cannot beacon or load scripts.
 */
export const SAFE_SRCDOC_CSP =
  "default-src 'none'; img-src data: https:; style-src 'unsafe-inline'; font-src data: https:";

const CSP_META = `<meta http-equiv="Content-Security-Policy" content="${SAFE_SRCDOC_CSP}">`;

export function toSafeSrcDoc(html: string): string {
  const source = typeof html === "string" ? html : "";
  // Prefer the start of <head> so the policy precedes every other resource.
  const headOpen = /<head(?:\s[^>]*)?>/i.exec(source);
  if (headOpen) {
    const at = headOpen.index + headOpen[0].length;
    return source.slice(0, at) + CSP_META + source.slice(at);
  }
  const htmlOpen = /<html(?:\s[^>]*)?>/i.exec(source);
  if (htmlOpen) {
    const at = htmlOpen.index + htmlOpen[0].length;
    return `${source.slice(0, at)}<head>${CSP_META}</head>${source.slice(at)}`;
  }
  return CSP_META + source;
}
