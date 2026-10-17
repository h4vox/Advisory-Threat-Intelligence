import { isCandidateResourceUrl } from "./qualification.ts";
import { decodeEntities, htmlToText } from "./extract.ts";

export type FeedArticle = {
  url: string;
  title: string;
  publishedAt: string | null;
  author: string;
  /** Plain-text summary (first 300 chars of the item content). */
  summary: string;
  /** Item content exactly as the feed carried it (HTML, entity-encoded HTML or text). */
  rawContent?: string;
  /** Item content as clean structured text (headings, lists, tables kept); never HTML. */
  contentText?: string;
};

/** One level of XML decoding for entity-encoded markup (&lt;p&gt; → <p>) inside a non-CDATA element. */
function decodeXmlMarkup(s: string): string {
  return s
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#0*39;|&apos;/gi, "'")
    .replace(/&amp;/gi, "&");
}

/**
 * Feed item content → clean text. Feeds carry HTML (CDATA), entity-encoded HTML or plain text; all
 * three become the same structure-preserving text the page extractor produces, so a report taken
 * from a full-content feed never stores markup as its text.
 */
export function feedContentToText(raw: string | null | undefined): string {
  let html = (raw ?? "").trim();
  if (!html) return "";
  if (!/<[a-z!/][^>]*>/i.test(html) && /&lt;\/?[a-z!]/i.test(html)) html = decodeXmlMarkup(html);
  if (!/<[a-z!/][^>]*>/i.test(html)) return decodeEntities(html).replace(/\s+/g, " ").trim();
  return htmlToText(html, { structured: true }).text;
}

export function parseRssOrAtomXml(xml: string): FeedArticle[] {
  const articles: FeedArticle[] = [];
  if (!xml || xml.trim().length === 0) return articles;

  // 1. Check for RSS <item> tags
  const itemRegex = /<item\b[^>]*>([\s\S]*?)<\/item>/gi;
  let itemMatch: RegExpExecArray | null;

  while ((itemMatch = itemRegex.exec(xml)) !== null) {
    const itemXml = itemMatch[1];

    const link =
      itemXml.match(/<link[^>]*>([\s\S]*?)<\/link>/i)?.[1]?.trim() ??
      itemXml.match(/<guid[^>]*isPermaLink=["']true["'][^>]*>([\s\S]*?)<\/guid>/i)?.[1]?.trim() ??
      "";

    if (!link || !link.startsWith("http")) continue;

    // Check if link is an individual resource (verified from feed)
    if (!isCandidateResourceUrl(link, true).isResource) continue;

    const title =
      itemXml.match(/<title[^>]*>(?:<!\[CDATA\[([\s\S]*?)\]\]>|([\s\S]*?))<\/title>/i)?.[1] ??
      itemXml.match(/<title[^>]*>(?:<!\[CDATA\[([\s\S]*?)\]\]>|([\s\S]*?))<\/title>/i)?.[2] ??
      "Untitled threat report";

    const pubDate =
      itemXml.match(/<pubDate[^>]*>([\s\S]*?)<\/pubDate>/i)?.[1]?.trim() ??
      itemXml.match(/<dc:date[^>]*>([\s\S]*?)<\/dc:date>/i)?.[1]?.trim() ??
      null;

    const author =
      itemXml.match(/<dc:creator[^>]*>(?:<!\[CDATA\[([\s\S]*?)\]\]>|([\s\S]*?))<\/dc:creator>/i)?.[1] ??
      itemXml.match(/<author[^>]*>([\s\S]*?)<\/author>/i)?.[1]?.trim() ??
      "";

    const encoded = itemXml.match(/<content:encoded[^>]*>(?:<!\[CDATA\[([\s\S]*?)\]\]>|([\s\S]*?))<\/content:encoded>/i);
    const described = itemXml.match(/<description[^>]*>(?:<!\[CDATA\[([\s\S]*?)\]\]>|([\s\S]*?))<\/description>/i);
    const content = encoded?.[1] ?? encoded?.[2] ?? described?.[1] ?? described?.[2] ?? "";
    const contentText = feedContentToText(content);

    articles.push({
      url: link,
      title: decodeXmlEntities(title).trim(),
      publishedAt: pubDate ? tryParseDate(pubDate) : null,
      author: decodeXmlEntities(author).trim(),
      summary: contentText.replace(/\s+/g, " ").slice(0, 300),
      rawContent: content,
      contentText,
    });
  }

  // 2. Check for Atom <entry> tags (e.g. Google / Talos)
  if (articles.length === 0) {
    const entryRegex = /<entry\b[^>]*>([\s\S]*?)<\/entry>/gi;
    let entryMatch: RegExpExecArray | null;

    while ((entryMatch = entryRegex.exec(xml)) !== null) {
      const entryXml = entryMatch[1];

      const link =
        entryXml.match(/<link\b[^>]*rel=["']alternate["'][^>]*href=["']([^"']+)["']/i)?.[1] ??
        entryXml.match(/<link\b[^>]*href=["']([^"']+)["']/i)?.[1] ??
        "";

      if (!link || !link.startsWith("http")) continue;
      if (!isCandidateResourceUrl(link, true).isResource) continue;

      const title =
        entryXml.match(/<title[^>]*>(?:<!\[CDATA\[([\s\S]*?)\]\]>|([\s\S]*?))<\/title>/i)?.[1] ??
        entryXml.match(/<title[^>]*>(?:<!\[CDATA\[([\s\S]*?)\]\]>|([\s\S]*?))<\/title>/i)?.[2] ??
        "Untitled threat report";

      const published =
        entryXml.match(/<published[^>]*>([\s\S]*?)<\/published>/i)?.[1]?.trim() ??
        entryXml.match(/<updated[^>]*>([\s\S]*?)<\/updated>/i)?.[1]?.trim() ??
        null;

      const author =
        entryXml.match(/<author>[\s\S]*?<name>([\s\S]*?)<\/name>[\s\S]*?<\/author>/i)?.[1]?.trim() ??
        "";

      // Prefer the full <content> over the short <summary> for the stored text.
      const summaryEl = entryXml.match(/<summary[^>]*>(?:<!\[CDATA\[([\s\S]*?)\]\]>|([\s\S]*?))<\/summary>/i);
      const contentEl = entryXml.match(/<content[^>]*>(?:<!\[CDATA\[([\s\S]*?)\]\]>|([\s\S]*?))<\/content>/i);
      const content = contentEl?.[1] ?? contentEl?.[2] ?? summaryEl?.[1] ?? summaryEl?.[2] ?? "";
      const contentText = feedContentToText(content);
      const summaryText = feedContentToText(summaryEl?.[1] ?? summaryEl?.[2] ?? "") || contentText;

      articles.push({
        url: link,
        title: decodeXmlEntities(title).trim(),
        publishedAt: published ? tryParseDate(published) : null,
        author: decodeXmlEntities(author).trim(),
        summary: summaryText.replace(/\s+/g, " ").slice(0, 300),
        rawContent: content,
        contentText,
      });
    }
  }

  return articles;
}

function decodeXmlEntities(s: string): string {
  return decodeEntities(s);
}



function tryParseDate(raw: string): string | null {
  try {
    const d = new Date(raw);
    if (!isNaN(d.getTime())) {
      return d.toISOString().slice(0, 10);
    }
  } catch {
    /* fallback */
  }
  return null;
}
