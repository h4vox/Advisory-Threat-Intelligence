import { isCandidateResourceUrl } from "./qualification";
import { decodeEntities } from "./extract";

export type FeedArticle = {
  url: string;
  title: string;
  publishedAt: string | null;
  author: string;
  summary: string;
  rawContent?: string;
};

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

    const content =
      itemXml.match(/<content:encoded[^>]*>(?:<!\[CDATA\[([\s\S]*?)\]\]>|([\s\S]*?))<\/content:encoded>/i)?.[1] ??
      itemXml.match(/<description[^>]*>(?:<!\[CDATA\[([\s\S]*?)\]\]>|([\s\S]*?))<\/description>/i)?.[1] ??
      "";

    articles.push({
      url: link,
      title: decodeXmlEntities(title).trim(),
      publishedAt: pubDate ? tryParseDate(pubDate) : null,
      author: decodeXmlEntities(author).trim(),
      summary: stripHtml(decodeXmlEntities(content)).slice(0, 300),
      rawContent: content,
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

      const summary =
        entryXml.match(/<summary[^>]*>(?:<!\[CDATA\[([\s\S]*?)\]\]>|([\s\S]*?))<\/summary>/i)?.[1] ??
        entryXml.match(/<content[^>]*>(?:<!\[CDATA\[([\s\S]*?)\]\]>|([\s\S]*?))<\/content>/i)?.[1] ??
        "";

      articles.push({
        url: link,
        title: decodeXmlEntities(title).trim(),
        publishedAt: published ? tryParseDate(published) : null,
        author: decodeXmlEntities(author).trim(),
        summary: stripHtml(decodeXmlEntities(summary)).slice(0, 300),
        rawContent: summary,
      });
    }
  }

  return articles;
}

function decodeXmlEntities(s: string): string {
  return decodeEntities(s);
}

function stripHtml(s: string): string {
  return s.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
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
