import { test } from "node:test";
import assert from "node:assert/strict";
import { comparePublishedDesc, normaliseDate, resolvePublicationDate } from "./published-date.ts";

const now = new Date("2026-10-26T12:00:00Z");
const page = (head: string, body = "") => `<html><head>${head}</head><body>${body}</body></html>`;

test("normaliseDate keeps the written calendar day and reads common forms", () => {
  assert.equal(normaliseDate("2022-06-06T23:30:00-05:00"), "2022-06-06");
  assert.equal(normaliseDate("2022-6-6"), "2022-06-06");
  assert.equal(normaliseDate("20220606"), "2022-06-06");
  assert.equal(normaliseDate("Mon, 06 Jun 2022 10:00:00 GMT"), "2022-06-06");
  assert.equal(normaliseDate("06 June 2022"), "2022-06-06");
  assert.equal(normaliseDate("June 6th, 2022"), "2022-06-06");
  assert.equal(normaliseDate("Sept. 14, 2023"), "2023-09-14");
  assert.equal(normaliseDate(1654473600), "2022-06-06");
  assert.equal(normaliseDate("2022-02-30"), null);
  assert.equal(normaliseDate("not a date"), null);
  assert.equal(normaliseDate(""), null);
});

test("JSON-LD datePublished inside @graph wins, with dateModified as the update", () => {
  const ld = {
    "@context": "https://schema.org",
    "@graph": [
      { "@type": "WebSite", datePublished: "2010-01-01" },
      { "@type": "BlogPosting", datePublished: "2024-05-21T08:00:00+00:00", dateModified: "2024-06-02T09:00:00+00:00" },
    ],
  };
  const r = resolvePublicationDate({
    html: page(`<script type="application/ld+json">${JSON.stringify(ld)}</script><meta property="article:published_time" content="2024-05-20">`),
    feedDate: "2024-05-25",
    now,
  });
  assert.equal(r.publishedAt, "2024-05-21");
  assert.equal(r.sourceUpdatedAt, "2024-06-02");
  assert.equal(r.source, "json-ld");
  assert.equal(r.confidence, "high");
  assert.match(r.evidence, /BlogPosting\.datePublished/);
});

test("meta tags are read in either attribute order and across vocabularies", () => {
  assert.equal(resolvePublicationDate({ html: page(`<meta content="2023-03-14T10:00:00Z" property="article:published_time">`), now }).publishedAt, "2023-03-14");
  assert.equal(resolvePublicationDate({ html: page(`<meta name="citation_publication_date" content="2021/11/02">`), now }).publishedAt, "2021-11-02");
  assert.equal(resolvePublicationDate({ html: page(`<meta name="DC.date.issued" content="2020-08-09">`), now }).publishedAt, "2020-08-09");
  const parsely = resolvePublicationDate({ html: page(`<meta name="parsely-page" content='{"pub_date":"2019-04-05T00:00:00Z"}'>`), now });
  assert.equal(parsely.publishedAt, "2019-04-05");
  assert.equal(parsely.source, "meta");
});

test("itemprop datePublished on a time or span element", () => {
  assert.equal(resolvePublicationDate({ html: page("", `<time itemprop="datePublished" datetime="2022-01-10">Jan 10</time>`), now }).publishedAt, "2022-01-10");
  assert.equal(resolvePublicationDate({ html: page("", `<span itemprop="datePublished">March 3, 2021</span>`), now }).publishedAt, "2021-03-03");
});

test("the feed date is used when the page has no structured date", () => {
  const r = resolvePublicationDate({ html: page("", "<p>Body</p>"), feedDate: "2025-02-01", url: "https://x.example/2024/01/01/old", now });
  assert.equal(r.publishedAt, "2025-02-01");
  assert.equal(r.source, "feed");
});

test("a full date in the URL path", () => {
  const r = resolvePublicationDate({ html: page("", "<p>Body</p>"), url: "https://blog.example.com/2024/05/21/new-loader/", now });
  assert.equal(r.publishedAt, "2024-05-21");
  assert.equal(r.source, "url");
  assert.equal(resolvePublicationDate({ url: "https://x.example/research/20230912-campaign.html", now }).publishedAt, "2023-09-12");
});

test("a labelled date in the page text: the NCC Group style byline", () => {
  const html = page("", `<article><h1>Black Basta</h1><div class="meta">Published 06 June 2022 by the research team</div><p>On 1 March 2022 the actor…</p></article>`);
  const r = resolvePublicationDate({ html, url: "https://research.example.com/blog/black-basta/", now });
  assert.equal(r.publishedAt, "2022-06-06");
  assert.equal(r.source, "text");
  assert.equal(r.confidence, "medium");
});

test("time tags: a marked publish date beats an earlier unmarked one; sidebars are ignored", () => {
  const html = page(
    "",
    `<aside><time datetime="2026-01-01">recent</time></aside><article><time class="comment" datetime="2024-01-03"></time><time class="entry-date published" datetime="2024-01-02">Jan 2</time><time class="updated" datetime="2024-02-01"></time></article>`,
  );
  const r = resolvePublicationDate({ html, now });
  assert.equal(r.publishedAt, "2024-01-02");
  assert.equal(r.source, "time-tag");
});

test("a short byline line in extracted text; dates inside sentences are not taken", () => {
  assert.equal(resolvePublicationDate({ text: "Threat brief\nJane Doe · 12 August 2025 · 8 min read\nThe actor…", now }).publishedAt, "2025-08-12");
  const sentence = resolvePublicationDate({
    text: "Threat brief\nOn March 3, 2022 the actor deployed a loader against several manufacturing firms in the region.\nMore text",
    now,
  });
  assert.equal(sentence.publishedAt, null);
  assert.equal(sentence.source, "none");
});

test("future and pre-1995 dates are rejected", () => {
  assert.equal(resolvePublicationDate({ html: page(`<meta property="article:published_time" content="2030-01-01">`), feedDate: "2024-03-01", now }).publishedAt, "2024-03-01");
  assert.equal(resolvePublicationDate({ html: page(`<meta name="date" content="1970-01-01">`), now }).publishedAt, null);
});

test("PDF creation date and URL year/month are lower-confidence fallbacks", () => {
  const pdf = resolvePublicationDate({ text: "Report body", pdfDate: "D:20230405120000Z", now });
  assert.equal(pdf.publishedAt, "2023-04-05");
  assert.equal(pdf.source, "pdf");
  const month = resolvePublicationDate({ url: "https://x.example/2023/07/apt-report/", now });
  assert.equal(month.publishedAt, "2023-07-01");
  assert.equal(month.confidence, "low");
});

test("only an update date: used, but marked low confidence and as the last update", () => {
  const r = resolvePublicationDate({ html: page(`<meta property="article:modified_time" content="2024-09-09">`), now });
  assert.equal(r.publishedAt, "2024-09-09");
  assert.equal(r.confidence, "low");
  assert.equal(r.source, "meta");
  assert.match(r.evidence, /last update/);
});

test("malformed JSON-LD is skipped, not fatal", () => {
  const r = resolvePublicationDate({ html: page(`<script type="application/ld+json">{bad json</script><meta name="pubdate" content="2022-12-12">`), now });
  assert.equal(r.publishedAt, "2022-12-12");
});

test("comparePublishedDesc: newest published first, undated last, ingest time breaks ties", () => {
  const rows = [
    { id: "undated-new", publishedAt: null, ingestedAt: "2026-10-20T00:00:00Z" },
    { id: "old", publishedAt: "2021-01-01", ingestedAt: "2026-10-25T00:00:00Z" },
    { id: "new-a", publishedAt: "2026-10-01T08:00:00Z", ingestedAt: "2026-10-02T00:00:00Z" },
    { id: "new-b", publishedAt: "2026-10-01", ingestedAt: "2026-10-03T00:00:00Z" },
    { id: "undated-old", publishedAt: null, ingestedAt: "2026-01-01T00:00:00Z" },
  ];
  assert.deepEqual(
    [...rows].sort(comparePublishedDesc).map((r) => r.id),
    ["new-b", "new-a", "old", "undated-new", "undated-old"],
  );
});
