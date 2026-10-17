import { test } from "node:test";
import assert from "node:assert/strict";
import { excerptOf } from "./extract.ts";
import { feedContentToText, parseRssOrAtomXml } from "./feeds.ts";

const ARTICLE_HTML = `<aside class="table-of-contents-block"><button class="btn">Contents</button></aside>
<p class="wp-block-paragraph">Storm-2570 operators used <code>rclone.exe</code> to exfiltrate data before encrypting ESXi hosts.</p>
<h2>Indicators</h2><table><tr><th>IOC</th><th>Type</th></tr><tr><td>203.0.113[.]7</td><td>IP</td></tr></table>`;

test("feedContentToText: CDATA HTML, entity-encoded HTML and plain text become clean text", () => {
  const fromHtml = feedContentToText(ARTICLE_HTML);
  assert.ok(!/<[a-z]/i.test(fromHtml), fromHtml);
  assert.match(fromHtml, /Storm-2570 operators used rclone\.exe/);
  assert.match(fromHtml, /## Indicators/);
  assert.match(fromHtml, /\| 203\.0\.113\[\.\]7 \| IP \|/);

  const encoded = ARTICLE_HTML.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  assert.equal(feedContentToText(encoded), fromHtml);

  assert.equal(feedContentToText("  Plain   summary &amp; text "), "Plain summary & text");
  assert.equal(feedContentToText(undefined), "");
});

test("parseRssOrAtomXml: full-content RSS items carry clean contentText (CDATA and entity-encoded)", () => {
  const encoded = ARTICLE_HTML.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const xml = `<?xml version="1.0"?><rss><channel>
    <item><title>Storm-2570 tradecraft</title><link>https://vendor.example/research/2026/storm-2570-tradecraft</link>
      <pubDate>Mon, 05 Oct 2026 10:00:00 GMT</pubDate><content:encoded><![CDATA[${ARTICLE_HTML}]]></content:encoded></item>
    <item><title>Second report</title><link>https://vendor.example/research/2026/second-report</link>
      <description>${encoded}</description></item>
  </channel></rss>`;
  const items = parseRssOrAtomXml(xml);
  assert.equal(items.length, 2);
  for (const it of items) {
    assert.ok(it.contentText && !/<[a-z]/i.test(it.contentText), it.contentText);
    assert.match(it.contentText!, /rclone\.exe/);
    assert.ok(!/[<>]|&lt;/.test(it.summary), it.summary);
  }
});

test("parseRssOrAtomXml: Atom entries prefer the full content for contentText", () => {
  const xml = `<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Atom report</title>
    <link rel="alternate" href="https://vendor.example/threat-research/atom-report"/>
    <published>2026-10-01T00:00:00Z</published><summary>Short summary.</summary>
    <content type="html">${ARTICLE_HTML.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")}</content></entry></feed>`;
  const [e] = parseRssOrAtomXml(xml);
  assert.equal(e.summary, "Short summary.");
  assert.match(e.contentText ?? "", /## Indicators/);
});

test("excerptOf never shows markup", () => {
  assert.equal(excerptOf('<p class="x">Hello <b>analyst</b></p><script>alert(1)</script>'), "Hello analyst");
});
