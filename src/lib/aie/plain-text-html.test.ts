import { test } from "node:test";
import assert from "node:assert/strict";
import { plainTextToHtml } from "./plain-text-html.ts";

test("plain-text reports keep code blocks, headings and step lines", () => {
  const html = plainTextToHtml(
    [
      "# DGA algorithm",
      "The following Python snippet represents the DGA algorithm:",
      '```python',
      'ADJECTIVES = [ "silver", "amber" ]',
      "def hash_bytes(data: bytes, seed: int) -> int:",
      "    value = seed",
      "```",
      "",
      "1. Adjectives",
      "2. Nouns",
    ].join("\n"),
  );
  assert.match(html, /<h2>DGA algorithm<\/h2>/);
  assert.match(html, /<pre><code>ADJECTIVES = \[ &quot;silver&quot;, &quot;amber&quot; \]\ndef hash_bytes\(data: bytes, seed: int\) -&gt; int:\n {4}value = seed<\/code><\/pre>/);
  assert.match(html, /<p>1\. Adjectives<br>2\. Nouns<\/p>/);
  assert.ok(!html.includes("```"));
});

test("code that starts on the fence line stays code", () => {
  assert.match(plainTextToHtml('```""" Author: x """\nimport sys\n```'), /<pre><code>&quot;&quot;&quot; Author: x &quot;&quot;&quot;\nimport sys<\/code><\/pre>/);
});
