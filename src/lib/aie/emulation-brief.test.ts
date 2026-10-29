import { test } from "node:test";
import assert from "node:assert/strict";
import { buildEmulationBrief, defangUrl } from "./emulation-brief.ts";
import { assessEmulationValue, summarizeEmulation } from "./emulation-value.ts";
import { CLICKFIX_CHAIN } from "./__fixtures__/emulation-samples.ts";

test("defangUrl defangs the last dot of the host, like shared intel posts", () => {
  assert.equal(defangUrl("https://www.forescout.com/blog/romulus/"), "https://www.forescout[.]com/blog/romulus/");
});

test("a chain report becomes a brief in the shared-intel format, using only the report's sentences", () => {
  const emulation = summarizeEmulation(assessEmulationValue(CLICKFIX_CHAIN));
  const b = buildEmulationBrief({
    ...CLICKFIX_CHAIN,
    url: "https://www.forescout.com/blog/romulus-analysis-of-a-new-multi-payload-clickfix-delivery-platform/",
    publisher: "Forescout",
    extractedText: CLICKFIX_CHAIN.text,
    emulation,
  });
  assert.equal(b.category, "ATTACK INFRASTRUCTURE");
  assert.equal(b.stepsFrom, "rules");
  assert.ok(b.steps.some((s) => s.includes("IconEdit2Turb.msi")));
  for (const s of b.steps) assert.ok(CLICKFIX_CHAIN.text.includes(s.replace(/…$/, "")), `step is quoted from the text: ${s}`);
  assert.match(b.text, /^\[ATTACK INFRASTRUCTURE\] ROMULUS/);
  assert.match(b.text, /📍 INFECTION CHAIN/);
  assert.match(b.text, /📌 Source: Forescout\n🔗 https:\/\/www\.forescout\[\.\]com\/blog\//);
});

test("verified AI steps take precedence over the rules' steps", () => {
  const b = buildEmulationBrief({
    title: "New loader",
    url: "https://x.example/r",
    aiAnalysis: {
      summary: "Researchers found a loader. It sideloads a DLL.",
      emulation: {
        grade: "procedures",
        claimedGrade: "procedures",
        reproducible: "partly",
        steps: [
          { text: "a", quote: "javaw.exe loads jli.dll." },
          { text: "b", quote: "jli.dll decodes config.ini." },
        ],
        novel: [],
        missing: [],
        note: "",
      },
    },
    emulation: { version: 1, grade: "context", score: 20, signals: [], steps: ["Other step."], novelty: [] },
  });
  assert.equal(b.stepsFrom, "ai");
  assert.deepEqual(b.steps, ["javaw.exe loads jli.dll.", "jli.dll decodes config.ini."]);
  assert.deepEqual(b.about, ["Researchers found a loader.", "It sideloads a DLL."]);
});
