import { test } from "node:test";
import assert from "node:assert/strict";

test("real-time sitemap window: each run reads the 60 days before the last; it starts over after three years", async () => {
  const { realtimeSitemapWindow, filterSitemapEntries } = await import("./discovery-depth.ts");
  const now = Date.parse("2026-10-30T00:00:00Z");
  const first = realtimeSitemapWindow(null, now);
  assert.equal(first.untilIso, "2026-10-31T00:00:00.000Z");
  const second = realtimeSitemapWindow(first.sinceIso, now);
  assert.equal(second.untilIso, first.sinceIso);
  assert.ok(Date.parse(second.sinceIso) < Date.parse(first.sinceIso));
  assert.equal(realtimeSitemapWindow("2022-01-01T00:00:00Z", now).untilIso, first.untilIso, "past three years: start over");
  const entries = [
    { loc: "https://x/a", lastmod: "2026-10-01" },
    { loc: "https://x/b", lastmod: "2026-07-01" },
    { loc: "https://x/c", lastmod: "2026-08-20" },
  ];
  assert.deepEqual(filterSitemapEntries(entries, { sinceIso: second.sinceIso, untilIso: second.untilIso }).map((e) => e.loc), ["https://x/c"]);
});
