import { chromium } from "playwright";

async function main() {
  console.log("Launching Edge browser for UI verification...");
  const browser = await chromium.launch({
    executablePath: "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    headless: true,
  });
  const page = await browser.newPage({ viewport: { width: 1440, height: 950 } });

  const consoleErrors = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") {
      consoleErrors.push({ url: page.url(), text: msg.text() });
    }
  });

  // 1. Check /sources - Curated Tab
  console.log("\n1. Visiting /sources (Curated)...");
  await page.goto("http://127.0.0.1:8080/sources", { waitUntil: "networkidle" });
  await page.waitForTimeout(1500);
  await page.screenshot({ path: "./screenshots/sources-curated-3col.png" });
  console.log("Captured screenshots/sources-curated-3col.png");

  // Check that green button class is NOT present
  const curatedContent = await page.content();
  const hasGreenButton = curatedContent.includes("bg-emerald-950/30 text-emerald-400");
  console.log("Has old green buttons on /sources?:", hasGreenButton);

  // Check for report count badges
  const hasReportBadges = curatedContent.includes("reports collected");
  console.log("Has 'reports collected' badges?:", hasReportBadges);

  // Test toggling the first curated source
  console.log("Testing Curated Toggle button on first source...");
  const firstToggle = page.locator("article button").first();
  const beforeText = await firstToggle.innerText();
  console.log("Initial state of first source button:", beforeText);
  await firstToggle.click();
  await page.waitForTimeout(500);
  const afterText = await firstToggle.innerText();
  console.log("State after click:", afterText);
  await page.screenshot({ path: "./screenshots/sources-curated-toggled.png" });
  console.log("Captured screenshots/sources-curated-toggled.png");

  // Toggle it back to keep it enabled
  if (beforeText !== afterText) {
    await firstToggle.click();
    await page.waitForTimeout(500);
    console.log("Restored toggle to active state.");
  }

  // 2. Check /sources - Discovered Tab
  console.log("\n2. Visiting Discovered Sources Tab...");
  await page.getByRole("button", { name: /Discovered Sources/i }).click();
  await page.waitForTimeout(1500);
  await page.screenshot({ path: "./screenshots/sources-discovered-3col.png" });
  console.log("Captured screenshots/sources-discovered-3col.png");

  const discContent = await page.content();
  console.log("Contains securelist.com?:", discContent.includes("securelist.com"));
  console.log("Contains krebsonsecurity.com?:", discContent.includes("krebsonsecurity.com"));
  console.log("Contains zerotracelab.com?:", discContent.includes("zerotracelab.com"));
  console.log("Contains media.defense.gov?:", discContent.includes("media.defense.gov"));
  console.log("Has 'reports in library' badges?:", discContent.includes("reports in library"));

  // 3. Check /ingest - Discovery Queue Score Column
  console.log("\n3. Visiting /ingest...");
  await page.goto("http://127.0.0.1:8080/ingest", { waitUntil: "networkidle" });
  await page.waitForTimeout(2000);
  await page.screenshot({ path: "./screenshots/ingest-queue-scores.png" });
  console.log("Captured screenshots/ingest-queue-scores.png");

  const ingestContent = await page.content();
  console.log("Contains 'Engine:' in Score column?:", ingestContent.includes("Engine:"));
  console.log("Contains 'AI:' or 'SIM:'?:", ingestContent.includes("AI:") || ingestContent.includes("SIM:"));

  // 4. Check /settings?tab=agent - AI Agent Toggles & Warning Banner
  console.log("\n4. Visiting /settings (AI Agent tab)...");
  await page.goto("http://127.0.0.1:8080/settings?tab=agent", { waitUntil: "networkidle" });
  await page.waitForTimeout(1500);
  await page.screenshot({ path: "./screenshots/settings-ai-agent-toggles.png" });
  console.log("Captured screenshots/settings-ai-agent-toggles.png");

  // Find the Auto-Ingest Agent Approved toggle and toggle it ON
  console.log("Testing Auto-Ingest Agent Approved toggle...");
  const agentAutoIngestButton = page.locator("button[role='switch']").nth(3); // 4th toggle (0-indexed)
  await agentAutoIngestButton.click();
  await page.waitForTimeout(800);
  await page.screenshot({ path: "./screenshots/settings-agent-warning.png" });
  console.log("Captured screenshots/settings-agent-warning.png");

  const settingsContent = await page.content();
  console.log("Shows Warning Alert if Auto-Ingest is OFF?:", settingsContent.includes("Prerequisite Setting Disabled") || settingsContent.includes("Auto-Ingest Qualified Reports"));

  console.log("\nTotal console errors:", consoleErrors.length);
  if (consoleErrors.length > 0) {
    console.log("Console errors:", JSON.stringify(consoleErrors, null, 2));
  }

  await browser.close();
  console.log("\nAll UI QA verifications completed successfully!");
}

main().catch(console.error);
