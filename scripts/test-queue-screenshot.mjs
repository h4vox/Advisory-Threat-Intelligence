import { chromium } from "playwright";

async function main() {
  const browser = await chromium.launch({
    executablePath: "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    headless: true,
  });
  const page = await browser.newPage({ viewport: { width: 1440, height: 950 } });
  await page.goto("http://127.0.0.1:8080/ingest", { waitUntil: "networkidle" });
  await page.waitForTimeout(1000);

  // Click Discovery Queue tab
  await page.getByRole("button", { name: /Discovery Queue/i }).click();
  await page.waitForTimeout(1500);

  await page.screenshot({ path: "./screenshots/ingest-discovery-queue-table.png" });
  console.log("Screenshot saved to ./screenshots/ingest-discovery-queue-table.png");

  const content = await page.content();
  console.log("Found Engine: in page:", content.includes("Engine:"));
  console.log("Found AI: in page:", content.includes("AI:"));

  await browser.close();
}

main().catch(console.error);
