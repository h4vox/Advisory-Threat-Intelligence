import { chromium } from "playwright";

async function main() {
  const browser = await chromium.launch({
    executablePath: "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    headless: true,
  });
  const page = await browser.newPage({ viewport: { width: 1440, height: 950 } });

  // 1. Visit /settings
  await page.goto("http://127.0.0.1:8080/settings", { waitUntil: "networkidle" });
  await page.waitForTimeout(1000);

  // 2. Uncheck Auto-Ingest Qualified Reports
  const autoIngestCheckbox = page.locator("label", { hasText: "Auto-Ingest Qualified Reports" }).locator("input[type='checkbox']");
  if (await autoIngestCheckbox.isChecked()) {
    await autoIngestCheckbox.uncheck();
    console.log("Unchecked Auto-Ingest Qualified Reports");
  }

  // 3. Switch to AI Agent tab
  await page.getByRole("button", { name: /AI Agent/i }).click();
  await page.waitForTimeout(500);

  // 4. Ensure Auto-Ingest Agent Approved is checked
  const agentAutoIngestSwitch = page.locator("button[role='switch']").nth(3);
  const checked = await agentAutoIngestSwitch.getAttribute("aria-checked");
  if (checked !== "true") {
    await agentAutoIngestSwitch.click();
    console.log("Turned ON Auto-Ingest Agent Approved");
    await page.waitForTimeout(500);
  }

  // 5. Check if warning is visible
  await page.screenshot({ path: "./screenshots/settings-warning-active.png" });
  console.log("Saved screenshots/settings-warning-active.png");

  const content = await page.content();
  const warningPresent = content.includes("Prerequisite Setting Disabled: \"Auto-Ingest Qualified Reports\" is OFF");
  console.log("Warning alert is present?:", warningPresent);

  // 6. Click the quick-enable button
  const quickEnableBtn = page.getByRole("button", { name: /Enable "Auto-Ingest Qualified Reports" Now/i });
  if (await quickEnableBtn.isVisible()) {
    await quickEnableBtn.click();
    console.log("Clicked quick enable button");
    await page.waitForTimeout(500);
    await page.screenshot({ path: "./screenshots/settings-warning-resolved.png" });
    console.log("Saved screenshots/settings-warning-resolved.png");
  }

  await browser.close();
}

main().catch(console.error);
