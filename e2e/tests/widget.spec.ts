import { test, expect, Page } from "@playwright/test";

/**
 * End-to-end against static/testsite.html.
 * Runs the real widget — fetches puzzle, solves PoW in the worker, posts to
 * /v1/verify with the bearer secret. Asserts the server returns success.
 */

async function setupSite(page: Page) {
  await page.goto("/static/testsite.html");
  await page.click("#setup-btn");
  await expect(page.locator("#setup-btn")).toHaveText("Site Created", {
    timeout: 30_000,
  });
}

test("happy path: widget solves PoW and verify returns success=true", async ({
  page,
}) => {
  await setupSite(page);

  // Wait for the widget to receive a puzzle (event fired by widget).
  // The testsite mirrors that into the risk-debug section.
  await expect(page.locator("#rc-widget-tier")).not.toHaveText("—", {
    timeout: 30_000,
  });

  await page.fill("#name", "Jane Doe");
  await page.fill("#email", "jane@example.com");

  // Click checkbox (will silently solve for invisible_pass tier; for higher
  // tiers a click is required).
  const checkbox = page.locator(".rc-captcha-checkbox");
  if (await checkbox.isVisible()) {
    await checkbox.click();
  }

  // Wait for verified state (PoW solved by worker).
  await expect(page.locator(".rc-captcha-label")).toHaveText("Verified", {
    timeout: 60_000,
  });

  await page.click("#submit-btn");

  // Result section shows server_verification.success = true.
  const result = page.locator("#result-data");
  await expect(result).toBeVisible();
  await expect(result).toContainText('"success": true', { timeout: 15_000 });
});

test("rate spam pushes tier toward HardPow / 429", async ({ page }) => {
  await setupSite(page);

  // Drive the spam button (30 manual fetches in a row).
  await page.click("#risk-spam");

  // Wait for the spam to finish (button text resets).
  await expect(page.locator("#risk-spam")).toHaveText(
    "Spam 30× (push toward HardPow / Block)",
    { timeout: 60_000 },
  );

  // Pull tier history rows. We expect to see at least one tier escalation
  // beyond invisible_pass (HardPow / Checkbox / blocked-429) somewhere in the run.
  const tiers = await page
    .locator("#risk-history .row .tier-pill")
    .allTextContents();

  const escalated = tiers.some((t) =>
    ["hard_pow", "checkbox", "block", "blocked-429", "visual_challenge"].includes(
      t.trim(),
    ),
  );
  expect(escalated, `tier history was: ${JSON.stringify(tiers)}`).toBe(true);
});

test("honeypot: filling the trap should fail verification", async ({ page }) => {
  await setupSite(page);

  await expect(page.locator("#rc-widget-tier")).not.toHaveText("—", {
    timeout: 30_000,
  });

  // Force-fill the off-screen honeypot input (simulates a naive bot).
  await page.evaluate(() => {
    const hp = document.querySelector(
      'input[name="rc_email_confirm"]',
    ) as HTMLInputElement | null;
    if (hp) hp.value = "bot@bot.example";
  });

  await page.fill("#name", "Bot Bot");
  await page.fill("#email", "bot@bot.example");

  const checkbox = page.locator(".rc-captcha-checkbox");
  if (await checkbox.isVisible()) {
    await checkbox.click();
  }
  await expect(page.locator(".rc-captcha-label")).toHaveText("Verified", {
    timeout: 60_000,
  });

  await page.click("#submit-btn");
  const result = page.locator("#result-data");
  await expect(result).toBeVisible();
  // Honeypot adds +100 verify-time score — still dominates regardless of
  // any other signal weights.
  await expect(result).toContainText('"success": false', { timeout: 15_000 });
});
