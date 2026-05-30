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

  // Time-on-page <500ms scores +50 at verify-time. Sit on the page long
  // enough for that band to fall to 0, otherwise webdriver(+30) + time(+50)
  // already lands at the verify-time block threshold (60).
  await page.waitForTimeout(2_500);

  await page.fill("#name", "Jane Doe");
  await page.fill("#email", "jane@example.com");

  // Default mode always shows the checkbox row. On invisible_pass it's
  // already auto-solving (or solved) by the time we click, and the click
  // is a no-op for verified/solving states. On checkbox/hard_pow the
  // click is what kicks off the worker.
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

test("invisible mode: invisible_pass tier renders no visible UI but verifies", async ({
  page,
}) => {
  await page.goto("/static/testsite.html?invisible=1");
  await page.click("#setup-btn");
  await expect(page.locator("#setup-btn")).toHaveText("Site Created", {
    timeout: 30_000,
  });

  // The puzzle event fires once the widget receives its tier. Use the
  // testsite's mirrored readout to wait for it without racing.
  await expect(page.locator("#rc-widget-tier")).not.toHaveText("—", {
    timeout: 30_000,
  });

  // For the invisible_pass tier the widget must render zero chrome —
  // no rc-captcha class, no checkbox, no label, no footer. The honeypot
  // input is the one element that stays present so naive bots still trip.
  await expect(page.locator("#captcha-widget.rc-captcha")).toHaveCount(0);
  await expect(page.locator(".rc-captcha-checkbox")).toHaveCount(0);
  await expect(page.locator(".rc-captcha-label")).toHaveCount(0);
  await expect(page.locator(".rc-captcha-footer")).toHaveCount(0);
  await expect(
    page.locator('#captcha-widget input[aria-hidden="true"]'),
  ).toHaveCount(1);

  // Silent PoW finishes in the background; widget reports `verified` via
  // its public getResult().
  await page.waitForFunction(
    () => {
      const inst = (window as any).RustCaptcha?._instances?.[0];
      return inst && inst.getResult().state === "verified";
    },
    undefined,
    { timeout: 60_000 },
  );

  // Sit on the page long enough that the verify-time time-on-page band
  // drops to 0 (matches the happy-path test).
  await page.waitForTimeout(2_500);

  await page.fill("#name", "Jane Doe");
  await page.fill("#email", "jane@example.com");
  await page.click("#submit-btn");

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
    ["hard_pow", "checkbox", "block", "blocked-429"].includes(
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
      '.rc-captcha input[aria-hidden="true"]',
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
