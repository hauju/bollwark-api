import { test, expect, Page } from "@playwright/test";

/**
 * Adversarial e2e: simulates browser-harness's default interaction pattern.
 *
 * browser-harness drives a real Chrome over CDP and (when the agent doesn't
 * write extra mouse-movement helpers) dispatches clicks via
 * `Runtime.evaluate("el.click()")`. From the page's POV that means:
 *   - real Chrome → real TLS / UA / Accept-Language → header & TLS signals
 *     are inert (as designed: those catch curl/python, not real browsers)
 *   - `navigator.webdriver === true` (CDP marker)
 *   - zero mousemove events, zero touch events
 *   - clicks happen via JS dispatch only
 *   - submission is typically fast (LLM agents don't pause to read forms)
 *
 * Expected verify-time score: webdriver(30) + no_pointer(15) + time<500ms(50)
 * = 95 → above VERIFY_BLOCK_MIN (60) → success=false.
 *
 * If this test ever starts passing with success=true, the captcha has
 * regressed against the cheapest agentic threat model.
 */

async function setupSite(page: Page) {
  await page.goto("/static/testsite.html");
  await page.click("#setup-btn");
  await expect(page.locator("#setup-btn")).toHaveText("Site Created", {
    timeout: 30_000,
  });
}

test("browser-harness-simulator: programmatic clicks + webdriver flag should block", async ({
  page,
}) => {
  await setupSite(page);

  // Wait for the widget to mount and lock its tier — but don't *interact*
  // with the page in the meantime. The agent doesn't browse, it just calls.
  await expect(page.locator("#rc-widget-tier")).not.toHaveText("—", {
    timeout: 30_000,
  });

  // Set form values directly — no keystrokes, no focus events.
  await page.evaluate(() => {
    (document.getElementById("name") as HTMLInputElement).value = "Agent Smith";
    (document.getElementById("email") as HTMLInputElement).value =
      "agent@example.com";
  });

  // Programmatic click on the captcha checkbox (if visible). No mouse move.
  await page.evaluate(() => {
    const cb = document.querySelector(".rc-captcha-checkbox") as HTMLElement | null;
    if (cb) cb.click();
  });

  // Wait for the widget to finish solving the PoW.
  await expect(page.locator(".rc-captcha-label")).toHaveText("Verified", {
    timeout: 60_000,
  });

  // Inspect the verify payload before submit so failures are diagnosable.
  const payload = await page.evaluate(() => {
    const input = document.querySelector(
      'input[name="captcha-token"]',
    ) as HTMLInputElement | null;
    return input ? input.value : null;
  });
  console.log("verify payload:", payload);

  // Fire submit programmatically — also no mouse move.
  await page.evaluate(() => {
    (document.getElementById("submit-btn") as HTMLButtonElement).click();
  });

  const result = page.locator("#result-data");
  await expect(result).toBeVisible();
  // Server should reject. The flatline behavior + webdriver flag combine
  // to push the verify-time score over the block threshold.
  await expect(result).toContainText('"success": false', { timeout: 15_000 });
});

test("browser-harness-simulator: organic interactions (mouse + keystrokes) should pass", async ({
  page,
}) => {
  // Sanity-check the *positive* control: when the same Playwright browser
  // (still has navigator.webdriver=true) interacts with real mouse moves
  // and keystrokes, the score lands in the shadow band — webdriver alone
  // is +30 → ShadowFail → success=true. This protects us from the
  // signal becoming a false-positive trap for legit Playwright-driven
  // happy-path tests in the existing suite.
  await setupSite(page);
  await expect(page.locator("#rc-widget-tier")).not.toHaveText("—", {
    timeout: 30_000,
  });

  // Real mouse movement + keystrokes
  await page.mouse.move(100, 100);
  await page.mouse.move(200, 200);
  await page.mouse.move(300, 300);
  await page.fill("#name", "Jane Doe");
  await page.fill("#email", "jane@example.com");

  const checkbox = page.locator(".rc-captcha-checkbox");
  if (await checkbox.isVisible()) {
    await checkbox.click(); // real click via mouse
  }
  await expect(page.locator(".rc-captcha-label")).toHaveText("Verified", {
    timeout: 60_000,
  });

  await page.click("#submit-btn");

  const result = page.locator("#result-data");
  await expect(result).toBeVisible();
  await expect(result).toContainText('"success": true', { timeout: 15_000 });
});
