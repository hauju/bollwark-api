import { test, expect, Page } from "@playwright/test";

/**
 * Keyboard and screen-reader access to the widget.
 *
 * The checkbox is a styled `div`, so nothing here comes for free — every
 * assertion below covers an affordance a real `<input type=checkbox>` would
 * have had by default, and whose absence blocked keyboard-only visitors from
 * completing an escalated challenge at all.
 *
 * `?forceclick=1` registers the site with tier bands starting at zero, so the
 * widget lands on `hard_pow` and waits for an explicit activation instead of
 * auto-solving — otherwise a clean browser always scores `invisible_pass` and
 * the activation path is unreachable from a test.
 */

async function setupSite(page: Page) {
  await page.click("#setup-btn");
  await expect(page.locator("#setup-btn")).toHaveText("Site Created", {
    timeout: 30_000,
  });
}

test("checkbox exposes a name, role and value to assistive tech", async ({
  page,
}) => {
  await page.goto("/static/testsite.html");

  const checkbox = page.locator(".rc-captcha-checkbox");
  await expect(checkbox).toHaveAttribute("role", "checkbox");
  await expect(checkbox).toHaveAttribute("tabindex", "0");
  await expect(checkbox).toHaveAttribute("aria-checked", "false");
  // The name states what the control asks. It must NOT track the label's
  // state text, or a verified widget would announce "Verified" as its
  // question rather than as its value.
  await expect(checkbox).toHaveAttribute("aria-label", "I'm not a robot");

  // State changes have to be audible, not just visible.
  await expect(page.locator(".rc-captcha-label")).toHaveAttribute(
    "aria-live",
    "polite"
  );
  const status = page.locator(".rc-captcha-status");
  await expect(status).toHaveAttribute("role", "status");
  await expect(status).toHaveAttribute("aria-live", "polite");
});

test("checkbox is reachable by keyboard alone", async ({ page }) => {
  await page.goto("/static/testsite.html?forceclick=1");
  await setupSite(page);

  // Tab from the top of the document until focus lands on the checkbox. A
  // bare div would never be reached no matter how many times we press.
  let reached = false;
  for (let i = 0; i < 25 && !reached; i++) {
    await page.keyboard.press("Tab");
    reached = await page.evaluate(() =>
      document.activeElement?.classList.contains("rc-captcha-checkbox") ?? false
    );
  }
  expect(reached, "checkbox never received focus while tabbing").toBe(true);

  // A focused control must be visibly focused (WCAG 2.4.7). The widget's own
  // rule draws an outline; the browser default is `outline: none` here only
  // if something suppressed it.
  const outline = await page.evaluate(() => {
    const el = document.querySelector(".rc-captcha-checkbox")!;
    const s = getComputedStyle(el);
    return { style: s.outlineStyle, width: s.outlineWidth };
  });
  expect(outline.style).not.toBe("none");
  expect(parseFloat(outline.width)).toBeGreaterThan(0);
});

test("space activates the challenge and the checked state follows", async ({
  page,
}) => {
  await page.goto("/static/testsite.html?forceclick=1");
  await setupSite(page);

  await expect(page.locator("#rc-widget-tier")).toHaveText("hard_pow", {
    timeout: 30_000,
  });

  const checkbox = page.locator(".rc-captcha-checkbox");
  await expect(checkbox).toHaveAttribute("aria-checked", "false");

  await checkbox.focus();
  await page.keyboard.press("Space");

  // Solving is real work — the whole point is that a keyboard user can start
  // it and be told when it finished.
  await expect(page.locator(".rc-captcha-label")).toHaveText("Verified", {
    timeout: 60_000,
  });
  await expect(checkbox).toHaveAttribute("aria-checked", "true");
  // Not marked disabled: the verified state is carried by aria-checked and
  // the announced label. Claiming `aria-disabled` would also make the element
  // non-actionable to anything reading ARIA — a behaviour change for existing
  // integrations, not an accessibility fix.
  await expect(checkbox).not.toHaveAttribute("aria-disabled", /.*/);
});

test("enter activates the challenge too", async ({ page }) => {
  await page.goto("/static/testsite.html?forceclick=1");
  await setupSite(page);

  await expect(page.locator("#rc-widget-tier")).toHaveText("hard_pow", {
    timeout: 30_000,
  });

  await page.locator(".rc-captcha-checkbox").focus();
  await page.keyboard.press("Enter");

  await expect(page.locator(".rc-captcha-label")).toHaveText("Verified", {
    timeout: 60_000,
  });
});

test("space on the checkbox does not scroll the page", async ({ page }) => {
  // Space is the activation key here, so its default scroll behaviour has to
  // be suppressed — otherwise activating the widget yanks it off screen.
  await page.goto("/static/testsite.html?forceclick=1");
  await setupSite(page);
  await page.evaluate(() => {
    document.body.style.minHeight = "4000px";
  });

  await page.locator(".rc-captcha-checkbox").focus();
  const before = await page.evaluate(() => window.scrollY);
  await page.keyboard.press("Space");
  await page.waitForTimeout(300);
  expect(await page.evaluate(() => window.scrollY)).toBe(before);
});

test("keyboard-only submission completes the whole form flow", async ({
  page,
}) => {
  // The end-to-end proof: no mouse events at any point.
  await page.goto("/static/testsite.html?forceclick=1");
  await setupSite(page);

  await expect(page.locator("#rc-widget-tier")).toHaveText("hard_pow", {
    timeout: 30_000,
  });

  // Dwell so the verify-time time-on-page band doesn't stack with the
  // no-pointer behaviour score — the exact combination that penalises a
  // keyboard user hardest.
  await page.waitForTimeout(2_500);

  await page.locator("#name").focus();
  await page.keyboard.type("Jane Doe");
  await page.keyboard.press("Tab");
  await page.keyboard.type("jane@example.com");

  await page.locator(".rc-captcha-checkbox").focus();
  await page.keyboard.press("Space");
  await expect(page.locator(".rc-captcha-label")).toHaveText("Verified", {
    timeout: 60_000,
  });

  await page.locator("#submit-btn").focus();
  await page.keyboard.press("Enter");

  const result = page.locator("#result-data");
  await expect(result).toBeVisible();
  await expect(result).toContainText('"success": true', { timeout: 15_000 });
});
