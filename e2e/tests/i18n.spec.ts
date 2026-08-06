import { test, expect, Page } from "@playwright/test";

/**
 * Widget localisation against static/testsite.html.
 *
 * The harness's `?lang=` param retags `<html lang>` before /v1/widget.js
 * loads, which is the source the widget prefers over `navigator.language` —
 * a widget inside a German form should read German even for a visitor whose
 * browser is set to English.
 */

async function setupSite(page: Page) {
  await page.click("#setup-btn");
  await expect(page.locator("#setup-btn")).toHaveText("Site Created", {
    timeout: 30_000,
  });
}

test("german document renders german chrome and tags it for screen readers", async ({
  page,
}) => {
  await page.goto("/static/testsite.html?lang=de");

  await expect(page.locator(".rc-captcha-label")).toHaveText(
    "Ich bin kein Roboter"
  );
  // Without lang on the container a screen reader reads the German string
  // with the document's voice, which defeats the point of translating it.
  await expect(page.locator(".rc-captcha")).toHaveAttribute("lang", "de");
  // Brand-corner links are translated too — they are the visitor's route to
  // "why am I seeing this?" and are useless in a language they don't read.
  await expect(
    page.locator(".rc-captcha-brand-links a").first()
  ).toHaveText("Datenschutz");
});

test("regional tag falls back to its base language", async ({ page }) => {
  // `de-AT` has no table of its own; it must resolve to `de` rather than
  // dropping all the way to English.
  await page.goto("/static/testsite.html?lang=de-AT");

  await expect(page.locator(".rc-captcha-label")).toHaveText(
    "Ich bin kein Roboter"
  );
  await expect(page.locator(".rc-captcha")).toHaveAttribute("lang", "de");
});

test("unknown language falls back to english", async ({ page }) => {
  await page.goto("/static/testsite.html?lang=x-klingon");

  await expect(page.locator(".rc-captcha-label")).toHaveText("I'm not a robot");
  await expect(page.locator(".rc-captcha")).toHaveAttribute("lang", "en");
});

test("state labels are translated through a full verify, not just at mount", async ({
  page,
}) => {
  // The mount-time string is the easy one. This asserts the label the visitor
  // actually ends on — driven by `_updateUI`, a separate lookup path.
  await page.goto("/static/testsite.html?lang=de");
  await setupSite(page);

  await expect(page.locator("#rc-widget-tier")).not.toHaveText("—", {
    timeout: 30_000,
  });

  const checkbox = page.locator(".rc-captcha-checkbox");
  if (await checkbox.isVisible()) {
    await checkbox.click();
  }

  await expect(page.locator(".rc-captcha-label")).toHaveText("Bestätigt", {
    timeout: 60_000,
  });
});
