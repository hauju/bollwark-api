import { test, expect, Page } from "@playwright/test";

/**
 * End-to-end against the Argon2id server (PUZZLE_ALGORITHM=argon2id on :3001,
 * booted by playwright.config.ts). Uses absolute URLs because the widget
 * resolves its API base from the script origin — loading testsite.html from
 * :3001 makes every /v1/* call hit the argon2id server.
 *
 * Asserts both the wire shape (algorithm = {argon2id: {...}}) and that the
 * worker actually solves the memory-hard puzzle via the vendored hash-wasm
 * bundle, ending in a server-side verify success.
 */

const ARGON2ID_BASE =
  process.env.CAPTCHA_ARGON2ID_BASE_URL ?? "http://127.0.0.1:3001";

async function setupSite(page: Page) {
  await page.goto(`${ARGON2ID_BASE}/static/testsite.html`);
  await page.click("#setup-btn");
  await expect(page.locator("#setup-btn")).toHaveText("Site Created", {
    timeout: 30_000,
  });
}

test("argon2id: puzzle carries argon2id params and widget solves + verifies", async ({
  page,
}) => {
  // Capture the widget's eager puzzle fetch so we can inspect the wire shape.
  const puzzlePromise = page.waitForResponse(
    (r) => r.url().includes("/v1/puzzle") && r.status() === 200,
    { timeout: 30_000 },
  );

  await setupSite(page);

  const puzzle = await (await puzzlePromise).json();

  // SHA-256 serialises as the bare string "sha256"; Argon2id as a tagged
  // object {argon2id: {m_cost, t_cost, p_cost}}. The worker dispatches on
  // exactly this shape.
  expect(typeof puzzle.algorithm).toBe("object");
  expect(puzzle.algorithm.argon2id).toMatchObject({
    m_cost: 1024,
    t_cost: 1,
    p_cost: 1,
  });

  // Widget has its tier; sit out the verify-time time-on-page band (<500ms
  // scores +50) so we don't trip the block threshold.
  await expect(page.locator("#rc-widget-tier")).not.toHaveText("—", {
    timeout: 30_000,
  });
  await page.waitForTimeout(2_500);

  await page.fill("#name", "Jane Doe");
  await page.fill("#email", "jane@example.com");

  const checkbox = page.locator(".rc-captcha-checkbox");
  if (await checkbox.isVisible()) {
    await checkbox.click();
  }

  // Worker brute-forces the Argon2id nonce off the main thread.
  await expect(page.locator(".rc-captcha-label")).toHaveText("Verified", {
    timeout: 60_000,
  });

  await page.click("#submit-btn");

  const result = page.locator("#result-data");
  await expect(result).toBeVisible();
  await expect(result).toContainText('"success": true', { timeout: 15_000 });
});
