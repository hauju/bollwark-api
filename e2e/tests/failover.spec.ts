import { test, expect, Page } from "@playwright/test";

/**
 * Client failover, widget side.
 *
 * The server half is covered by Rust tests; what only a real browser can
 * exercise is the widget's decision to *stop being a hard blocker* when the
 * service is unreachable — the retry backoff, the minted claim, and the
 * in-place upgrade back to a solved token once the service returns.
 *
 * `/v1/puzzle` is intercepted rather than the server being stopped, so these
 * tests need no special server config: they assert what the widget emits, not
 * whether the server honors it.
 */

async function setupSite(page: Page) {
  await page.goto("/static/testsite.html");
  await page.click("#setup-btn");
  await expect(page.locator("#setup-btn")).toHaveText("Site Created", {
    timeout: 30_000,
  });
}

/** Decode the hidden `captcha-token` input the form host would forward. */
async function readToken(page: Page) {
  return page.evaluate(() => {
    const input = document.querySelector(
      'input[name="captcha-token"]'
    ) as HTMLInputElement | null;
    if (!input || !input.value) return null;
    const bytes = new Uint8Array(
      input.value.match(/../g)!.map((h) => parseInt(h, 16))
    );
    return JSON.parse(new TextDecoder().decode(bytes));
  });
}

test("unreachable service: widget mints a failover claim instead of blocking the form", async ({
  page,
}) => {
  await setupSite(page);

  // Count attempts to prove the backoff actually retried before giving up,
  // rather than falling open on the first blip.
  let attempts = 0;
  await page.route("**/v1/puzzle*", (route) => {
    attempts++;
    route.abort("connectionfailed");
  });

  const failoverEvent = page.evaluate(
    () =>
      new Promise<any>((resolve) => {
        document.addEventListener(
          "bollwark:puzzle",
          (e: any) => {
            if (e.detail && e.detail.failover) resolve(e.detail);
          },
          { once: false }
        );
      })
  );

  await page.evaluate(() => window.Bollwark._instances[0].reset());

  const detail = await failoverEvent;
  expect(detail.failover).toBe(true);
  expect(detail.ok).toBe(false);

  // 1 initial attempt + FAILOVER_RETRY_DELAYS_MS.length retries. The testsite's
  // own debug panel also hits /v1/puzzle, so assert a floor rather than equality.
  expect(attempts).toBeGreaterThanOrEqual(3);

  const token = await readToken(page);
  expect(token, "the form must still carry a token").not.toBeNull();
  expect(token.failover).toBe(true);
  expect(token.challenge_id).toBeUndefined();
  expect(typeof token.site_key).toBe("string");
  expect(typeof token.issued_at).toBe("number");
  // Behaviour is collected locally and survives the outage — it's the only
  // real evidence the server gets to score on this path.
  expect(token.behavior).toBeDefined();
});

test("a block-tier 429 does not fall back to failover", async ({ page }) => {
  // Failover is for "we couldn't reach you", never for "you answered and said
  // no". A 429 is a deliberate decision and must render as blocked.
  await setupSite(page);

  await page.route("**/v1/puzzle*", (route) =>
    route.fulfill({
      status: 429,
      contentType: "application/json",
      body: JSON.stringify({ error: "Rate limit exceeded", tier: "block" }),
    })
  );

  await page.evaluate(() => window.Bollwark._instances[0].reset());

  await expect
    .poll(
      () => page.evaluate(() => window.Bollwark._instances[0]._failover),
      { timeout: 20_000 }
    )
    .toBe(false);

  const token = await readToken(page);
  expect(
    token === null || token.failover !== true,
    "a 429 must not mint a failover claim"
  ).toBe(true);
});

test("recovery upgrades the failover claim to a real solved token", async ({
  page,
}) => {
  await setupSite(page);

  await page.route("**/v1/puzzle*", (route) => route.abort("connectionfailed"));
  await page.evaluate(() => window.Bollwark._instances[0].reset());

  await expect
    .poll(() => page.evaluate(() => window.Bollwark._instances[0]._failover), {
      timeout: 20_000,
    })
    .toBe(true);

  // Service comes back while the visitor is still filling in the form.
  await page.unroute("**/v1/puzzle*");

  // The recovery poll runs every FAILOVER_RECOVERY_POLL_MS (15s), then solves.
  await expect
    .poll(() => page.evaluate(() => window.Bollwark._instances[0]._failover), {
      timeout: 60_000,
      intervals: [1_000],
    })
    .toBe(false);

  const token = await readToken(page);
  expect(token.failover).toBeUndefined();
  expect(
    typeof token.challenge_id,
    "recovery must replace the claim with a real solve"
  ).toBe("string");
  expect(typeof token.nonce).toBe("number");
});
