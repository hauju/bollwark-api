import { defineConfig, devices } from "@playwright/test";

const baseURL = process.env.CAPTCHA_BASE_URL ?? "http://127.0.0.1:3000";
const reuseServer = process.env.CAPTCHA_REUSE_SERVER === "1";

export default defineConfig({
  testDir: "./tests",
  timeout: 120_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    baseURL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: reuseServer
    ? undefined
    : {
        // `cargo run` (release would be much faster but slower to build).
        // LOG_FORMAT=json so the JSONL captured during e2e is parseable.
        command: "cargo run --quiet",
        cwd: "..",
        env: {
          LOG_FORMAT: "json",
          RUST_LOG: "info,rust_captcha=debug",
          // Lower difficulty so the widget solves PoW within the page lifetime.
          DEFAULT_DIFFICULTY: "12",
          MIN_DIFFICULTY: "8",
          MAX_DIFFICULTY: "16",
          // Lower the checkbox/hard-pow thresholds so the rate signal can
          // visibly escalate the tier inside the spam test (~30 requests).
          // Push visual/block thresholds high so we never get 429'd mid-test.
          TIER_CHECKBOX_MIN: "8",
          TIER_HARD_POW_MIN: "15",
          TIER_VISUAL_MIN: "200",
          TIER_BLOCK_MIN: "250",
          // Verify-time thresholds left at default (shadow_min=30, block_min=60)
          // so the browser-harness-simulator bot signature (webdriver=30 +
          // no_pointer=15 + time<500=50 = 95) blocks. Legit tests insert a
          // waitForTimeout(>2s) before submit so time-on-page lands in the
          // "0 score" band and they stay below block_min.
          // Let the testsite's autoSetup() call POST /v1/sites without an
          // ADMIN_TOKEN. Debug-build only — the server refuses to honour
          // this in a release binary.
          DEV_DISABLE_ADMIN_AUTH: "1",
        },
        url: `${baseURL}/static/testsite.html`,
        reuseExistingServer: true,
        timeout: 120_000,
        stdout: "pipe",
        stderr: "pipe",
      },
});
