import { defineConfig, devices } from "@playwright/test";

const baseURL = process.env.CAPTCHA_BASE_URL ?? "http://127.0.0.1:3000";
// Second server, identical config except it issues Argon2id puzzles. The
// argon2id.spec.ts navigates here with absolute URLs so the widget (which
// resolves its API base from the script origin) talks to this server.
const argon2idURL =
  process.env.CAPTCHA_ARGON2ID_BASE_URL ?? "http://127.0.0.1:3001";
const reuseServer = process.env.CAPTCHA_REUSE_SERVER === "1";

// Shared env for both dev servers. Argon2id overrides difficulty + algorithm.
const sharedEnv: Record<string, string> = {
  LOG_FORMAT: "json",
  RUST_LOG: "info,bollwark=debug",
  TIER_CHECKBOX_MIN: "8",
  TIER_HARD_POW_MIN: "15",
  TIER_VISUAL_MIN: "200",
  TIER_BLOCK_MIN: "250",
  FULL_FINGERPRINT_MODE: "1",
  DEV_DISABLE_ADMIN_AUTH: "1",
};

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
    : [
        {
          // SHA-256 server (default algorithm) on :3000 — the baseURL host.
          // `cargo run` (release would be much faster but slower to build).
          // LOG_FORMAT=json so the JSONL captured during e2e is parseable.
          command: "cargo run --quiet",
          cwd: "..",
          env: {
            ...sharedEnv,
            LISTEN_ADDR: "127.0.0.1:3000",
            // Lower difficulty so the widget solves PoW within the page lifetime.
            DEFAULT_DIFFICULTY: "12",
            MAX_DIFFICULTY: "16",
            // Verify-time thresholds left at default (shadow_min=30, block_min=60)
            // so the browser-harness-simulator bot signature (webdriver=30 +
            // no_pointer=15 + time<500=50 = 95) blocks. Legit tests insert a
            // waitForTimeout(>2s) before submit so time-on-page lands in the
            // "0 score" band and they stay below block_min.
          },
          url: `${baseURL}/static/testsite.html`,
          reuseExistingServer: true,
          timeout: 120_000,
          stdout: "pipe",
          stderr: "pipe",
        },
        {
          // Argon2id server on :3001 for argon2id.spec.ts. Memory-hard hashes
          // are orders of magnitude slower than SHA-256, so use light Argon2
          // params + a low difficulty to keep an in-browser solve sub-second.
          command: "cargo run --quiet",
          cwd: "..",
          env: {
            ...sharedEnv,
            LISTEN_ADDR: "127.0.0.1:3001",
            PUZZLE_ALGORITHM: "argon2id",
            ARGON2_M_COST: "1024",
            ARGON2_T_COST: "1",
            ARGON2_P_COST: "1",
            DEFAULT_DIFFICULTY: "6",
            MAX_DIFFICULTY: "10",
          },
          url: `${argon2idURL}/static/testsite.html`,
          reuseExistingServer: true,
          timeout: 120_000,
          stdout: "pipe",
          stderr: "pipe",
        },
      ],
});
