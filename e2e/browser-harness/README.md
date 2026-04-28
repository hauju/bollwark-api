# Agentic adversarial test (browser-harness)

Run an LLM-driven [browser-harness](https://github.com/browser-use/browser-harness) agent against the captcha-protected form in `static/testsite.html`. The goal is to confirm the captcha rejects (or shadow-fails) a default-configured agentic attack — a real Chrome driven over CDP by an LLM.

## Two layers

This directory is the **manual / agentic** test. It needs an LLM and a Chrome instance with remote debugging enabled, and is not safe to run in CI without API key budget.

For CI, see `e2e/tests/browser-harness-simulator.spec.ts` — a deterministic Playwright spec that simulates the *same interaction pattern* (CDP-driven Chrome, programmatic clicks, no mouse movement) without an LLM. That asserts the same defensive behaviour.

## Setup (one-time)

1. Install browser-harness per [upstream README](https://github.com/browser-use/browser-harness):
   ```sh
   git clone https://github.com/browser-use/browser-harness ~/src/browser-harness
   cd ~/src/browser-harness
   uv tool install -e .
   ```
2. Wire it into your local Claude Code by adding to `~/.claude/CLAUDE.md`:
   ```
   @~/src/browser-harness/SKILL.md
   ```
3. Launch Chrome with remote debugging — `browser-harness --setup` will guide you.

## Running the test

1. Start the captcha server with structured logs in one terminal:
   ```sh
   cd <repo-root>
   LOG_FORMAT=json RUST_LOG=info cargo run --release \
     | tee /tmp/captcha-decisions.jsonl
   ```
   Optional: also enable Argon2id PoW to test the cost path:
   ```sh
   PUZZLE_ALGORITHM=argon2id ARGON2_M_COST=8192 ARGON2_T_COST=2 DEFAULT_DIFFICULTY=4 …
   ```
2. In another Claude Code session (with browser-harness skill loaded), give the agent the task in [`AGENT_TASK.md`](./AGENT_TASK.md). The agent will drive Chrome to the testsite and try to submit the form.
3. Inspect the captured JSONL for `verify_decision` events — the expected outcome is `outcome=block` (or, at worst, `outcome=shadow_fail`):
   ```sh
   jq -c 'select(.fields.event=="verify_decision")' /tmp/captcha-decisions.jsonl
   ```

## What you're measuring

| Field on the verify_decision event | What it tells you |
|---|---|
| `outcome` | `pass` = agent slipped through; `shadow_fail` = caught but soft; `block` = caught and hard-blocked |
| `webdriver` | `true` = vanilla CDP-driven Chrome; `false` = stealth-patched (uncommon for default browser-harness) |
| `sig_behavior` | Behaviour signal contribution to the score. 30+ implies flatline; 15 implies clicks-without-pointer |
| `sig_time_on_page` | 50 if submission was <500ms after mount; 25 if <2s |
| `score` / `tier` (puzzle_decision) | Risk score at puzzle issuance — affects difficulty bump |

## Calibration tip

If the agent consistently reaches `pass`, the behaviour signal weights are too low for your threat model. Bump `BEHAVIOR_*_SCORE` constants in `src/risk/behavior.rs` and re-run.
