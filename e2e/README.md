# e2e

Playwright end-to-end tests against `static/testsite.html`.

## Run

```bash
bun install
bunx playwright install chromium  # one-time
bun run test                      # boots `cargo run` itself
```

The suite drives **two** auto-spawned servers: a SHA-256 server on `:3000`
(the baseURL) and an Argon2id server on `:3001` for `argon2id.spec.ts`.

Set `CAPTCHA_REUSE_SERVER=1` to skip the auto-spawned servers (useful when you
already have one running and want to capture its JSON logs):

```bash
# terminal A — match the env that playwright.config.ts sets for the auto-spawned
# server: DEV_DISABLE_ADMIN_AUTH=1 so the testsite can register a site without
# a bearer, and lowered tier thresholds so the rate-spam test escalates quickly.
LOG_FORMAT=json RUST_LOG=info,bollwark=debug \
  DEV_DISABLE_ADMIN_AUTH=1 \
  TIER_CHECKBOX_MIN=8 TIER_HARD_POW_MIN=15 TIER_BLOCK_MIN=250 \
  DEFAULT_DIFFICULTY=12 MAX_DIFFICULTY=16 \
  cargo run 2> e2e-run.jsonl

# terminal B — argon2id.spec.ts needs an Argon2id server on :3001 (light
# params + low difficulty so an in-browser solve stays sub-second).
LOG_FORMAT=json RUST_LOG=info,bollwark=debug \
  DEV_DISABLE_ADMIN_AUTH=1 PUZZLE_ALGORITHM=argon2id \
  ARGON2_M_COST=1024 ARGON2_T_COST=1 ARGON2_P_COST=1 \
  DEFAULT_DIFFICULTY=6 MAX_DIFFICULTY=10 \
  TIER_CHECKBOX_MIN=8 TIER_HARD_POW_MIN=15 TIER_BLOCK_MIN=250 \
  LISTEN_ADDR=127.0.0.1:3001 cargo run 2> e2e-argon2id.jsonl

# terminal C
CAPTCHA_REUSE_SERVER=1 bun run test
```

The JSONL stream from terminal A is what you analyze afterwards. Decision
events have `"event": "puzzle_decision"` or `"event": "verify_decision"`:

```bash
jq -c 'select(.event == "puzzle_decision") | {tier, score, outcome}' e2e-run.jsonl | sort | uniq -c
jq -c 'select(.event == "verify_decision") | {outcome, score}'      e2e-run.jsonl | sort | uniq -c
```
