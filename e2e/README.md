# e2e

Playwright end-to-end tests against `static/testsite.html`.

## Run

```bash
bun install
bunx playwright install chromium  # one-time
bun run test                      # boots `cargo run` itself
```

Set `CAPTCHA_REUSE_SERVER=1` to skip the auto-spawned server (useful when you
already have one running and want to capture its JSON logs):

```bash
# terminal A
LOG_FORMAT=json RUST_LOG=info,rust_captcha=debug \
  DEFAULT_DIFFICULTY=12 MIN_DIFFICULTY=8 MAX_DIFFICULTY=16 \
  TIER_VISUAL_MIN=200 TIER_BLOCK_MIN=250 \
  cargo run 2> e2e-run.jsonl

# terminal B
CAPTCHA_REUSE_SERVER=1 bun run test
```

The JSONL stream from terminal A is what you analyze afterwards. Decision
events have `"event": "puzzle_decision"` or `"event": "verify_decision"`:

```bash
jq -c 'select(.event == "puzzle_decision") | {tier, score, outcome}' e2e-run.jsonl | sort | uniq -c
jq -c 'select(.event == "verify_decision") | {outcome, score}'      e2e-run.jsonl | sort | uniq -c
```
