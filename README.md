# rust-captcha

Self-hostable proof-of-work CAPTCHA service in Rust. Clients solve a SHA-256 (or Argon2id) puzzle to prove they aren't bots; the server brackets each solve with two scoring passes that adapt difficulty — or short-circuit — based on per-request risk signals.

- **Two-pass risk scoring.** A puzzle-time pass picks an escalation tier (invisible / checkbox / hard PoW / 429). A verify-time pass re-scores after submit using time-on-page, cookie age, honeypot, and behavioural telemetry, returning `pass` / `shadow_fail` / `block`.
- **Pluggable signals.** Rate, header anomaly, IP reputation (CIDR list), cookie age (HMAC-signed `__captcha_trust`), and TLS fingerprint (read from a trusted reverse-proxy header). Each optional signal is gated by its own env var.
- **Drop-in browser widget.** `static/captcha-widget.js` mounts on a `<div data-sitekey="…">`, runs the PoW in a Web Worker, and posts a token into your form. SHA-256 uses `crypto.subtle`; Argon2id uses a vendored hash-wasm build.
- **Validation dashboard.** Optional SQLite-backed decision log with a vanilla-JS admin UI for inspecting puzzle/verify sessions.

## Quickstart

```bash
cargo run                                # listens on 0.0.0.0:3000
```

Set an admin token and register a site, then issue and verify a puzzle:

```bash
export ADMIN_TOKEN=$(openssl rand -hex 32)
SITE_DB_PATH=tmp/sites.db cargo run

# 1. Register a site → returns { site_key, secret_key }
curl -s -X POST http://localhost:3000/v1/sites \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"my-site"}' | jq

# 2. Fetch a puzzle (anonymous; widget does this for you)
curl -s "http://localhost:3000/v1/puzzle?site_key=<SITE_KEY>" | jq

# 3. Server-to-server verify (Bearer = secret_key)
curl -s -X POST http://localhost:3000/v1/verify \
  -H "Authorization: Bearer <SECRET_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"challenge_id":"…","nonce":"…"}'
```

Without `ADMIN_TOKEN`, `POST /v1/sites` returns 404 — no anonymous provisioning. Without `SITE_DB_PATH`, sites live only in memory and are lost on restart.

Open `http://localhost:3000/static/testsite.html` for a working harness that exercises the full flow against a freshly registered site.

## Embedding the widget

```html
<link rel="stylesheet" href="https://your-host/static/captcha-widget.css">

<form action="/signup" method="post">
  <!-- … -->
  <div id="captcha" data-sitekey="<SITE_KEY>"></div>
  <button type="submit">Register</button>
</form>

<script src="https://your-host/static/captcha-widget.js"></script>
```

The widget evaluates its risk tier once on mount (matching Turnstile / hCaptcha behaviour), solves the PoW off-thread, and writes the resulting token into a hidden `cf-turnstile-response`-style input on submit. Your backend then calls `POST /v1/verify` with the site secret to confirm.

## API

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /v1/sites` | Bearer (`ADMIN_TOKEN`) | Register a site. Returns `{ site_key, secret_key }`. Returns 404 when `ADMIN_TOKEN` is unset. |
| `GET /v1/puzzle?site_key=<uuid>` | None | Score the request and either issue a puzzle or short-circuit with `429` when the tier is `visual_challenge` or `block`. May set the `__captcha_trust` cookie. |
| `POST /v1/verify` | Bearer (site secret) | Verify a solution. Body: `challenge_id`, `nonce`, optional `honeypot`, `time_on_page_ms`, `behavior`. |
| `GET /v1/admin/sessions[/:id]` | Bearer (`ADMIN_TOKEN`) | Decision log read API. Mounted only when `ADMIN_DB_PATH` is set. |

Static assets (`captcha-widget.js`, `captcha-widget.css`, `captcha-worker.js`, `admin.html`, `testsite.html`) are served from `/static/`.

## Configuration

Everything is env-var driven and every setting has a default — `cargo run` works out of the box with rate + header-anomaly signals only. See **[CONFIGURATION.md](./CONFIGURATION.md)** for the full reference, score weights, and file formats. The most load-bearing knobs:

- `LISTEN_ADDR` (default `0.0.0.0:3000`), `RUST_LOG` (default `info`)
- `PUZZLE_ALGORITHM` — `sha256` (default) or `argon2id`. With Argon2id, drop `DEFAULT_DIFFICULTY` to `4`–`6` and tune `ARGON2_M_COST` / `ARGON2_T_COST` / `ARGON2_P_COST`.
- `DEFAULT_DIFFICULTY` / `MIN_DIFFICULTY` / `MAX_DIFFICULTY` — PoW difficulty in leading zero bits (`20` / `16` / `28`).
- `TIER_CHECKBOX_MIN` / `TIER_HARD_POW_MIN` / `TIER_VISUAL_MIN` / `TIER_BLOCK_MIN` — puzzle-time score → tier thresholds.
- `VERIFY_SHADOW_MIN` / `VERIFY_BLOCK_MIN` — verify-time score thresholds.
- Optional signals (off until set): `IP_REPUTATION_FILE`, `COOKIE_SIGNING_SECRET` (+ `COOKIE_SECURE`), `TLS_FINGERPRINT_HEADER` (+ `TLS_FINGERPRINT_FILE`, `TRUSTED_PROXIES`).
- Validation dashboard: `ADMIN_DB_PATH` + `ADMIN_TOKEN`.

## Architecture

```
src/
  api/         Axum router, handlers orchestrating both scoring passes
  puzzle/      PoW engine — SHA-256 and Argon2id, shared leading-zero check
  risk/        Signals (rate, headers, reputation, cookie, TLS fingerprint),
               puzzle-time RiskScorer, verify-time VerifyScorer, behaviour
  storage/     Store trait + in-memory implementation (Redis/Mongo planned)
  dashboard/   SQLite decision log + /v1/admin/* read API
  site/        Site registration types
  config.rs    AppConfig from env
  error.rs     CaptchaError → IntoResponse
static/        Embeddable widget, Web Worker, admin UI, test harness
```

Two passes bracket every successful solve:

1. **Puzzle-time** (`GET /v1/puzzle`): score the request, pick an `EscalationTier`, issue at a tier-adjusted difficulty or return `429`.
2. **Verify-time** (`POST /v1/verify`): after PoW passes, re-score using submit-only signals and return `Pass` / `ShadowFail` (success + WARN log) / `Block`.

Challenges are single-use and deleted after a successful PoW verification — even if the verify-time decision is `Block`.

## Development

```bash
cargo build
cargo test                     # unit + integration
cargo clippy -- -D warnings
cargo fmt
```

A `justfile` wraps these (`just build`, `just test`, `just lint`, `just ci`).

### Validation harnesses

- **Structured logs** — `LOG_FORMAT=json cargo run` emits JSONL on stderr. `event=puzzle_decision` and `event=verify_decision` carry the score, tier/decision, signal breakdown, and outcome. Pipe through `jq -c 'select(.event == "puzzle_decision")'` for clean parsing.
- **Load generator** — `cargo run --release --example loadgen -- --base http://127.0.0.1:3000 --requests 200 --concurrency 16` drives four scenarios (`happy`, `no_ua`, `burst`, `full_solve`) and prints latency percentiles + tier distribution. For `full_solve`, run the server with `DEFAULT_DIFFICULTY=12 MIN_DIFFICULTY=8 MAX_DIFFICULTY=16`.
- **Playwright e2e** — `cd e2e && bun install && bunx playwright install chromium && bun run test`. Auto-spawns `cargo run`; set `CAPTCHA_REUSE_SERVER=1` to reuse a server you started yourself (so you can capture its JSONL).

Requires Rust 1.85+ (edition 2024).
