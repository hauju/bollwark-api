# Bollwark

Self-hostable proof-of-work CAPTCHA service in Rust. Clients solve a memory-hard Argon2id (or SHA-256) puzzle to prove they aren't bots; the server brackets each solve with two scoring passes that adapt difficulty — or short-circuit — based on per-request risk signals.

- **Two-pass risk scoring.** A puzzle-time pass picks an escalation tier (invisible / checkbox / hard PoW / 429 block) and issues a proof-of-work puzzle at a tier-adjusted difficulty. A verify-time pass re-scores after submit using time-on-page, honeypot, and behavioural telemetry, returning `pass` / `shadow_fail` / `block`.
- **Pluggable signals.** Rate, header anomaly, honeypot, time-on-page, and behavioural telemetry are always on; IP reputation (CIDR list) and TLS fingerprint (read from a trusted reverse-proxy header) self-gate on their own config. The service is cookie-free — there's no global scoring toggle and no consent-triggering client storage; every signal runs under legitimate interest with data minimization.
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

For a full application walkthrough, see **[INTEGRATION.md](./INTEGRATION.md)**.

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

When `captcha-widget.js` is served from a different origin than your app, the widget automatically uses the script origin as the CAPTCHA API origin and loads the PoW worker through a same-page Blob wrapper. If you self-host or bundle the script somewhere else, set `data-server-url="https://your-captcha-host"` on the widget element.

For cross-origin embeds, allowlist your app origin on the puzzle endpoint:

```bash
CORS_ALLOWED_ORIGINS="https://your-app.example"
```

The service is cookie-free, so cross-origin embeds need no `SameSite` or credentials handling.

The widget evaluates its risk tier once on mount (matching Turnstile / hCaptcha behaviour), solves the PoW off-thread, and writes the resulting token into a hidden `<input name="captcha-token">` on submit. Your backend then calls `POST /v1/verify` with the site secret to confirm.

> **Token contract:** The widget writes a single **opaque token** (like Turnstile / hCaptcha) into the hidden input. Your form handler forwards it verbatim as `{"token": "<value>"}` in the `/v1/verify` body — no parsing required. The server unpacks the challenge id, PoW nonce, honeypot, and behaviour from inside the token. Dwell time is **not** carried in the token; it's derived server-side from the challenge's issuance timestamp, so a client can't claim a longer dwell than actually elapsed. Server-to-server callers that build the request themselves may instead send the explicit fields (`challenge_id` + `nonce`, optional `honeypot`/`behavior`).

## API

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /v1/sites` | Bearer (`ADMIN_TOKEN`) | Register a site. Returns `{ site_key, secret_key }`. Returns 404 when `ADMIN_TOKEN` is unset. |
| `GET /v1/puzzle?site_key=<uuid>` | None | Score the request and issue a PoW puzzle (`algorithm`/`prefix`/`difficulty`) for any non-block tier, or `429` for `block`. Cookie-free — never sets a cookie. |
| `POST /v1/verify` | Bearer (site secret) | Verify a solution. Body: either the opaque `token` from the widget, or explicit `challenge_id` plus `nonce`, with optional `honeypot`, `behavior`. Dwell time is derived server-side, not accepted from the client. |
| `GET /healthz` | None | Liveness probe. Always returns `200 ok`. |
| `GET /v1/admin/sessions[/:id]` | Bearer (`ADMIN_TOKEN`) | Decision log read API. Mounted only when `ADMIN_DB_PATH` is set. |
| `GET /v1/admin/stats` | Bearer (`ADMIN_TOKEN`) | Aggregate decision-log stats (counts, tier/decision breakdowns) for the dashboard. |
| `GET /v1/admin/sites` | Bearer (`ADMIN_TOKEN`) | List registered sites with activity aggregates from the decision log. |
| `POST /v1/admin/sites/:id/rotate` | Bearer (`ADMIN_TOKEN`) | Generate a new `secret_key` for a site; the old one is invalidated immediately. |
| `DELETE /v1/admin/sites/:id` | Bearer (`ADMIN_TOKEN`) | Delete a site. Future `/v1/verify` calls with its secret will fail. |

Static assets (`captcha-widget.js`, `captcha-widget.css`, `captcha-worker.js`, `admin.html`, `testsite.html`) are served from `/static/`.

## Configuration

Everything is env-var driven and every setting has a default — `cargo run` works out of the box with the always-on signals (rate, header anomaly, honeypot, time-on-page, behaviour) plus PoW; the service is cookie-free and IP reputation / TLS fingerprint self-gate on their own config. See **[CONFIGURATION.md](./CONFIGURATION.md)** for the full reference, score weights, and file formats. The most load-bearing knobs:

- `LISTEN_ADDR` (default `0.0.0.0:3000`), `RUST_LOG` (default `info`)
- `PUZZLE_ALGORITHM` — `argon2id` (default, memory-hard) or `sha256`. For Argon2id, tune `ARGON2_M_COST` / `ARGON2_T_COST` / `ARGON2_P_COST`.
- `DEFAULT_DIFFICULTY` / `MAX_DIFFICULTY` — base PoW difficulty and upper clamp, in leading zero bits. Defaults track the algorithm: `5` / `10` for argon2id, `18` / `28` for sha256.
- `TIER_CHECKBOX_MIN` / `TIER_HARD_POW_MIN` / `TIER_BLOCK_MIN` — puzzle-time score → tier thresholds.
- `VERIFY_SHADOW_MIN` / `VERIFY_BLOCK_MIN` — verify-time score thresholds.
- Optional signal inputs (off until configured): `IP_REPUTATION_FILE`, `TLS_FINGERPRINT_HEADER` (+ `TLS_FINGERPRINT_FILE`, `TRUSTED_PROXIES`).
- Validation dashboard: `ADMIN_DB_PATH` + `ADMIN_TOKEN`.

## Docker

Build and run locally:

```bash
docker build -t bollwark .
docker run --rm -p 3000:3000 \
  -e ADMIN_TOKEN=<long-random-secret> \
  -e SITE_DB_PATH=/data/sites.db \
  -v bollwark-data:/data \
  bollwark
```

The image exposes port `3000`, serves static widget assets from `/static`, and keeps runtime configuration env-var driven. CI publishes `dcr.oxidt.com/bollwark:latest` and `dcr.oxidt.com/bollwark:<commit-sha>` from `main`.

Public multi-arch images are published to `ghcr.io/hauju/bollwark`. For self-hosting — compose quickstart, reverse-proxy and persistence notes, Coolify setup — see **[DEPLOYMENT.md](./DEPLOYMENT.md)**.

## Architecture

```
src/
  api/         Axum router, handlers orchestrating both scoring passes
  puzzle/      PoW engine — SHA-256 and Argon2id, shared leading-zero check
  risk/        Signals (rate, headers, reputation, TLS fingerprint),
               puzzle-time RiskScorer, verify-time VerifyScorer, behaviour
  storage/     Store trait + in-memory implementation (Redis/Mongo planned)
  dashboard/   SQLite decision log + /v1/admin/* read API
  site/        Site registration types
  config.rs    AppConfig from env
  error.rs     CaptchaError → IntoResponse
static/        Embeddable widget, Web Worker, admin UI, test harness
```

Two passes bracket every successful solve:

1. **Puzzle-time** (`GET /v1/puzzle`): score the request, pick an `EscalationTier`, issue a PoW puzzle at a tier-adjusted difficulty, or return `429` for `Block`.
2. **Verify-time** (`POST /v1/verify`): after the PoW check passes, re-score using submit-only signals and return `Pass` / `ShadowFail` (success + WARN log) / `Block`.

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
- **Load generator** — `cargo run --release --example loadgen -- --base http://127.0.0.1:3000 --requests 200 --concurrency 16` drives four scenarios (`happy`, `no_ua`, `burst`, `full_solve`) and prints latency percentiles + tier distribution. For `full_solve`, run the server with `DEFAULT_DIFFICULTY=12 MAX_DIFFICULTY=16`.
- **Playwright e2e** — `cd e2e && bun install && bunx playwright install chromium && bun run test`. Auto-spawns `cargo run`; set `CAPTCHA_REUSE_SERVER=1` to reuse a server you started yourself (so you can capture its JSONL).

Requires Rust 1.85+ (edition 2024).

## License

MIT — see [LICENSE](LICENSE). The vendored `static/vendor/argon2.umd.min.js` (hash-wasm) is also MIT; see `static/vendor/README.md`.
