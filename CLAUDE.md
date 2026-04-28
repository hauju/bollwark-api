# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
cargo build                              # Build
cargo run                                # Run server (listens on 0.0.0.0:3000)
cargo test                               # Run all tests (unit + integration)
cargo test --lib                         # Unit tests only
cargo test --test api_integration        # Integration tests only
cargo test puzzle::challenge::tests      # Single test module
cargo test test_full_flow                # Single test by name
cargo clippy -- -D warnings              # Lint (warnings → errors)
cargo fmt                                # Format
```

A `justfile` wraps these (`just build`, `just test`, `just lint`, `just ci`). `just ci` runs `fmt-check + lint + test`.

### Observability & validation harnesses

- `LOG_FORMAT=json cargo run` emits structured JSONL on stderr. Decision events: `event=puzzle_decision` (per `/v1/puzzle`, with score / tier / signal breakdown / outcome=`issued|rejected`) and `event=verify_decision` (per `/v1/verify`, with score / decision-derived outcome=`pass|shadow_fail|block|pow_invalid` and the verify-side breakdown). Use `jq -c 'select(.event == "puzzle_decision")'` for clean parsing.
- `cargo run --release --example loadgen -- --base http://127.0.0.1:3000 --requests 200 --concurrency 16` drives 4 synthetic scenarios (`happy`, `no_ua`, `burst`, `full_solve`) and prints latency percentiles + tier distribution per scenario. Use `--only` to pick a subset. `full_solve` does real PoW on the client, so run the server with `DEFAULT_DIFFICULTY=12 MIN_DIFFICULTY=8 MAX_DIFFICULTY=16` to keep solve times sub-second.
- `cd e2e && bun install && bunx playwright install chromium && bun run test` runs Playwright against `static/testsite.html`. Auto-spawns `cargo run` itself; set `CAPTCHA_REUSE_SERVER=1` to reuse a server you already started (so you can capture its JSONL).

## Configuration

All runtime config is via environment variables; every setting has a default. **`CONFIGURATION.md` is the source of truth** — env var descriptions, score weights, file formats (CIDR reputation list, TLS fingerprint blocklist), and a production-leaning example are documented there. The most load-bearing knobs:

- `LISTEN_ADDR` (default `0.0.0.0:3000`), `RUST_LOG` (default `info`)
- `PUZZLE_ALGORITHM` (default `sha256`; alternative `argon2id`). When `argon2id` is selected, `ARGON2_M_COST` / `ARGON2_T_COST` / `ARGON2_P_COST` (defaults `8192`/`2`/`1`) tune memory/iterations/lanes — and `DEFAULT_DIFFICULTY` should be dropped to ~4–6 since each hash is much more expensive than SHA-256.
- `DEFAULT_DIFFICULTY` / `MIN_DIFFICULTY` / `MAX_DIFFICULTY` — PoW difficulty in leading zero bits (default `20` / `16` / `28`)
- `CHALLENGE_TTL_SECS` / `CLEANUP_INTERVAL_SECS` — challenge expiry + sweeper cadence
- `TIER_CHECKBOX_MIN` / `TIER_HARD_POW_MIN` / `TIER_VISUAL_MIN` / `TIER_BLOCK_MIN` — puzzle-time score → tier thresholds (defaults `20`/`40`/`65`/`85`)
- `VERIFY_SHADOW_MIN` / `VERIFY_BLOCK_MIN` — verify-time score thresholds (defaults `30` / `60`)
- Optional signal toggles, each disabled when its env var is unset: `IP_REPUTATION_FILE`, `COOKIE_SIGNING_SECRET` (+ `COOKIE_SECURE`), `TLS_FINGERPRINT_HEADER` (+ `TLS_FINGERPRINT_FILE`, `TRUSTED_PROXIES`).
- Validation dashboard: `ADMIN_DB_PATH` enables SQLite-backed decision logging + the admin endpoints; `ADMIN_TOKEN` is the bearer token for `/v1/admin/*` and is required when the path is set. Browser UI is `static/admin.html`.

## Architecture

Self-hostable proof-of-work CAPTCHA service. Clients solve SHA-256 puzzles (find a nonce that produces a hash with N leading zero bits) to prove they are not bots. Rust edition 2024.

Two scoring passes bracket every successful solve:

1. **Puzzle-time** (`GET /v1/puzzle`): score the request, pick an `EscalationTier`, either issue a puzzle at a tier-adjusted difficulty or short-circuit with `429`.
2. **Verify-time** (`POST /v1/verify`): after the PoW check passes, run a second scoring pass on signals only available at submit (time-on-page, cookie age now, honeypot, behavioural telemetry). Decision is `Pass` / `ShadowFail` (return `success: true` but emit a WARN log) / `Block` (return `success: false`).

### Module Layout

- **`puzzle/`** — Core PoW engine. `challenge.rs` generates challenges and verifies solutions, dispatching on `Algorithm` (SHA-256 via `compute_sha256` or Argon2id via `compute_argon2id`) and reusing `has_leading_zero_bits()` for both. `difficulty.rs` is the legacy adaptive-difficulty calculator (still constructed in `AppState` but superseded by the risk pipeline). `solve_challenge()` / `solve_argon2id_challenge()` are brute-force solvers used only in tests.
- **`risk/`** — Scoring + escalation. Each signal lives in its own module so it can be disabled by config:
  - `signals.rs` — always-on scorers: `score_rate` (per-IP + per-site, 60s window) and `score_header_anomaly` (UA / Accept-Language / Accept-Encoding). Also defines `CookiePresence` and `score_cookie_age`.
  - `reputation.rs` — `CidrListReputation` loaded from `IP_REPUTATION_FILE`; categories `tor`/`datacenter`/`vpn`/`residential`.
  - `cookie.rs` — `CookieSigner` (HMAC-SHA256), `extract_cookie`, `set_cookie_header`. Stateless, self-validating `__captcha_trust` cookie.
  - `tls_fingerprint.rs` — `TrustedProxies` CIDR allowlist + `FingerprintBlocklist`. Header is only honored when the immediate peer is in the trusted-proxies list.
  - `score.rs` — `RiskScorer` aggregates a `SignalContext` (ip, headers, counts, cookie, fingerprint) into a `RiskScore { total, breakdown, tier }` for puzzle-time.
  - `verify.rs` — `VerifyScorer` aggregates a `VerifyContext` into a `VerifyScore { total, breakdown, decision }`. Honeypot scores +100 (always blocks); time-on-page bands at <500ms (+50) and <2000ms (+25); cookie age reuses `score_cookie_age`; behaviour reuses `score_behavior`.
  - `behavior.rs` — `BehaviorReport` (mouse moves, touches, interactions, first-interaction ms) collected by the widget and submitted in `/v1/verify`. Flatline (zero events) scores +30; click-without-pointer scores +15; sub-50ms first interaction adds +20. `BehaviorPresence::Absent` (legacy clients with no blob) scores 0.
  - `tier.rs` — `EscalationTier` (`InvisiblePass` / `Checkbox` / `HardPow` / `VisualChallenge` / `Block`) and `difficulty_for(tier, default, max)` which returns `None` for `VisualChallenge`/`Block` (caller short-circuits with 429).
- **`dashboard/`** — Validation dashboard. `log.rs` (`DecisionLog`) owns a writer thread that drains an unbounded channel into SQLite. `query.rs` (`Sessions`) opens read-only connections in `spawn_blocking` for list/detail queries; database is in WAL mode so reads run concurrent with writes. `routes.rs` defines `GET /v1/admin/sessions` and `/sessions/:id` behind a bearer-token check. `types.rs` holds the per-decision records (`PuzzleRecord`, `VerifyRecord`) emitted from handlers and the JSON DTOs returned to the dashboard. The dashboard HTML is `static/admin.html` (vanilla JS, no build step).
- **`storage/`** — `Store` trait defines the async storage interface. `memory.rs` is the in-memory implementation using `RwLock<HashMap>`. The trait is designed for future Redis/MongoDB backends.
- **`api/`** — Axum router. `handlers.rs` contains the three handlers and is where the puzzle-time + verify-time scoring is orchestrated. `state.rs` defines `AppState` (shared via `Arc`), `tier_thresholds_from_config`, and `verify_thresholds_from_config`. `middleware.rs` has Bearer token extraction helpers.
- **`site/`** — Site registration types (`site_key` + `secret_key`).
- **`error.rs`** — `CaptchaError` enum implementing `IntoResponse` for Axum error mapping.
- **`config.rs`** — `AppConfig` loaded from environment variables with defaults.
- **`static/`** — Bundled browser widget served by `tower-http`'s `ServeDir`. `captcha-widget.js` + `captcha-widget.css` are the embeddable widget; `captcha-worker.js` is the Web Worker that solves the PoW off the main thread (dispatches on the wire `algorithm` field — SHA-256 via `crypto.subtle`, Argon2id via the vendored `static/vendor/argon2.umd.min.js` from hash-wasm); `testsite.html` is a local harness.

### API Endpoints

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /v1/puzzle?site_key=<uuid>` | None | Score request, issue a PoW challenge (or 429 if tier ≥ `VisualChallenge`). May set `__captcha_trust` cookie. |
| `POST /v1/verify` | Bearer (site secret) | Verify a solution server-to-server. Body fields: `challenge_id`, `nonce`, optional `honeypot`, optional `time_on_page_ms`, optional `behavior`. |
| `POST /v1/sites` | None | Register a site, returns site_key + secret. |
| `GET /v1/admin/sessions` | Bearer (`ADMIN_TOKEN`) | List recent puzzle/verify sessions for the dashboard. Only mounted when `ADMIN_DB_PATH` is set. |
| `GET /v1/admin/sessions/:id` | Bearer (`ADMIN_TOKEN`) | Detail for a single session. |

### Key Design Decisions

- `Store` trait uses `impl Future` return types (RPITIT) instead of `async_trait` — requires Rust 1.75+.
- `AppState.store` is typed as `Arc<InMemoryStore>` (concrete), not `Arc<dyn Store>`. This will need to change when adding alternative backends.
- Challenges are deleted after successful PoW verification (single-use). Failed PoW leaves the challenge intact for retry. A verify-time `Block` decision still consumes the challenge — the PoW already succeeded.
- `ShadowFail` has no persistent quarantine store; the structured WARN log is the audit trail.
- The TLS fingerprint signal deliberately doesn't do native TLS inspection — it reads a header set by a trusted reverse proxy (e.g. Cloudflare's `cf-ja4`). The `TRUSTED_PROXIES` CIDR check is what prevents direct clients from spoofing the header.
- Each optional signal is gated by its own env var being set; with no env vars the service runs with rate + header anomaly only.
- Integration tests use `tower::ServiceExt::oneshot` with a manually-injected `ConnectInfo` extension to simulate client connections without binding a real port.
- Difficulty 8 is used in tests (instead of the production default 20) to keep solve times fast.
