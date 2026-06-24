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
- `DEFAULT_DIFFICULTY` / `MIN_DIFFICULTY` / `MAX_DIFFICULTY` — PoW difficulty in leading zero bits (default `18` / `16` / `28`)
- `LOAD_LADDER` (default unset) — aggregate site-load difficulty floor: `threshold:difficulty` rungs (e.g. `200:20,500:22`) that raise PoW difficulty for *every* visitor once per-site request count crosses a threshold. Composes with the per-request tier via `max()`, never blocks. Implemented in `risk/load.rs` (`LoadLadder`), applied in the puzzle handler.
- `CHALLENGE_TTL_SECS` / `CLEANUP_INTERVAL_SECS` — challenge expiry + sweeper cadence
- `TIER_CHECKBOX_MIN` / `TIER_HARD_POW_MIN` / `TIER_BLOCK_MIN` — puzzle-time score → tier thresholds (defaults `20`/`40`/`85`)
- `VERIFY_SHADOW_MIN` / `VERIFY_BLOCK_MIN` — verify-time score thresholds (defaults `30` / `60`)
- Privacy posture: the service is **cookie-free** (no client-side storage, no consent banner) and runs every signal under legitimate interest with data minimization. There is no global scoring toggle — each signal self-gates on its own input (header anomaly always computes; IP reputation is 0 without `IP_REPUTATION_FILE`; TLS fingerprint is 0 unless a trusted proxy supplies the header).
- Optional signal inputs, each disabled when its env var is unset: `IP_REPUTATION_FILE`, `TLS_FINGERPRINT_HEADER` (+ `TLS_FINGERPRINT_FILE`, `TRUSTED_PROXIES`).
- Provisioning + persistence: `ADMIN_TOKEN` gates `POST /v1/sites` (returns 404 when unset — no anonymous provisioning) and `/v1/admin/*`. `SITE_DB_PATH` enables SQLite-backed site persistence; without it sites are in-memory only. `CORS_ALLOWED_ORIGINS` is a comma/whitespace allowlist for `GET /v1/puzzle`; other routes never get CORS. `DEV_DISABLE_ADMIN_AUTH=1` (debug builds only) lets local dev/Playwright call `POST /v1/sites` without a bearer; never affects `/v1/admin/*`.
- Reverse-proxy aware client IP: `TRUSTED_PROXIES` (the same CIDR list the TLS fingerprint signal uses) also gates `X-Forwarded-For` walking. The handler resolves the client IP via `risk::client_ip`; per-IP signals score the resolved IP, the TLS fingerprint signal still keys off the immediate peer.
- Validation dashboard: `ADMIN_DB_PATH` enables SQLite-backed decision logging + the admin endpoints; `ADMIN_TOKEN` is the bearer token (shared with provisioning) and is required when `ADMIN_DB_PATH` is set. Browser UI is `static/admin.html`.
- `ANONYMIZE_LOG_IP` (default `true`) — truncate the client IP (IPv4 /24, IPv6 /48) before it's written to the decision log, via `risk::anonymize_ip` applied in the puzzle handler. Live scoring always uses the full IP; only the logged copy is truncated. Governs the durable decision log only, not the `puzzle_decision` tracing event.
- `LOG_RETENTION_HOURS` (default `72`, `0` disables) — retention window for the decision log. A background sweeper (spawned in `main.rs`, only when `ADMIN_DB_PATH` is set) prunes rows older than the window so the durable log obeys GDPR storage-limitation instead of growing unbounded. Cadence is 1/24 of the window, clamped to `[60s, 1h]`; the first sweep runs at boot, so stale rows from a prior run are cleaned immediately. Implemented as `DecisionLog::prune` (routed through the writer thread, like `clear`).
- `GEOIP_DB_PATH` (default unset) — path to a MaxMind GeoLite2/GeoIP2 **Country** `.mmdb`. When set (and `ADMIN_DB_PATH` is enabled), the decision-log writer thread stamps each puzzle row's `country` column with the visitor's ISO code via an **offline** lookup (`dashboard::GeoIp`, wrapping `maxminddb`), performed **at log-write time on the already-anonymized IP** — so it's GDPR-clean and adds zero hot-path cost. Unset → `country` stays NULL and the dashboard's Countries panel is empty. The `.mmdb` is operator-provisioned (not bundled); a missing/corrupt file logs a WARN and disables enrichment rather than blocking boot (loaded via `open_geoip` in `main.rs`).

## Architecture

Self-hostable proof-of-work CAPTCHA service. Clients solve SHA-256 puzzles (find a nonce that produces a hash with N leading zero bits) to prove they are not bots. Rust edition 2024.

Two scoring passes bracket every successful solve:

1. **Puzzle-time** (`GET /v1/puzzle`): score the request, pick an `EscalationTier`, then either issue a PoW puzzle at a tier-adjusted difficulty, or short-circuit with `429` for the `Block` tier.
2. **Verify-time** (`POST /v1/verify`): after the PoW check passes, run a second scoring pass on signals only available at submit (time-on-page — derived server-side as `now - challenge.created_at`, not client-reported — honeypot, behavioural telemetry). Decision is `Pass` / `ShadowFail` (return `success: true` but emit a WARN log) / `Block` (return `success: false`).

### Module Layout

- **`puzzle/`** — Core puzzle engine. `challenge.rs` generates and verifies PoW puzzles: `generate()` + `verify()` dispatch on `Algorithm` (SHA-256 via `compute_sha256` or Argon2id via `compute_argon2id`) and reuse `has_leading_zero_bits()` for both. `difficulty.rs` is the legacy adaptive-difficulty calculator (still constructed in `AppState` but superseded by the risk pipeline). `solve_challenge()` / `solve_argon2id_challenge()` are brute-force solvers used only in tests.
- **`risk/`** — Scoring + escalation. Each signal lives in its own module so it can be disabled by config:
  - `signals.rs` — always-on scorers: `score_rate` (per-IP + per-site, 60s window) and `score_header_anomaly` (UA / Accept-Language / Accept-Encoding).
  - `reputation.rs` — `CidrListReputation` loaded from `IP_REPUTATION_FILE`; categories `tor`/`datacenter`/`vpn`/`residential`.
  - `tls_fingerprint.rs` — `TrustedProxies` CIDR allowlist + `FingerprintBlocklist`. Header is only honored when the immediate peer is in the trusted-proxies list.
  - `client_ip.rs` — `client_ip` (reverse-proxy aware XFF resolution) + `anonymize_ip` (truncate to /24 or /48 for at-rest log storage).
  - `score.rs` — `RiskScorer` aggregates a `SignalContext` (ip, headers, counts, fingerprint) into a `RiskScore { total, breakdown, tier }` for puzzle-time. Single always-on path; each signal self-gates on its input.
  - `verify.rs` — `VerifyScorer` aggregates a `VerifyContext` into a `VerifyScore { total, breakdown, decision }`. Honeypot scores +100 (always blocks); time-on-page bands at <500ms (+50) and <2000ms (+25); behaviour reuses `score_behavior`.
  - `behavior.rs` — `BehaviorReport` (mouse moves, touches, interactions, first-interaction ms) collected by the widget and submitted in `/v1/verify`. Flatline (zero events) scores +30; click-without-pointer scores +15; sub-50ms first interaction adds +20. `BehaviorPresence::Absent` (legacy clients with no blob) scores 0.
  - `tier.rs` — `EscalationTier` (`InvisiblePass` / `Checkbox` / `HardPow` / `Block`) and `difficulty_for(tier, default, max)` which returns `None` for `Block` (caller short-circuits with 429).
  - `load.rs` — `LoadLadder`: aggregate site-load difficulty floor (`threshold:difficulty` rungs from `LOAD_LADDER`). `floor_for(site_count)` returns the highest rung's difficulty the current per-site count meets; the handler composes it with the tier via `max()`. Orthogonal to per-request scoring and never blocks.
- **`dashboard/`** — Validation dashboard. `log.rs` (`DecisionLog`) owns a writer thread that drains an unbounded channel into SQLite. `query.rs` (`Sessions`) opens read-only connections in `spawn_blocking` for list/detail queries; database is in WAL mode so reads run concurrent with writes. `routes.rs` defines `GET /v1/admin/sessions` and `/sessions/:id` behind a bearer-token check. `types.rs` holds the per-decision records (`PuzzleRecord`, `VerifyRecord`) emitted from handlers and the JSON DTOs returned to the dashboard. `geo.rs` (`GeoIp`) wraps an optional `maxminddb` Country reader; the writer thread uses it to stamp the `country` column at insert time (see `GEOIP_DB_PATH`). The dashboard HTML is `static/admin.html` (vanilla JS, no build step).
- **`storage/`** — `Store` trait defines the async storage interface. `memory.rs` is the implementation: challenges and rate-window counters live in `RwLock<HashMap>`; sites are also in-memory but **write-through to a SQLite file** when `SITE_DB_PATH` is set, with rows reloaded on construction via `InMemoryStore::with_site_persistence`. The trait is designed for future Redis/MongoDB backends.
- **`api/`** — Axum router. `handlers.rs` contains the three handlers and is where the puzzle-time + verify-time scoring is orchestrated. The puzzle handler uses `risk::client_ip` to resolve the real client behind a trusted reverse proxy (XFF walked rightmost-untrusted) before scoring per-IP signals. `state.rs` defines `AppState` (shared via `Arc`), `tier_thresholds_from_config`, and `verify_thresholds_from_config`. `middleware.rs` has Bearer token extraction helpers. The CORS layer is scoped: only `GET /v1/puzzle` is CORS-enabled (configurable allowlist via `CORS_ALLOWED_ORIGINS`); `/v1/verify`, `/v1/sites`, and `/v1/admin/*` have no CORS layer (browsers can't reach them cross-origin).
- **`site/`** — Site registration types (`site_key` + `secret_key`).
- **`error.rs`** — `CaptchaError` enum implementing `IntoResponse` for Axum error mapping.
- **`config.rs`** — `AppConfig` loaded from environment variables with defaults.
- **`static/`** — Bundled browser widget served by `tower-http`'s `ServeDir`. `captcha-widget.js` + `captcha-widget.css` are the embeddable widget; `captcha-worker.js` is the Web Worker that solves the PoW off the main thread (dispatches on the wire `algorithm` field — SHA-256 via `crypto.subtle`, Argon2id via the vendored `static/vendor/argon2.umd.min.js` from hash-wasm); `testsite.html` is a local harness.

### API Endpoints

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /v1/puzzle?site_key=<uuid>` | None | Score request and issue a PoW puzzle (with `algorithm`/`prefix`/`difficulty`) for any non-block tier, or `429` for `Block`. Cookie-free — never sets a cookie. |
| `POST /v1/verify` | Bearer (site secret) | Verify a solution server-to-server. Body is either the widget's opaque `token` (hex-encoded JSON, unpacked by `VerifyRequest::resolve`) or explicit fields: `challenge_id` plus `nonce`, optional `honeypot`, `behavior`. Time-on-page is derived server-side from `challenge.created_at`, never trusted from the client. |
| `POST /v1/sites` | Bearer (`ADMIN_TOKEN`) | Register a site, returns site_key + secret. Returns 404 when `ADMIN_TOKEN` is unset. |
| `GET /healthz` | None | Liveness probe. Returns `200 ok`. |
| `GET /v1/admin/sessions` | Bearer (`ADMIN_TOKEN`) | List recent puzzle/verify sessions for the dashboard. Only mounted when `ADMIN_DB_PATH` is set. |
| `GET /v1/admin/sessions/:id` | Bearer (`ADMIN_TOKEN`) | Detail for a single session. |
| `GET /v1/admin/stats` | Bearer (`ADMIN_TOKEN`) | Aggregate stats over the decision log (counts, tier/decision breakdowns) for the dashboard summary cards. |
| `GET /v1/admin/analytics?hours=&site_key=` | Bearer (`ADMIN_TOKEN`) | Windowed analytics for the dashboard's Analytics tab: time-bucketed traffic/outcome/tier series (dense, zero-filled), bot-probability histogram, browser-family breakdown, network-type + country breakdowns, per-signal fire counts. `hours` clamped to 1–720, optional `site_key` filter. |
| `GET /v1/admin/sites` | Bearer (`ADMIN_TOKEN`) | List registered sites (no secrets) merged with per-site activity from the decision log. |
| `POST /v1/admin/sites/:id/rotate` | Bearer (`ADMIN_TOKEN`) | Issue a new `secret_key` for a site; old one invalidated immediately. |
| `DELETE /v1/admin/sites/:id` | Bearer (`ADMIN_TOKEN`) | Delete a site. |

### Operational notes

- `main.rs` installs SIGINT + SIGTERM handlers and serves with `with_graceful_shutdown`, so in-flight requests drain on stop. `/healthz` is the liveness probe.
- **External TLS/uptime monitor.** `/healthz` only proves the app is up *inside* the container — it can't see a reverse-proxy failure. The public deployment is fronted by Coolify's Traefik, which manages the Let's Encrypt cert; when ACME issuance fails, Traefik silently falls back to its **default self-signed cert**, so browsers refuse `captcha-widget.js` and every embed breaks while the app still looks healthy. `scripts/check-public-endpoint.sh` checks the **public** URL with full TLS verification (assets return 2xx over a valid, non-self-signed, non-near-expiry chain) and is run every 15 min by `.github/workflows/monitor.yml` (a failed run emails the owner; set the `MONITOR_WEBHOOK` secret for a Slack/Discord alert). Run it by hand with `just monitor`. **Fix when it fires:** the cert is Coolify/Traefik-managed, not in this repo — re-issue the certificate / re-trigger ACME for the captcha domain in Coolify.
- The decision-log channel is **bounded** (capacity 8192). The hot path uses `try_send`; on `Full` the record is dropped and a counter increments. Power-of-two thresholds emit a WARN so a sustained backlog is visible without log spam.
- The service is cookie-free: no `Set-Cookie` is ever issued and no request cookie is read, so cross-origin embeds need no `SameSite`/credentials handling.
- Default `DEFAULT_DIFFICULTY` is `18` (was `20`) to keep low-end mobile in the few-seconds range. Tests still use `8` for speed.

### Key Design Decisions

- `Store` trait uses `impl Future` return types (RPITIT) instead of `async_trait` — requires Rust 1.75+.
- `AppState.store` is typed as `Arc<InMemoryStore>` (concrete), not `Arc<dyn Store>`. This will need to change when adding alternative backends.
- Challenges are deleted after successful PoW verification (single-use). Failed PoW leaves the challenge intact for retry. A verify-time `Block` decision still consumes the challenge — the PoW already succeeded.
- `ShadowFail` has no persistent quarantine store; the structured WARN log is the audit trail.
- The TLS fingerprint signal deliberately doesn't do native TLS inspection — it reads a header set by a trusted reverse proxy (e.g. Cloudflare's `cf-ja4`). The `TRUSTED_PROXIES` CIDR check is what prevents direct clients from spoofing the header.
- Each signal self-gates on its own input: header anomaly always computes; IP reputation is 0 without `IP_REPUTATION_FILE`; TLS fingerprint is 0 unless a trusted proxy supplies the header. There is no global scoring toggle — the service is cookie-free and scores under legitimate interest with data minimization.
- Integration tests use `tower::ServiceExt::oneshot` with a manually-injected `ConnectInfo` extension to simulate client connections without binding a real port.
- Difficulty 8 is used in tests (instead of the production default 18) to keep solve times fast.
