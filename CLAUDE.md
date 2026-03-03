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
```

## Environment Variables

All optional, with sensible defaults:

- `LISTEN_ADDR` — Socket address (default: `0.0.0.0:3000`)
- `DEFAULT_DIFFICULTY` — PoW difficulty in leading zero bits (default: `20`)
- `MIN_DIFFICULTY` / `MAX_DIFFICULTY` — Adaptive difficulty bounds (default: `16` / `28`)
- `CHALLENGE_TTL_SECS` — Challenge expiry (default: `300`)
- `CLEANUP_INTERVAL_SECS` — Expired challenge cleanup interval (default: `60`)
- `RUST_LOG` — Tracing filter (default: `info`)

## Architecture

Self-hostable proof-of-work CAPTCHA service. Clients solve SHA-256 puzzles (find a nonce that produces a hash with N leading zero bits) to prove they are not bots. Rust edition 2024.

### Module Layout

- **`puzzle/`** — Core PoW engine. `challenge.rs` generates challenges and verifies solutions via `compute_hash(prefix, nonce)` + `has_leading_zero_bits()`. `difficulty.rs` computes adaptive difficulty from IP and site-key rate counters. `solve_challenge()` is a brute-force solver used only in tests.
- **`storage/`** — `Store` trait defines the async storage interface. `memory.rs` is the in-memory implementation using `RwLock<HashMap>`. The trait is designed for future Redis/MongoDB backends.
- **`api/`** — Axum router with three endpoints. `handlers.rs` contains all handler logic. `state.rs` defines `AppState` (shared via `Arc`). `middleware.rs` has Bearer token extraction helpers.
- **`site/`** — Site registration types (`site_key` + `secret_key`).
- **`error.rs`** — `CaptchaError` enum implementing `IntoResponse` for Axum error mapping.
- **`config.rs`** — `AppConfig` loaded from environment variables with defaults.

### API Endpoints

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /v1/puzzle?site_key=<uuid>` | None | Issue a PoW challenge |
| `POST /v1/verify` | Bearer (site secret) | Verify a solution server-to-server |
| `POST /v1/sites` | None | Register a site, returns site_key + secret |

### Key Design Decisions

- `Store` trait uses `impl Future` return types (RPITIT) instead of `async_trait` — requires Rust 1.75+.
- `AppState.store` is typed as `Arc<InMemoryStore>` (concrete), not `Arc<dyn Store>`. This will need to change when adding alternative backends.
- Challenges are deleted after successful verification (single-use). Failed verifications leave the challenge intact for retry.
- Integration tests use `tower::ServiceExt::oneshot` with a manually-injected `ConnectInfo` extension to simulate client connections without binding a real port.
- Difficulty 8 is used in tests (instead of the production default 20) to keep solve times fast.
