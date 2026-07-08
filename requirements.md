# Bollwark — Requirements

> **Historical / aspirational.** This document captures the original product brief and has drifted from the current implementation in several places (e.g. the hidden-input field is `captcha-token` not `captcha-solution`; the storage backends are in-memory + SQLite, not Redis/MongoDB; there is no published Rust SDK crate or OpenAPI spec; the risk pipeline, escalation tiers, visual-text challenges, Argon2id algorithm support, and dual scoring are not described here). Treat this as design context, not as the spec. The authoritative docs are **README.md**, **INTEGRATION.md**, and **CONFIGURATION.md**.

Core Concept
Self-hostable, open-source proof-of-work CAPTCHA service with a Rust-native SDK as the key differentiator. No tracking, no cookies, GDPR-friendly by default.

1. Proof-of-Work Puzzle Engine

Generate unique cryptographic challenges per request (SHA-256 or Argon2 based)
Adaptive difficulty based on configurable risk signals (IP rate, request frequency)
Puzzles expire after a configurable TTL (e.g. 5 min)
Solutions are single-use (replay protection via a seen-solutions store)

2. Backend Service (Axum)

GET /v1/puzzle — issue a puzzle for a given site key
POST /v1/verify — verify a solution token server-to-server
POST /v1/sites — register a site (returns site key + secret)
API key auth for verify endpoint
Rate limiting per site key
Storage: in-memory (dev) + Redis or MongoDB (prod)
Docker image published to GHCR

3. JavaScript Widget (Vanilla)

Drop-in <script> tag, no framework dependencies
Solves puzzle in a Web Worker (non-blocking)
Injects a hidden <input name="captcha-solution"> into the parent form
Shows a small status indicator (solving → verified)
Configurable data-sitekey attribute
Published to npm and as a CDN-ready single file

4. Rust Verify SDK (crate)

async fn verify(secret: &str, solution: &str) -> Result<bool, Error>
Configurable endpoint (for self-hosters)
Works with any async runtime (tokio)
Published to crates.io
Example integration for Axum middleware

5. Developer Experience

Single docker compose up to run the full stack locally
README with quickstart (< 5 min to working integration)
Example app: Axum server + HTML form with the widget
OpenAPI spec for the REST API

6. Open Source

License: MIT or Apache-2.0 dual license (Rust ecosystem standard)
GitHub repo with CI via GitHub Actions (build + test)
Changelog + semver
