# Configuration

All runtime configuration is via environment variables. Every setting is optional with a sensible default — the service starts cleanly with `cargo run` and no env vars set, running with the puzzle pipeline only (rate + header anomaly signals active).

A `.env` file in the working directory is loaded automatically at startup (via `dotenvy`). Existing shell env vars take precedence, so you can override values without editing the file. Copy `.env.example` to `.env` to get started.

## Quick reference

| Variable | Default | Purpose |
|---|---|---|
| `LISTEN_ADDR` | `0.0.0.0:3000` | Socket address to bind |
| `RUST_LOG` | `info` | Tracing filter |
| `PUZZLE_ALGORITHM` | `sha256` | PoW algorithm: `sha256` or `argon2id` |
| `ARGON2_M_COST` | `8192` | Argon2id memory cost in KiB (when `PUZZLE_ALGORITHM=argon2id`) |
| `ARGON2_T_COST` | `2` | Argon2id iteration count |
| `ARGON2_P_COST` | `1` | Argon2id lanes / parallelism |
| `DEFAULT_DIFFICULTY` | `18` | Base PoW difficulty (leading zero bits). ~250–500ms on a modern CPU; ~3–5s on low-end mobile in a Web Worker. For Argon2id, drop to `4`–`6`. |
| `MIN_DIFFICULTY` | `16` | Lower clamp on adaptive difficulty |
| `MAX_DIFFICULTY` | `28` | Upper clamp on adaptive difficulty |
| `CHALLENGE_TTL_SECS` | `300` | How long an issued puzzle is valid |
| `CLEANUP_INTERVAL_SECS` | `60` | How often expired challenges are swept |
| `TIER_CHECKBOX_MIN` | `20` | Score at/above which tier becomes `checkbox` |
| `TIER_HARD_POW_MIN` | `40` | …becomes `hard_pow` |
| `TIER_VISUAL_MIN` | `65` | …becomes `visual_challenge` (returns 429) |
| `TIER_BLOCK_MIN` | `85` | …becomes `block` (returns 429) |
| `VERIFY_SHADOW_MIN` | `30` | Verify-time score for shadow-fail (success returned, log emitted) |
| `VERIFY_BLOCK_MIN` | `60` | Verify-time score for hard rejection |
| `IP_REPUTATION_FILE` | _unset_ | Path to CIDR reputation list (signal off if unset) |
| `COOKIE_SIGNING_SECRET` | _unset_ | HMAC secret for trust cookies (≥16 bytes; signal off if unset) |
| `COOKIE_SECURE` | `false` | Set the `Secure` attribute on issued cookies |
| `COOKIE_SAMESITE` | `Lax` | `Lax` or `None`. Use `None` for cross-origin embeds; requires `COOKIE_SECURE=true` (boot panics otherwise). |
| `TLS_FINGERPRINT_HEADER` | _unset_ | Header to read TLS fingerprint from (signal off if unset) |
| `TLS_FINGERPRINT_FILE` | _unset_ | Path to known-bad fingerprint blocklist |
| `TRUSTED_PROXIES` | _unset_ | CIDR allowlist of peers whose `TLS_FINGERPRINT_HEADER` we honor |
| `ADMIN_DB_PATH` | _unset_ | Path to the SQLite database for the validation dashboard. Enables decision logging + admin endpoints. |
| `ADMIN_TOKEN` | _unset_ | Bearer token for `/v1/admin/*` and `POST /v1/sites`. Without it, `POST /v1/sites` returns 404 (no anonymous provisioning). Required when `ADMIN_DB_PATH` is set. |
| `SITE_DB_PATH` | _unset_ | Path to a SQLite file for persistent site registrations. Without it, sites live only in memory and are lost on restart. |
| `CORS_ALLOWED_ORIGINS` | _unset_ | Comma- or whitespace-separated allowlist of origins permitted to call `GET /v1/puzzle` from a browser. Empty/unset = any origin (no credentials). Other endpoints never have CORS enabled. |
| `DEV_DISABLE_ADMIN_AUTH` | `false` | **Dev/test only.** When truthy (`1`/`true`/`yes`/`on`), `POST /v1/sites` skips the `ADMIN_TOKEN` bearer check. Refused in release builds. Admin dashboard endpoints (`/v1/admin/*`) are NOT bypassed. |

---

## Server basics

### `LISTEN_ADDR`
Socket address the HTTP server binds to.

- Default: `0.0.0.0:3000`
- Format: `<ip>:<port>` (`SocketAddr` parser — accepts IPv4 and IPv6)

### `RUST_LOG`
Standard `tracing-subscriber` env filter. Useful targets:

- `rust_captcha=info` — high-level events
- `rust_captcha::api::handlers=debug` — adds per-request scoring detail (Pass-tier verifies)
- `rust_captcha=trace` — everything

---

## PoW configuration

PoW difficulty is the number of **leading zero bits** the SHA-256 hash of `prefix || nonce` must have. Each additional bit roughly doubles the expected solve time.

### `DEFAULT_DIFFICULTY` (default `18`)
Base difficulty for `invisible_pass` tier. Each additional bit doubles expected solve time:

| Difficulty | Modern CPU | Low-end mobile (Web Worker) |
|---|---|---|
| 16 | ~100ms | ~1–2s |
| 18 | ~300ms | ~3–5s |
| 20 | ~1s | ~10–15s |
| 22 | ~4s | timeout territory |

The default `18` trades a bit of bot resistance for materially better mobile UX. Bump to `20` if you have telemetry showing your audience is desktop-heavy.

### `MIN_DIFFICULTY` (default `16`) / `MAX_DIFFICULTY` (default `28`)
Clamp the final difficulty. The risk tier can bump difficulty above `DEFAULT_DIFFICULTY`:
- `invisible_pass` → `DEFAULT_DIFFICULTY`
- `checkbox` → `DEFAULT_DIFFICULTY + 2`
- `hard_pow` → `DEFAULT_DIFFICULTY + 4`

The result is clamped to `MAX_DIFFICULTY`. `MIN_DIFFICULTY` exists for the legacy `DifficultyCalculator` and currently has no effect on the risk pipeline (kept for backwards-compatible env API).

### `CHALLENGE_TTL_SECS` (default `300`)
A challenge is valid for this many seconds after issuance. Verify with an expired challenge returns `410 Gone`.

### `CLEANUP_INTERVAL_SECS` (default `60`)
How often the background sweeper deletes expired challenges and stale rate-window counters.

---

## Risk tier thresholds (puzzle-time)

The puzzle-time scorer adds up contributions from each enabled signal and maps the total to an `EscalationTier`. Tier thresholds are inclusive: `score >= threshold` selects that tier.

| Score range | Tier | Behavior |
|---|---|---|
| `0` — `TIER_CHECKBOX_MIN-1` | `invisible_pass` | Issue puzzle at base difficulty; widget solves silently |
| `TIER_CHECKBOX_MIN` — `TIER_HARD_POW_MIN-1` | `checkbox` | Difficulty +2; widget renders "I'm not a robot" checkbox |
| `TIER_HARD_POW_MIN` — `TIER_VISUAL_MIN-1` | `hard_pow` | Difficulty +4; same widget UX as checkbox |
| `TIER_VISUAL_MIN` — `TIER_BLOCK_MIN-1` | `visual_challenge` | Returns `429 Too Many Requests` (visual challenge not implemented) |
| `TIER_BLOCK_MIN` — | `block` | Returns `429 Too Many Requests` |

Defaults: `20` / `40` / `65` / `85`.

### Puzzle-time signals

| Signal | Max contribution | Enabled by |
|---|---|---|
| Rate (per-IP + per-site, 60s window) | 45 | Always on |
| Header anomaly (UA / Accept-Language / Accept-Encoding) | 50 | Always on |
| IP reputation | 40 | `IP_REPUTATION_FILE` |
| Cookie age | 20 | `COOKIE_SIGNING_SECRET` |
| TLS fingerprint | 35 | `TLS_FINGERPRINT_HEADER` + `TRUSTED_PROXIES` |

Tuning the per-signal score weights requires a code change (see `src/risk/signals.rs` and the per-signal modules); only the **tier thresholds** are env-tunable.

---

## Verify-time scoring

After a PoW solution is verified, a second scoring pass runs against verify-time-only signals (time-on-page, cookie age at verify, honeypot). The result is one of three decisions:

| Score range | Decision | Response | Side effect |
|---|---|---|---|
| `0` — `VERIFY_SHADOW_MIN-1` | `Pass` | `success: true` | DEBUG log |
| `VERIFY_SHADOW_MIN` — `VERIFY_BLOCK_MIN-1` | `ShadowFail` | `success: true` | WARN log, `quarantined` field |
| `VERIFY_BLOCK_MIN` — | `Block` | `success: false` | INFO log |

### `VERIFY_SHADOW_MIN` (default `30`)
At/above this, the request is shadow-failed: success is still returned to the caller (they see no failure), but a structured WARN log fires for offline review. No persistent quarantine store yet — the log is the audit trail.

### `VERIFY_BLOCK_MIN` (default `60`)
At/above this, the request is hard-rejected (`success: false`).

### Verify-time signals

| Signal | Score |
|---|---|
| Honeypot field non-empty | +100 (always blocks) |
| Time-on-page < 500ms | +50 |
| Time-on-page < 2000ms | +25 |
| Cookie missing (when feature on) | +5 |
| Cookie present, age < 60s | +20 |
| Cookie present, age < 5min | +10 |
| Cookie present, age < 1h | +5 |

---

## IP reputation signal

### `IP_REPUTATION_FILE`
Path to a CIDR reputation file. Unset → signal contributes 0 for all IPs.

**File format:**
```
# comments and blank lines are ignored
<cidr> <category>
<cidr> <category> # inline comment
```

**Categories** (case-insensitive, plus aliases):

| Category | Aliases | Score |
|---|---|---|
| `tor` | — | 40 |
| `datacenter` | `dc`, `hosting` | 30 |
| `vpn` | `proxy` | 20 |
| `residential` | `isp` | 0 |

**Example:**
```
# Tor exit nodes (refresh from official list)
185.220.100.0/22 tor
2a0b:f4c0::/29 tor

# Major cloud providers
3.0.0.0/8 datacenter
35.190.0.0/16 datacenter

# Commercial VPNs
146.70.0.0/16 vpn
```

Lookup is first-match-wins on the order in the file. Unknown categories on otherwise well-formed lines are skipped with a WARN log at boot.

---

## Cookie age signal

### `COOKIE_SIGNING_SECRET`
HMAC-SHA256 secret for the `__captcha_trust` cookie. Unset → cookies are not issued, signal contributes 0. Must be **at least 16 bytes** when set; shorter values are silently ignored at boot with a WARN log.

The cookie is opaque and stateless — the server doesn't track issued cookies anywhere; the HMAC self-validates.

**Cookie format:** `__captcha_trust=<hex(timestamp)>.<hex(hmac)>`
- `Max-Age`: 30 days
- `HttpOnly`, `SameSite=Lax`
- `Secure` only when `COOKIE_SECURE=true`

### `COOKIE_SECURE` (default `false`)
Set the `Secure` attribute on issued cookies. Set to `true` in production behind TLS. Leave `false` for local HTTP dev.

### `COOKIE_SAMESITE` (default `Lax`)
- `Lax` — cookie only flows on top-level same-origin navigation. Embedded widgets on a different origin from the captcha service won't see it; the cookie signal silently degrades to "missing" (+5) for those requests.
- `None` — cookie flows on every cross-site request. Required for cross-origin embeds. Browsers refuse `SameSite=None` without `Secure`, so the service **panics at boot** if `COOKIE_SAMESITE=None` is combined with `COOKIE_SECURE=false`.

For cross-origin embeds you also need to set `CORS_ALLOWED_ORIGINS` to the embedder's origin (a wildcard origin can't be combined with credentials).

---

## TLS fingerprint signal

Native TLS inspection (JA3/JA4 in Rust) is intrusive and brittle. This service instead reads a fingerprint set by a trusted reverse proxy. **All three settings below must be set together** for the signal to fire.

### `TLS_FINGERPRINT_HEADER`
Header name to read, e.g. `x-ja4`. Unset → signal disabled. Header is only read when the request's immediate peer IP is in `TRUSTED_PROXIES` — otherwise direct clients could spoof it.

### `TLS_FINGERPRINT_FILE`
Path to a file listing known-bad fingerprint values, one per line. `#` comments and blank lines ignored.

**Example:**
```
# Bot framework defaults
t13d1715h2_5b57614c22b0_5c2c66f702b6   # python-requests
t13d301100_286b2c61aa14_e74b73c89e6c   # go default
```

Match → +35 to score. Lookup is exact-match on the full fingerprint string.

### `TRUSTED_PROXIES`
CIDR allowlist of upstream proxies whose `TLS_FINGERPRINT_HEADER` we honor. Comma- or whitespace-separated.

**Example:**
```
TRUSTED_PROXIES="10.0.0.0/8,fd00::/8"
```

Empty/unset → no peer is trusted → signal never fires (boot log will WARN if `TLS_FINGERPRINT_HEADER` is set without trusted proxies).

---

## Site registration & provisioning

Sites are registered with `POST /v1/sites`, which returns a `site_key` (public, embedded in the widget) and a `secret_key` (server-to-server, used as the bearer for `/v1/verify`). Two settings govern this surface:

### `ADMIN_TOKEN`
Bearer token required for `POST /v1/sites`. **When unset, `/v1/sites` returns 404** — no anonymous provisioning. Generate with `openssl rand -hex 32` and pass on the call:

```bash
curl -X POST http://localhost:3000/v1/sites \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-site"}'
```

The same token also gates `/v1/admin/*` (validation dashboard).

### `SITE_DB_PATH`
Path to a SQLite file that persists site rows. When unset, sites live only in `Arc<RwLock<HashMap>>` and are lost on restart — meaning every integrator's stored `secret_key` becomes invalid. **Set this for any deployment beyond local dev.** Created on first run, schema is `(site_key TEXT PRIMARY KEY, secret_key TEXT UNIQUE, name TEXT, created_at TEXT)`.

Challenges and rate-window counters intentionally stay in-memory: they're cheap to lose and a fresh start is fine.

---

## CORS

### `CORS_ALLOWED_ORIGINS`
The puzzle endpoint (`GET /v1/puzzle`) is the only surface a browser-embedded widget reaches cross-origin. It's the only route with a CORS layer. `/v1/verify`, `/v1/sites`, and `/v1/admin/*` have **no** CORS layer — same-origin policy in browsers blocks cross-origin reads of those endpoints.

- Unset: any origin allowed, no credentials. Operationally equivalent to "any embed."
- Set: comma- or whitespace-separated allowlist (`https://a.example,https://b.example`). Origins outside the list don't get CORS headers and the browser blocks the response.

Cookies don't flow cross-origin in the default `SameSite=Lax` configuration regardless of CORS — the cookie signal degrades to "missing" for embedders on a different origin from the captcha service.

---

## Reverse proxies & client IP

Behind a reverse proxy (Cloudflare, nginx, AWS ALB) the TCP peer is the proxy itself. Per-IP signals (rate, IP reputation) need the original client. The service walks `X-Forwarded-For` right-to-left, skipping trusted-proxy hops, when **and only when** the immediate peer is in [`TRUSTED_PROXIES`](#trusted_proxies). Direct clients can't spoof the header — without a trusted peer, XFF is ignored entirely.

Cloudflare's `CF-Connecting-IP` is **not** read; configure the upstream to put the client IP in `X-Forwarded-For` (Cloudflare does this automatically when the request reaches your origin) and add Cloudflare's IP ranges to `TRUSTED_PROXIES`.

---

## Liveness & shutdown

### `GET /healthz`
Always returns `200 ok`. No auth, no state read — suitable as a Kubernetes / Docker / load-balancer liveness probe. Doesn't gate on dependency health (a degraded SQLite shouldn't pull the pod out of rotation; the dashboard surfaces backend errors via tracing instead).

### Graceful shutdown
The server installs SIGINT (Ctrl-C) and SIGTERM handlers and shuts down via `axum::serve(...).with_graceful_shutdown(...)`. In-flight requests complete; new connections are refused after the signal. Operators using systemd / Kubernetes should expect a clean drain on stop.

---

## Validation dashboard

A self-hosted dashboard that lets you inspect every puzzle and verify decision in a browser. Persists to SQLite so history survives restarts.

### Decision-log channel
Decisions are written from the request handler through a **bounded** mpsc channel (capacity 8192) to a dedicated SQLite writer thread. The hot path uses `try_send`, so when the writer falls behind the queue fills and subsequent records are dropped (with a rate-limited WARN — emitted at every power-of-two threshold so logs don't drown). Operators can read `DecisionLog::dropped_count()` if they want to surface it; in steady state this should be zero.

### `ADMIN_DB_PATH`
Path to the SQLite database file. Created on first run; uses WAL mode so reads don't block writes. When unset, decision logging and admin endpoints are both disabled.

The bearer token for `/v1/admin/*` is the same `ADMIN_TOKEN` used for `/v1/sites`. The service refuses to start when `ADMIN_DB_PATH` is set without `ADMIN_TOKEN`.

### Endpoints (when enabled)

| Endpoint | Purpose |
|---|---|
| `GET /v1/admin/sessions?limit=N` | List recent sessions (puzzle decision joined with matching verify, if any). `limit` capped at 1000, default 100. |
| `GET /v1/admin/sessions/:id` | Detail for a single session id. |
| `GET /static/admin.html` | Browser dashboard (paste the token to sign in). |

Each session row includes the puzzle score, tier, signal breakdown, verify result (when present), and a derived `bot_probability` (max of puzzle and verify scores, capped at 100). Decision writes go through an unbounded channel to a dedicated writer thread, so the hot path is never blocked on disk.

---

## Putting it all together

A production-leaning configuration:

```bash
LISTEN_ADDR=0.0.0.0:3000
DEFAULT_DIFFICULTY=20

# Provisioning + persistence (do not deploy without these)
ADMIN_TOKEN=$(openssl rand -hex 32)
SITE_DB_PATH=/var/lib/rust-captcha/sites.db

# Restrict the puzzle endpoint to your known embedders
CORS_ALLOWED_ORIGINS="https://app.example,https://admin.example"

# Adaptive escalation tuned a bit more aggressively
TIER_CHECKBOX_MIN=15
TIER_HARD_POW_MIN=35
TIER_BLOCK_MIN=80

# Behavioral checks on
COOKIE_SIGNING_SECRET=$(openssl rand -hex 32)
COOKIE_SECURE=true
VERIFY_SHADOW_MIN=25
VERIFY_BLOCK_MIN=55

# IP reputation from a maintained list
IP_REPUTATION_FILE=/etc/rust-captcha/ip_reputation.txt

# Reverse-proxy aware client IP + TLS fingerprint via Cloudflare.
# TRUSTED_PROXIES gates BOTH the X-Forwarded-For walk AND the TLS
# fingerprint header — direct clients can't spoof either without
# being in this CIDR list.
TLS_FINGERPRINT_HEADER=cf-ja4
TLS_FINGERPRINT_FILE=/etc/rust-captcha/ja4_blocklist.txt
TRUSTED_PROXIES="173.245.48.0/20,103.21.244.0/22,..."  # CF ranges

# Validation dashboard
ADMIN_DB_PATH=/var/lib/rust-captcha/decisions.db

RUST_LOG=rust_captcha=info
```

For local development, the bare minimum (just the testsite + scoring scaffold):

```bash
DEFAULT_DIFFICULTY=8 cargo run
```

Add `COOKIE_SIGNING_SECRET=<16+chars>` to exercise the cookie path in the testsite.
