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
| `LOAD_LADDER` | _unset_ | Aggregate site-load difficulty floor. Comma-separated `threshold:difficulty` rungs, e.g. `200:20,500:22,1000:24` (thresholds are requests per `RATE_WINDOW_SECS` window; difficulty in leading zero bits). When the per-site request count crosses a rung, the floor is raised for every visitor. Composes with the per-request tier via `max()`, clamped to `MAX_DIFFICULTY`. Never blocks — only raises difficulty. Empty/unset = no floor. Malformed = boot panics. |
| `CHALLENGE_TTL_SECS` | `300` | How long an issued puzzle is valid |
| `CLEANUP_INTERVAL_SECS` | `60` | How often expired challenges are swept |
| `TIER_CHECKBOX_MIN` | `20` | Score at/above which tier becomes `checkbox` |
| `TIER_HARD_POW_MIN` | `40` | …becomes `hard_pow` (covers the whole 40–`TIER_BLOCK_MIN` band) |
| `TIER_BLOCK_MIN` | `85` | …becomes `block` (returns 429) |
| `VERIFY_SHADOW_MIN` | `30` | Verify-time score for shadow-fail (success returned, log emitted) |
| `VERIFY_BLOCK_MIN` | `60` | Verify-time score for hard rejection |
| `IP_REPUTATION_FILE` | _unset_ | Path to CIDR reputation list (signal off if unset) |
| `TLS_FINGERPRINT_HEADER` | _unset_ | Header to read TLS fingerprint from (signal off if unset) |
| `TLS_FINGERPRINT_FILE` | _unset_ | Path to known-bad fingerprint blocklist |
| `TRUSTED_PROXIES` | _unset_ | CIDR allowlist of peers whose `TLS_FINGERPRINT_HEADER` we honor |
| `ADMIN_DB_PATH` | _unset_ | Path to the SQLite database for the validation dashboard. Enables decision logging + admin endpoints. |
| `ADMIN_TOKEN` | _unset_ | Bearer token for `/v1/admin/*` and `POST /v1/sites`. Without it, `POST /v1/sites` returns 404 (no anonymous provisioning). Required when `ADMIN_DB_PATH` is set. |
| `SITE_DB_PATH` | _unset_ | Path to a SQLite file for persistent site registrations. Without it, sites live only in memory and are lost on restart. |
| `CORS_ALLOWED_ORIGINS` | _unset_ | Comma- or whitespace-separated allowlist of origins permitted to call `GET /v1/puzzle` and fetch static widget assets from a browser. Empty/unset = any origin, no credentials. Other API endpoints never have CORS enabled. |
| `DEV_DISABLE_ADMIN_AUTH` | `false` | **Dev/test only.** When truthy (`1`/`true`/`yes`/`on`), `POST /v1/sites` skips the `ADMIN_TOKEN` bearer check. Refused in release builds. Admin dashboard endpoints (`/v1/admin/*`) are NOT bypassed. |
| `ANONYMIZE_LOG_IP` | `true` | Truncate the client IP (IPv4 → /24, IPv6 → /48) before writing it to the decision log. **On by default** so the dashboard stores no per-visitor address. Set to `false` to log full IPs (abuse forensics). Live scoring always uses the full IP regardless. |
| `LOG_RETENTION_HOURS` | `72` | Retention window for the decision log. A background sweeper prunes rows older than this (only runs when `ADMIN_DB_PATH` is set). **On by default** (ALTCHA's window) so the durable log obeys GDPR storage-limitation. Set to `0` to disable pruning and keep rows forever. |
| `GEOIP_DB_PATH` | _unset_ | Path to a MaxMind GeoLite2/GeoIP2 **Country** `.mmdb`. When set (and `ADMIN_DB_PATH` is enabled), the decision-log writer stamps each row with the visitor's ISO country code, looked up offline on the already-anonymized IP. Off if unset (the `country` column stays NULL and the dashboard's Countries panel is empty). |

---

## Server basics

### `LISTEN_ADDR`
Socket address the HTTP server binds to.

- Default: `0.0.0.0:3000`
- Format: `<ip>:<port>` (`SocketAddr` parser — accepts IPv4 and IPv6)

### `RUST_LOG`
Standard `tracing-subscriber` env filter. Useful targets:

- `bollwark=info` — high-level events
- `bollwark::api::handlers=debug` — adds per-request scoring detail (Pass-tier verifies)
- `bollwark=trace` — everything

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

### `LOAD_LADDER` (default _unset_)
An **aggregate** site-load difficulty floor, separate from the per-request risk tier. Where the tier escalates an individual visitor based on who they are, the load floor raises difficulty for *everyone* when the whole site is hot — catching distributed floods where each IP looks individually benign but the site-wide request count is abnormal.

Format is comma-separated `threshold:difficulty` rungs, e.g. `200:20,500:22,1000:24`. Thresholds are requests in the per-site rate window (60s — note mCaptcha, which inspired this, uses 30s); difficulty is leading zero bits. The floor for a request is the difficulty of the highest rung whose threshold the current per-site count meets, then composed with the tier difficulty:

```
final = min(MAX_DIFFICULTY, max(tier_difficulty, load_floor))
```

The floor **never blocks** — `Block` stays a per-request risk decision, so a legitimate traffic spike (launch, viral link) slows everyone fairly instead of rejecting real users. Unset/empty disables it; a malformed spec panics at boot rather than silently running without the configured protection.

> **Note:** the per-site counter is a tumbling 60s window, so the floor sawtooths slightly at window boundaries (it can briefly drop to base under sustained load right after a reset). A leaky-bucket counter would smooth this; it's deliberately not implemented yet.

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
| `TIER_HARD_POW_MIN` — `TIER_BLOCK_MIN-1` | `hard_pow` | Difficulty +4; same widget UX as checkbox |
| `TIER_BLOCK_MIN` — | `block` | Returns `429 Too Many Requests` |

Defaults: `20` / `40` / `85`.

### Puzzle-time signals

| Signal | Max contribution | Enabled by |
|---|---|---|
| Rate (per-IP + per-site, 60s window) | 45 | Always on |
| Header anomaly (UA / Accept-Language / Accept-Encoding) | 50 | Always on |
| IP reputation | 40 | `IP_REPUTATION_FILE` |
| TLS fingerprint | 35 | `TLS_FINGERPRINT_HEADER` + `TRUSTED_PROXIES` |

Every signal self-gates on its own input: header anomaly always computes, IP reputation contributes 0 without `IP_REPUTATION_FILE`, and TLS fingerprint contributes 0 unless a trusted proxy supplied the header. There is no global on/off switch — the service is cookie-free and runs these signals under legitimate interest with data minimization. Tuning the per-signal score weights requires a code change (see `src/risk/signals.rs` and the per-signal modules); only the **tier thresholds** are env-tunable.

---

## Verify-time scoring

After a PoW solution is verified, a second scoring pass runs against verify-time-only signals (time-on-page, honeypot, behavioral telemetry). The result is one of three decisions:

| Score range | Decision | Response | Side effect |
|---|---|---|---|
| `0` — `VERIFY_SHADOW_MIN-1` | `Pass` | `success: true` | DEBUG log |
| `VERIFY_SHADOW_MIN` — `VERIFY_BLOCK_MIN-1` | `ShadowFail` | `success: true` | WARN log (the response body is identical to `Pass`; the log is the only signal) |
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
| Behavior: flatline (zero events) | +30 |
| Behavior: click without pointer movement | +15 |
| Behavior: sub-50ms first interaction | +20 |

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

**Hot reload.** The file is watched for changes — rewriting it (e.g. via a cron pulling Tor exits or AWS ranges) hot-swaps the in-memory list with no restart. Saves are debounced ~500ms to coalesce editor-rewrite bursts (atomic-rename via tmp file). A failed reparse is logged at WARN and the previous list is kept; the request path can never observe an empty/partial list.

---

## Cookie-free operation

The service sets **no cookies** and reads none. There is no client-side storage of any kind: the widget submits an opaque token in the form body, and every risk signal is derived server-side from the request itself (rate counters, request headers, optional IP reputation / TLS fingerprint) or from behavioral telemetry the widget collects for that one submission. This is what lets the service run without a consent banner — there is no ePrivacy Article 5(3) "storage or access on the user's device" to consent to.

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
The browser-embedded widget reaches `GET /v1/puzzle` and static assets (`/static/captcha-worker.js`, vendor files) cross-origin. Those are the only surfaces with CORS. `/v1/verify`, `/v1/sites`, and `/v1/admin/*` have **no** CORS layer — same-origin policy in browsers blocks cross-origin reads of those endpoints.

- Unset: any origin allowed, no credentials. The widget can fetch puzzles from any embedding origin.
- Set: comma- or whitespace-separated allowlist (`https://a.example,https://b.example`). Origins outside the list don't get CORS headers and the browser blocks the response.

Since the service is cookie-free, there are no cross-origin credential concerns — the widget never sends or receives cookies, so a wildcard origin is safe for the puzzle endpoint.

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
| `GET /v1/admin/stats` | Aggregate counts and tier/decision breakdowns over the decision log (powers the dashboard summary cards). |
| `GET /v1/admin/sites` | List registered sites (no secrets) merged with per-site activity from the decision log. |
| `POST /v1/admin/sites/:id/rotate` | Issue a new `secret_key` for a site; the old one is invalidated immediately. |
| `DELETE /v1/admin/sites/:id` | Delete a site. Future `/v1/verify` calls with its old secret will fail. |
| `GET /static/admin.html` | Browser dashboard (paste the token to sign in). |

Each session row includes the puzzle score, tier, signal breakdown, verify result (when present), and a derived `bot_probability` (max of puzzle and verify scores, capped at 100). Decision writes go through an unbounded channel to a dedicated writer thread, so the hot path is never blocked on disk.

### `ANONYMIZE_LOG_IP` (default `true`)
Controls the IP value persisted in each decision-log row. On by default: the IP is truncated to its network prefix (IPv4 → /24, e.g. `203.0.113.42` → `203.0.113.0`; IPv6 → /48) before it is written, so the durable log — and the dashboard reading from it — never holds a per-visitor address. This is the data-minimization control that keeps the dashboard defensible under GDPR.

Live scoring (rate window, IP reputation, XFF resolution) always operates on the **full** IP, so anonymizing the logged copy does not weaken detection. Set `ANONYMIZE_LOG_IP=false` to store full IPs where the operator is the data controller and needs them for abuse forensics. Note: the full IP still appears transiently in the structured `puzzle_decision` tracing event (`ip=…`); this flag governs the durable decision log only, not your log pipeline.

### `LOG_RETENTION_HOURS` (default `72`)
Caps how long decision-log rows live. A background sweeper (spawned at startup, only when `ADMIN_DB_PATH` is set) deletes any puzzle/verify row older than the window. The default `72` matches ALTCHA's retention; together with `ANONYMIZE_LOG_IP` it is what makes the durable log defensible under GDPR **storage limitation** (Art. 5(1)(e)) — without it the table grows forever and the only way to bound it is the operator-initiated "Clear all".

The sweeper runs at **1/24 of the window**, clamped to `[60s, 1h]` — so a 72 h window sweeps hourly, and rows never outlive the window by more than ~4%. The first sweep fires at boot, so stale rows left by a previous run (e.g. before this was configured) are pruned immediately on the next start. Set `LOG_RETENTION_HOURS=0` to disable pruning entirely and keep every row (e.g. when you are the data controller and need a longer forensic trail — pair with a longer-retention upsell rather than treating it as the baseline). Pruning is index-backed (`idx_puzzle_ts` / `idx_verify_ts`) and serialised with inserts through the same writer thread, so it never races a concurrent write.

### `GEOIP_DB_PATH` (default _unset_)
Path to a MaxMind **GeoLite2-Country** (or GeoIP2-Country) `.mmdb` file. When set — and `ADMIN_DB_PATH` is enabled — the decision-log writer thread stamps each puzzle row with the visitor's ISO 3166-1 alpha-2 country code, and the dashboard's Analytics tab gains a **Countries** breakdown. Unset (the default) leaves the `country` column NULL and the panel empty.

The lookup is **offline** — the `.mmdb` is mmap'd at boot, every lookup is an in-memory tree walk, and nothing ever leaves the box. It runs **at log-write time on the already-anonymized IP** (the same /24- or /48-truncated value `ANONYMIZE_LOG_IP` stores), which still resolves country-level, so geo enrichment adds no per-visitor data beyond what the log already held — it stays GDPR-clean. The reader lives on the writer thread, so there is zero cost on the request hot path.

You must **provision the database yourself** (it is not bundled — MaxMind's license requires you to download it under your own account). Point `GEOIP_DB_PATH` at the file; a missing or corrupt file logs a `WARN` and disables enrichment (the column stays NULL) rather than blocking boot. The country code is denormalized into the row at write time, so rotating the `.mmdb` only affects rows logged afterward.

---

## Info-page links (`INFO_*_URL`)

The bundled widget shows a footer with **Bollwark** (→ `/static/about.html`) plus tiny `Privacy` / `Terms` links (→ `/static/privacy.html`, `/static/terms.html`). The footer is rendered eagerly at mount with these bundled defaults and stays visible across every tier — including `invisible_pass`, `checkbox`, and the 429 block path — so a user who's confused by the verification UI always has a one-click route to "why am I seeing this?".

Operators with their own About / Privacy / Terms pages can override per-field:

### `INFO_ABOUT_URL` / `INFO_PRIVACY_URL` / `INFO_TERMS_URL`

- Each is independent. Setting `INFO_PRIVACY_URL` only leaves the other two pointing at the bundled defaults.
- Values **must be absolute** (`http://` or `https://`). Relative paths (`/legal/privacy`) and bare filenames (`privacy.html`) are rejected at boot — a typo'd path here would produce broken links in every visitor's browser, which is exactly what we want to fail loud.
- Surfaced to the widget via the puzzle response (and the structured 429 body, so block-tier users still see the right links).
- Setting some-but-not-all three logs a startup `WARN` — most operators who customise their privacy notice want to customise terms too, and shipping the bundled boilerplate next to a bespoke privacy page is usually unintended.

The bundled `static/{about,privacy,terms}.html` are written to be safe defaults for self-hosted deployments — they describe what the bundled widget and server can collect when fully configured. They carry `<meta name="robots" content="noindex, follow">` to keep duplicate copies across operator deployments out of search indexes.

---

## Privacy posture

The service is **cookie-free** and runs every signal under **legitimate interest** with data minimization — there is no global on/off switch and no consent-triggering client storage. Each signal self-gates on whether its input is configured:

| Signal | Always on? | Privacy notes |
|---|---|---|
| Rate (per-IP + per-site, 60 s window) | Yes | Transient counter, no per-IP profile retained |
| Header anomaly (UA / Accept-Language / Accept-Encoding) | Yes | Scored transiently from headers the browser already sends; no stable identifier persisted |
| Honeypot | Yes | No PII |
| Time-on-page | Yes | Derived server-side, transient |
| Behavior (mouse / touch / `webdriver`) | Yes | Ephemeral, submitted for one verification, not linked to an identity |
| IP reputation | Only with `IP_REPUTATION_FILE` | Transient CIDR lookup; the full IP is never persisted (the decision log truncates it — see `ANONYMIZE_LOG_IP`) |
| TLS fingerprint | Only with `TLS_FINGERPRINT_HEADER` + `TRUSTED_PROXIES` | The one device-fingerprint signal; opt-in via its own env vars |
| Geo country (dashboard only) | Only with `GEOIP_DB_PATH` | Not a scoring signal — observability only. Offline lookup on the already-truncated logged IP; resolves country-level, stores only a 2-letter code |

What keeps this defensible: no cookies or other terminal-device storage (so no ePrivacy Art. 5(3) consent), short-lived transient processing for security (legitimate interest, Art. 6(1)(f)), and IP truncation before anything durable is written. As always, the final compliance determination — including a DPIA if you enable IP reputation or TLS fingerprinting — rests with you as the data controller.

---

## Putting it all together

A production-leaning configuration:

```bash
LISTEN_ADDR=0.0.0.0:3000
DEFAULT_DIFFICULTY=18

# Provisioning + persistence (do not deploy without these)
ADMIN_TOKEN=$(openssl rand -hex 32)
SITE_DB_PATH=/var/lib/bollwark/sites.db

# Restrict the puzzle endpoint to your known embedders
CORS_ALLOWED_ORIGINS="https://app.example,https://admin.example"

# Adaptive escalation tuned a bit more aggressively
TIER_CHECKBOX_MIN=15
TIER_HARD_POW_MIN=35
TIER_BLOCK_MIN=80

# Verify-time thresholds tuned a bit tighter
VERIFY_SHADOW_MIN=25
VERIFY_BLOCK_MIN=55

# IP reputation from a maintained list
IP_REPUTATION_FILE=/etc/bollwark/ip_reputation.txt

# Reverse-proxy aware client IP + TLS fingerprint via Cloudflare.
# TRUSTED_PROXIES gates BOTH the X-Forwarded-For walk AND the TLS
# fingerprint header — direct clients can't spoof either without
# being in this CIDR list.
TLS_FINGERPRINT_HEADER=cf-ja4
TLS_FINGERPRINT_FILE=/etc/bollwark/ja4_blocklist.txt
TRUSTED_PROXIES="173.245.48.0/20,103.21.244.0/22,..."  # CF ranges

# Validation dashboard
ADMIN_DB_PATH=/var/lib/bollwark/decisions.db

RUST_LOG=bollwark=info
```

For local development, the bare minimum (just the testsite + scoring scaffold):

```bash
DEFAULT_DIFFICULTY=8 cargo run
```
