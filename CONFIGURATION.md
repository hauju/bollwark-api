# Configuration

All runtime configuration is via environment variables. Every setting is optional with a sensible default — the service starts cleanly with `cargo run` and no env vars set, running with the puzzle pipeline only (rate + header anomaly signals active).

A `.env` file in the working directory is loaded automatically at startup (via `dotenvy`). Existing shell env vars take precedence, so you can override values without editing the file. Copy `.env.example` to `.env` to get started.

## Quick reference

| Variable | Default | Purpose |
|---|---|---|
| `LISTEN_ADDR` | `0.0.0.0:3000` | Socket address to bind |
| `RUST_LOG` | `info` | Tracing filter |
| `STATIC_DIR` | `static` | Filesystem directory for the bundled widget assets and landing page. Resolved relative to the process working directory unless absolute. |
| `PUZZLE_ALGORITHM` | `argon2id` | PoW algorithm: `argon2id` (default, memory-hard) or `sha256`. SHA-256 is fast to verify but trivially GPU-parallelised, so it taxes honest browsers more than attackers; Argon2id collapses that asymmetry. |
| `ARGON2_M_COST` | `8192` | Argon2id memory cost in KiB (when `PUZZLE_ALGORITHM=argon2id`) |
| `ARGON2_T_COST` | `2` | Argon2id iteration count |
| `ARGON2_P_COST` | `1` | Argon2id lanes / parallelism |
| `DEFAULT_DIFFICULTY` | `5` (argon2id) / `18` (sha256) | Base PoW difficulty (leading zero bits). The default tracks `PUZZLE_ALGORITHM` since each Argon2id hash is orders of magnitude slower than SHA-256. An explicit value overrides. |
| `MAX_DIFFICULTY` | `10` (argon2id) / `28` (sha256) | Upper clamp on the final difficulty (tier bump + `LOAD_LADDER` floor). Also algorithm-tracking so a bump/rung can't push a memory-hard solve into the minutes range. |
| `LOAD_LADDER` | _unset_ | Aggregate site-load difficulty floor. Comma-separated `threshold:difficulty` rungs, e.g. `200:20,500:22,1000:24` (thresholds are requests per `RATE_WINDOW_SECS` window; difficulty in leading zero bits). When the per-site request count crosses a rung, the floor is raised for every visitor. Composes with the per-request tier via `max()`, clamped to `MAX_DIFFICULTY`. Never blocks — only raises difficulty. Empty/unset = no floor. Malformed = boot panics. |
| `CHALLENGE_TTL_SECS` | `300` | How long an issued puzzle is valid |
| `CLEANUP_INTERVAL_SECS` | `60` | How often expired challenges + stale rate windows are swept. Coerced to at least `1` — a `0` period would panic the sweeper and let the in-memory maps grow unbounded. |
| `MAX_ACTIVE_CHALLENGES` | `1000000` | Global ceiling on challenges held in memory. Once reached, `GET /v1/puzzle` sheds new issuance with `block` (429) regardless of score — a memory backstop against a distributed / IPv6-spread flood that stays under `IP_HARD_LIMIT` per source. `0` disables (and skips the per-request count check). |
| `TIER_CHECKBOX_MIN` | `20` | Score at/above which tier becomes `checkbox` |
| `TIER_HARD_POW_MIN` | `40` | …becomes `hard_pow` (covers the whole 40–`TIER_BLOCK_MIN` band) |
| `TIER_BLOCK_MIN` | `85` | …becomes `block` (returns 429) |
| `IP_HARD_LIMIT` | `500` | Hard per-IP issuance cap: once an IP (IPv6: its /64 bucket) exceeds this many puzzle requests in the 60s rate window, further requests are throttled to a **max-difficulty PoW** regardless of score (not a 429 — a hard block would strand CGNAT users). `0` disables. Set `0` (or higher) when load-testing from a single IP. |
| `VERIFY_SHADOW_MIN` | `30` | Verify-time score for shadow-fail (success returned, log emitted) |
| `VERIFY_BLOCK_MIN` | `60` | Verify-time score for hard rejection |
| `VERIFY_MAX_ATTEMPTS` | `10` | Max failed PoW attempts a single challenge tolerates before the store evicts it. A wrong nonce leaves the challenge live for legitimate retry, so this bounds how many (with `argon2id`, memory-hard) verify attempts one challenge can absorb. `0` disables the cap. |
| `VERIFY_REQUIRE_BEHAVIOR` | `false` | When truthy, a verify request with no `behavior` blob scores +30 (like a flatline) instead of 0. Enable when every legitimate client is the bundled widget. |
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

### `STATIC_DIR`
Filesystem directory holding the bundled browser widget assets and the `landing.html` page served at `/`.

- Default: `static`
- Resolved relative to the process working directory unless absolute. Deployments not started from the repo root (systemd, etc.) should set an absolute path; the Dockerfile's `WORKDIR` already handles the container case.
- Only the filesystem location is configurable — the `/static` URL prefix is unaffected.

---

## PoW configuration

PoW difficulty is the number of **leading zero bits** the SHA-256 hash of `prefix || nonce` must have. Each additional bit roughly doubles the expected solve time.

### `DEFAULT_DIFFICULTY` (default `5` for argon2id, `18` for sha256)
Base difficulty for `invisible_pass` tier. Because per-hash cost differs by orders of magnitude between the algorithms, the default follows `PUZZLE_ALGORITHM`; an explicit `DEFAULT_DIFFICULTY` always overrides. The SHA-256 wall-clock table (each additional bit doubles expected solve time):

| Difficulty (sha256) | Modern CPU | Low-end mobile (Web Worker) |
|---|---|---|
| 16 | ~100ms | ~1–2s |
| 18 | ~300ms | ~3–5s |
| 20 | ~1s | ~10–15s |
| 22 | ~4s | timeout territory |

For Argon2id, a single memory-hard hash already costs tens of milliseconds, so `5` bits (~32 expected hashes) lands in a comparable few-hundred-ms-to-few-seconds range. Setting Argon2id with a SHA-256-scale difficulty (e.g. `18`) makes puzzles effectively unsolvable — the server logs a loud WARN at boot when it detects that combination.

### `MAX_DIFFICULTY` (default `10` for argon2id, `28` for sha256)
Upper clamp on the final difficulty. The risk tier can bump difficulty above `DEFAULT_DIFFICULTY`:
- `invisible_pass` → `DEFAULT_DIFFICULTY`
- `checkbox` → `DEFAULT_DIFFICULTY + 2`
- `hard_pow` → `DEFAULT_DIFFICULTY + 4`

The result (after composing with the `LOAD_LADDER` floor) is clamped to `MAX_DIFFICULTY`. There is no lower clamp — the former `MIN_DIFFICULTY` knob belonged to a superseded difficulty calculator and never affected the risk pipeline; it has been removed and is ignored if set.

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

### Argon2id verify-side cost

With `argon2id` (the default), every `POST /v1/verify` re-derives one full Argon2id hash server-side to check the submitted nonce. At the defaults (`ARGON2_M_COST=8192` KiB, `ARGON2_T_COST=2`, `ARGON2_P_COST=1`) that is tens of milliseconds of CPU plus an 8 MiB allocation **per attempt**. Two mechanisms bound the resulting DoS surface:

- The verify hash runs on a `spawn_blocking` thread, not an async runtime worker, so even a burst of memory-hard verifies can't starve the runtime and stall other endpoints (`/v1/puzzle`, `/healthz`).
- A failed PoW check leaves the challenge live for legitimate wrong-nonce retry, but `VERIFY_MAX_ATTEMPTS` (default 10) evicts a challenge once its failed-attempt count hits the cap, so one challenge can't be reused as an unlimited work amplifier.

`/v1/verify` is still gated only by the per-site secret bearer token, so the residual exposure is a hostile or compromised integrator (or a leaked secret), not the anonymous public — but they can no longer take the whole service down or replay one challenge indefinitely. The `sha256` path runs inline (one SHA-256 hash per verify is negligible).

Keep `ARGON2_M_COST` modest so each verify stays cheap, treat every `secret_key` as a sensitive credential, and put proxy-level rate limiting in front of `/v1/verify` if your integrators are not fully trusted.

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

### `IP_HARD_LIMIT` (default `500`)

A hard per-IP issuance cap that sits *outside* the scoring pipeline. The rate signal maxes out at +45, so a flood with clean browser headers can never reach `TIER_BLOCK_MIN` on its own. Once an IP (IPv6: its /64 bucket) exceeds the cap within the 60s rate window, further requests are throttled to a **max-difficulty** PoW (`hard_pow` tier at `MAX_DIFFICULTY`) regardless of score — *not* a hard 429. A plain block would also strand shared-IP populations (CGNAT / corporate NAT: hundreds of legitimate users behind one address) with no recourse, so max PoW is used instead: it makes each request expensive enough to throttle an abuser while a real user still gets through, slowly. The runaway-memory concern the cap originally guarded (each issued challenge sits in memory) is handled separately by `MAX_ACTIVE_CHALLENGES`. The window resets like any other rate counter. The default `500`/min is far above organic per-visitor traffic (the widget fetches one puzzle per page load), including large CGNAT egresses. Set `0` to disable — do this (or raise it) when driving load tests such as `examples/loadgen.rs` from a single IP.

### Puzzle-time signals

| Signal | Max contribution | Enabled by |
|---|---|---|
| Rate (per-IP — IPv6 bucketed to /64 — over a 60 s **and** a 15 min window, + per-site over 60 s) | 45 | Always on |
| Header anomaly (UA / Accept-Language / Accept-Encoding / fetch metadata / client hints) | 75 | Always on |
| IP reputation | 40 | `IP_REPUTATION_FILE` |
| TLS fingerprint | 35 | `TLS_FINGERPRINT_HEADER` + `TRUSTED_PROXIES` |

Every signal self-gates on its own input: header anomaly always computes, IP reputation contributes 0 without `IP_REPUTATION_FILE`, and TLS fingerprint contributes 0 unless a trusted proxy supplied the header. There is no global on/off switch — the service is cookie-free and runs these signals under legitimate interest with data minimization. Tuning the per-signal score weights requires a code change (see `src/risk/signals.rs` and the per-signal modules); only the **tier thresholds** are env-tunable.

Rate components: the per-IP counter is read over two tumbling windows, 60 s (>10 → +8, >20 → +15, >50 → +30) and 15 min (>90 → +8, >180 → +15, >450 → +30), and the IP component is the **worse band of the two, never the sum** — so a one-minute burst scores exactly as it did with one window and the signal's ceiling stays at 45. The 15-minute window exists for the source that paces itself just under the minute thresholds: 9 requests a minute never trips `>10`, but 135 in a quarter hour does. Its thresholds are the rate a source must *hold* for the whole window — roughly 6 / 12 / 30 a minute — which no single visitor produces (the widget fetches one puzzle per page load plus one refresh per `CHALLENGE_TTL_SECS`) but a shared egress can, which is why the lowest band is still below `TIER_CHECKBOX_MIN` on its own. Per-site stays on the single 60 s window (>200 → +8, >500 → +15); sustained site load is `LOAD_LADDER`'s job. Both per-IP counts are emitted on the `puzzle_decision` event as `ip_count` / `ip_count_sustained`.

Header anomaly components:

| Check | Score |
|---|---|
| `User-Agent` missing | +30 |
| `User-Agent` shorter than 10 chars, or naming an HTTP library (`curl`, `wget`, `python`, `go-http`, `libwww`, `httpclient`, `java/`) | +25 |
| `Accept-Language` missing | +10 |
| `Accept-Encoding` missing | +10 |
| UA claims a browser (`Mozilla/`) but none of `Sec-Fetch-Mode` / `-Site` / `-Dest` is present | +15 |
| UA claims Chromium (`Chrome/`) but `Sec-CH-UA` is absent | +15 |

The last two are **browser impersonation** checks. Fetch metadata has been attached to every browser request since Chrome 76 / Firefox 90 / Safari 16.4, and Chromium has sent the low-entropy client hints since 89; both are forbidden header names, so page script can neither add nor suppress them. An HTTP library with a copied Chrome UA string sends neither and lands on +30 — the same weight as omitting the UA, i.e. `checkbox` under the default bands. Each check alone stays below `TIER_CHECKBOX_MIN`, so the known false-positive populations — pre-16.4 Safari, a header-stripping proxy or extension — see no friction unless another signal also fires. WebKit and Gecko never send client hints, which is why that check is gated on `Chrome/` (Chrome on iOS reports `CriOS/` and is excluded). Both checks test presence only; the header values are never read.

---

## Verify-time scoring

After a PoW solution is verified, a second scoring pass runs against verify-time-only signals (time-on-page, honeypot, behavioral telemetry). The result is one of three decisions:

> **Time-on-page** is measured from the visitor's arrival, not from the challenge they happen to be holding. The widget silently refreshes its challenge shortly before expiry, and that refresh carries the original anchor forward (via `refresh_of` on `GET /v1/puzzle`), so a visitor who has had the form open for five minutes is not scored as having just arrived. It is always derived server-side — a client cannot claim a longer dwell than it actually had.

| Score range | Decision | Response | Side effect |
|---|---|---|---|
| `0` — `VERIFY_SHADOW_MIN-1` | `Pass` | `success: true` | DEBUG log |
| `VERIFY_SHADOW_MIN` — `VERIFY_BLOCK_MIN-1` | `ShadowFail` | `success: true` | WARN log (the response body is identical to `Pass`; the log is the only signal) |
| `VERIFY_BLOCK_MIN` — | `Block` | `success: false` | INFO log |

### `VERIFY_SHADOW_MIN` (default `30`)
At/above this, the request is shadow-failed: success is still returned to the caller (they see no failure), but a structured WARN log fires for offline review. No persistent quarantine store yet — the log is the audit trail.

### `VERIFY_BLOCK_MIN` (default `60`)
At/above this, the request is hard-rejected (`success: false`).

### `VERIFY_REQUIRE_BEHAVIOR` (default `false`)
By default, a verify request with no `behavior` blob at all contributes 0 — a deliberate allowance for server-to-server integrations and pre-blob clients. The flip side: a bot that skips the widget and hits the API directly opts out of the behavioral layer entirely. When every legitimate client is the bundled widget (which always sends the blob), set this truthy so an absent blob scores +30, same as a flatline — that alone lands in the shadow band, so rollout is observable before it costs anyone a pass. To make a missing blob hard-block instead, lower `VERIFY_BLOCK_MIN` to `30` alongside it.

### Verify-time signals

| Signal | Score |
|---|---|
| Honeypot field non-empty | +100 (always blocks) |
| Time-on-page < 500ms | +50 |
| Time-on-page < 2000ms | +25 |

| Behavior: flatline (zero events) | +30 |
| Behavior: blob absent (only with `VERIFY_REQUIRE_BEHAVIOR`) | +30 |
| Behavior: isolated click without pointer movement (≤1 interaction) | +15 |
| Behavior: sub-50ms first interaction, isolated (≤1 interaction) | +20 |
| Behavior: driven browser (`navigator.webdriver` **or** driver artifacts) | +30 |
| Behavior: headless hints | +20 |
| Behavior: impossible timing (`first_interaction_ms` > dwell + 30 s) | +30 |
| Behavior: duplicate blob (5th identical activity-claiming blob per site / 10 min) | +30 |

The two automation markers — `navigator.webdriver` and driver artifacts (ChromeDriver's `cdc_` globals, legacy Selenium/PhantomJS markers) — are **one dimension and saturate at +30**; they don't sum. They describe the same fact, and scoring them additively would put every driven browser at the block threshold. The artifact probe adds *recall*, catching drivers that scrub `navigator.webdriver` but leave the globals behind.

Headless hints (`HeadlessChrome` UA, zero outer window dimensions, empty `navigator.languages`) sit at +20 — deliberately below `VERIFY_SHADOW_MIN`, so a false positive on an otherwise-organic visitor changes nothing on its own. Modern headless modes defeat these checks; like the rest of the behavioral layer they raise the floor against the cheap long tail rather than catching stealth tooling. All three probes are reduced to a single boolean in the browser, so the blob carries no fingerprinting entropy.

**The last two rows score the blob itself, not the visitor.** Everything above them takes the counters at face value; a direct-API bot that simply *asserts* an organic-looking blob (`{"mouse_moves": 20, "interactions": 2, "first_interaction_ms": 800}`) scores nothing on any of them. These two ask whether the assertion holds up. Neither needs a new wire field, so both apply to every widget already deployed.

*Impossible timing.* `first_interaction_ms` is measured in the browser from the widget's page-load anchor, which is set *before* the widget fetches its puzzle; the server's dwell clock starts when it issues the challenge. So a claimed first interaction may legitimately run ahead of the server's dwell — but only by the length of that fetch. Beyond it, the blob describes an interaction that happened after the visitor was already submitting. The 30 s slack is far past any real fetch (the widget's own retry backoff totals 1.2 s), and the headroom is the point: **any visitor whose first interaction was within 30 s of the widget mounting can never trip this**, which also covers the one case where the dwell anchor legitimately jumps forward — a pre-expiry refresh deferred while the tab was hidden past the TTL, citing a challenge the server has already swept. Blobs with no `first_interaction_ms` (pointer-only visitors — `mousemove` doesn't set it) are out of scope, and so is the failover path, which has no challenge and therefore no dwell.

*Duplicate blobs.* Humans do not produce identical counters. `first_interaction_ms` alone is a millisecond reading, so two real visitors collide only when it is null — no click, keypress, scroll, focus or touch before submit — leaving `mouse_moves` as the single varying field. **Flatline blobs are excluded from dedup entirely**: every visitor who submits without touching the page produces the same one, and it is already worth +30. What remains as a collision risk is the visitor who moved a pointer and did nothing else, so the threshold sits well clear of a two-person coincidence at **5 identical blobs per site inside a 10-minute window** — while a script pacing itself at one submission a minute (under the 60 s rate window, invisible to the rate signal) still reaches it comfortably. Counting is per site: one tenant's traffic can never push another tenant's visitors over the line. The key is a hash of the blob's *parsed fields*, not the raw JSON, so re-ordering keys or spelling out a default does not mint a fresh identity.

Both land at +30 — shadow band alone under the default `30`/`60`, never a block on their own, the same rollout stance as `VERIFY_REQUIRE_BEHAVIOR`. They **stack** with each other and with the rows above: they are separate facts (one about this submission's internal consistency, one about the population of submissions this site received), unlike the `webdriver`/`automation` pair which are two readings of one. A client that is both internally impossible and mass-produced therefore reaches `VERIFY_BLOCK_MIN` on the behaviour component alone. All of it folds into the single `behavior` component of the decision log; the `verify_decision` log event carries `impossible_timing` and `duplicate_blob` booleans so you can see which fired.

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

Sites are registered with `POST /v1/sites`, which returns a `site_key` (public, embedded in the widget) and a `secret_key` (server-to-server, used as the bearer for `/v1/verify`). An optional `allowed_origins` array (`http(s)://host[:port]` entries, max 32) restricts which browser origins `GET /v1/puzzle` serves — a non-listed `Origin` gets `403`; requests with no `Origin` header always pass. This is tenant hygiene (quota/stats protection), not bot defense — `Origin` is browser-set only. Change it later without rotating the secret via `PUT /v1/admin/sites/{id}/origins`. A site's `name` is a label only — nothing in the scoring pipeline reads it — and can be changed with `PUT /v1/admin/sites/{id}/name`, which trims and length-checks it exactly like provisioning does. Two settings govern this surface:

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
Path to a SQLite file that persists site rows. When unset, sites live only in `Arc<RwLock<HashMap>>` and are lost on restart — meaning every integrator's stored `secret_key` becomes invalid. **Set this for any deployment beyond local dev.** Created on first run, schema is `(site_key TEXT PRIMARY KEY, secret_key TEXT UNIQUE, name TEXT, created_at TEXT, allowed_origins TEXT, policy TEXT)`. Databases from before `allowed_origins` or `policy` shipped are migrated in place on open.

Challenges and rate-window counters intentionally stay in-memory: they're cheap to lose and a fresh start is fine.

---

## Per-site policy

Every scoring knob below is a process-global env var, which is the right default for a single-tenant appliance. It stops being right the moment one instance protects forms with genuinely different risk profiles — a low-traffic contact form and a login endpoint under credential-stuffing want different bands, and previously you had to pick one or run a second instance.

A **site policy** overrides those globals for one site. Every field is optional and an omitted field *inherits the env value*, including later changes to it — a policy is a sparse overlay, never a full copy. A site with no policy behaves exactly as it did before policies existed.

| Policy field | Overrides |
|---|---|
| `tier_checkbox_min` | `TIER_CHECKBOX_MIN` |
| `tier_hard_pow_min` | `TIER_HARD_POW_MIN` |
| `tier_block_min` | `TIER_BLOCK_MIN` |
| `verify_shadow_min` | `VERIFY_SHADOW_MIN` |
| `verify_block_min` | `VERIFY_BLOCK_MIN` |
| `default_difficulty` | `DEFAULT_DIFFICULTY` |
| `max_difficulty` | `MAX_DIFFICULTY` |
| `mode` | *(no env equivalent)* — `"enforce"` (default) or `"monitor"`, see below |

Set it at provisioning time:

```bash
curl -X POST http://localhost:3000/v1/sites \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "name": "login",
        "policy": {
          "tier_checkbox_min": 10,
          "tier_hard_pow_min": 25,
          "tier_block_min": 60,
          "verify_block_min": 30
        }
      }'
```

or change it later without rotating the secret:

```bash
curl -X PUT http://localhost:3000/v1/admin/sites/$SITE_KEY/policy \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tier_block_min": 60}'
```

The body **replaces** the stored policy rather than merging into it, so `{}` clears every override and returns the site to the env defaults. A merge would make "unset this override" inexpressible, since both `null` and *absent* have to mean *inherit* for the type to work at all. Changes take effect on the next request; challenges already issued keep the difficulty they were stamped with.

**Validation.** A submitted policy is checked *after* being merged with the running config, because a partial override is only meaningful in combination with the globals — `{"tier_block_min": 10}` is unremarkable on its own but puts Block underneath the default `TIER_CHECKBOX_MIN=20`, leaving two bands unreachable. Rejected with `400`:

- a difficulty of `0` (accepts any nonce — the PoW is off for that site)
- `default_difficulty` above `max_difficulty` (the clamp would silently win)
- tier thresholds not non-decreasing (`classify` tests block → hard_pow → checkbox, so out of order the higher tier swallows the lower bands)
- `verify_shadow_min` above `verify_block_min` (empty shadow band)
- `tier_block_min` or `verify_block_min` of `0` (matches every score, so the site is down rather than strictly policed)

This mirrors the fail-loud stance `AppConfig::validated` takes for the global equivalents — a write-time `400` is the closest thing to a boot panic for something that arrives over HTTP.

`GET /v1/admin/sites` returns each site's policy, and the `puzzle_decision` log line carries `site_policy=true|false` so a tier that looks wrong against the documented defaults is distinguishable from a bug.

### Monitor mode

Pointing a live form at a new CAPTCHA is a leap of faith. `"mode": "monitor"` makes it not one: the full pipeline runs against real traffic and every verdict is scored and logged exactly as it would be when enforcing — but no visitor is ever refused. Run a site there for a week, read what it *would* have blocked, then flip to `"enforce"`. No arithmetic changes when you do, so the numbers you saw are the numbers you get.

```bash
curl -X PUT http://localhost:3000/v1/admin/sites/$SITE_KEY/policy \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"mode": "monitor"}'
```

What changes while monitoring:

| Situation | Enforcing | Monitoring |
|---|---|---|
| Puzzle-time `Block` tier | `429` | Puzzle issued at `max_difficulty` |
| Verify-time `Block` decision | `{"success": false}` | `{"success": true}` |
| Attested-outage failover claim refused on behaviour | `{"success": false}` | `{"success": true}` |

What does **not** change — monitor mode is scoped to *risk verdicts about a visitor*, and these are not that:

- **The load sheds.** `MAX_ACTIVE_CHALLENGES` and the flooder shed protect the whole instance, not one visitor. A monitored tenant still gets `429` when the challenge map is full, or one customer parked in observe mode could exhaust memory for every other site on the box.
- **An invalid proof of work.** A wrong nonce is a failed proof, not a judgement.
- **An unattested failover claim.** Refusing it means "you asserted an outage that didn't happen", which isn't a risk score.
- **The origin allowlist.** That's configuration the operator set deliberately.

**Reading the results.** Blocks that were observed rather than enforced stay in the ordinary `block` / `rejected` counts, so the dashboard keeps answering "what would I block?" without you having to look anywhere new. What marks them is a separate `monitored` flag:

- `GET /v1/admin/stats` → `outcomes.puzzle_monitored` / `outcomes.verify_monitored`. Subtract these to get what was actually refused.
- `GET /v1/admin/sessions` → `monitored` on the session and on its `verify` section; the dashboard renders a `monitor` pill beside the tier and outcome.
- `puzzle_decision` / `verify_decision` log lines carry `monitored=true`.

A monitored verify row is the one place `outcome` and `success` disagree on purpose: `outcome: "block"` with `success: true` reads as *this one would have been refused, and wasn't*.

> Monitor mode is not "off". A Block-tier visitor still has to solve a max-difficulty proof of work — the strongest response available that doesn't refuse anyone. A monitored site is weakened, not unprotected.

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

## Client failover

**Off by default.** The widget is a hard dependency of every form it guards: if `GET /v1/puzzle` fails, the visitor gets no token and the integrator's backend rejects the submit — so this service's downtime becomes theirs, on every embedding site at once.

With failover enabled, a widget that can't reach the service (after a short retry backoff) mints a *failover claim* instead of a solved token, and the form still submits. `POST /v1/verify` honors that claim **only while this service independently attests it was down**.

### What a failover claim proves

Nothing, on its own. During an outage we cannot have signed anything, so the claim is plain client-authored JSON that anyone can fabricate. Honoring one is a deliberate fail-open. What bounds it:

| Bound | Effect |
|---|---|
| **Attestation** | Refused unless there's an outage window this service recorded itself. No window → refused, always. |
| **Recency** | Acceptance keys on *now* falling inside a window or its grace tail — never on the claim's `issued_at`, which is forgeable. A closed window can't be reopened by backdating. |
| **Rate cap** | `FAILOVER_MAX_PER_MIN` per site, so catching a real outage still doesn't buy unbounded fail-open traffic. |
| **Local evidence** | The honeypot and behaviour blob are collected in the browser and survive the outage, so they're still scored. A flatline + `webdriver` blob is refused *inside* an attested window. |
| **Marking** | Acceptance returns `failover: true` on the verify response and emits a `WARN` with `outcome=failover_pass`. |

Inside an attested window a determined attacker does get through. That's the trade: a bounded, observable fail-open instead of taking every embedding form down. Enable it only if you'd rather your integrators' signup forms keep working than have them hard-fail during your outage.

Pair it with **`VERIFY_REQUIRE_BEHAVIOR=true`** if every legitimate client is the bundled widget — the widget always sends a behaviour blob even in failover, so requiring one keeps a direct-API caller from minting an evidence-free claim.

### How outages get attested

Two sources, covering two different failure modes:

1. **Heartbeat gap** (automatic). The process writes a liveness timestamp to `FAILOVER_STATE_PATH` every `FAILOVER_HEARTBEAT_INTERVAL_SECS`. On boot, a gap larger than `FAILOVER_MIN_GAP_SECS` is recorded as an outage window covering it. Catches crashes, OOM kills, deploys, host reboots.
2. **Operator-declared** (`POST /v1/admin/outages`). Catches what a heartbeat structurally *cannot* see: the process healthy the entire time while something in front of it — TLS, DNS, CDN, reverse proxy — made the widget unreachable to browsers. This is the Traefik self-signed-cert failure mode `scripts/check-public-endpoint.sh` exists for; set `MONITOR_ADMIN_TOKEN` and that script declares the window itself when a check fails.

### `FAILOVER_ENABLED` (default `false`)
Master switch. Requires `FAILOVER_STATE_PATH`; without it, failover stays off and a `WARN` is logged at boot.

### `FAILOVER_STATE_PATH` (default _unset_)
JSON file holding the heartbeat and attested windows. Must be on a volume that **survives restarts** — a heartbeat gap can only be detected by comparing against a timestamp that outlived the restart, and a declared window would be lost on the very restart it covers. A missing or corrupt file degrades to "nothing attested" (all claims refused), never a boot failure.

### `FAILOVER_HEARTBEAT_INTERVAL_SECS` (default `15`)
Heartbeat cadence. Bounds how much of a real outage goes unattested: the window starts at the *last* heartbeat, so a coarse cadence under-reports the outage's leading edge.

### `FAILOVER_MIN_GAP_SECS` (default `60`)
Minimum heartbeat gap treated as an outage. Below this a restart is assumed routine (deploy, config reload) rather than downtime worth opening a fail-open window for.

### `FAILOVER_GRACE_SECS` (default `300`)
How long after a window closes a claim is still honored. Covers the visitor who loaded the form *during* the outage and submits minutes later, once you're already back — without it, failover would only help visitors who submitted before recovery, i.e. almost nobody. This is also the blast radius: exactly how long the fail-open stays open after recovery.

### `FAILOVER_MAX_PER_MIN` (default `600`)
Per-site cap on **accepted** claims per rolling minute. `0` disables the cap.

### `POST /v1/admin/outages` (bearer `ADMIN_TOKEN`)
Declare a window. Either `{"duration_secs": 900}` (a window ending now) or `{"start": "...", "end": "..."}` (RFC 3339, for backfilling). Capped at 24h per window so a fat-fingered declaration expires on its own. Returns the current window list and counters.

### `GET /v1/admin/outages` (bearer `ADMIN_TOKEN`)
Active windows plus `accepted_total` / `refused_total` since boot. Use it to confirm a declaration landed and to see whether anyone is probing for a fail-open.

### What failover cannot cover

If **`captcha-widget.js` itself fails to load** — the exact symptom of the TLS breakage above — no widget code runs, so there is nothing to fall back to. That case is the embedder's to handle with a `script.onerror` / load-timeout fallback; see `INTEGRATION.md`.

Likewise, if this service is *fully* unreachable, the integrator's backend can't reach `/v1/verify` either. That decision (fail open or closed on a connection error) is theirs, and also documented in `INTEGRATION.md`.

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

Live scoring (rate window, IP reputation, XFF resolution) always operates on the **full** IP, so anonymizing the logged copy does not weaken detection. Set `ANONYMIZE_LOG_IP=false` to store full IPs where the operator is the data controller and needs them for abuse forensics. The flag applies to *everything the handler emits*: both the durable decision log and the structured `puzzle_decision` tracing event (`ip=…`) use the truncated copy when it's on, so shipping stderr to a log aggregator doesn't leak per-visitor addresses.

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
| Rate (per-IP over 60 s and 15 min + per-site over 60 s) | Yes | Transient counters, no per-IP profile retained |
| Header anomaly (UA / Accept-Language / Accept-Encoding / fetch metadata / client hints) | Yes | Scored transiently from headers the browser already sends; `Sec-Fetch-*` and `Sec-CH-UA` are checked for presence only, never read; no stable identifier persisted |
| Honeypot | Yes | No PII |
| Time-on-page | Yes | Derived server-side, transient |
| Behavior (mouse / touch / `webdriver`) | Yes | Ephemeral, submitted for one verification, not linked to an identity |
| Behavior blob dedup (5 identical blobs per site / 10 min) | Yes | In-memory only, never logged and never persisted. The key is a non-reversible hash of the blob's event counters scoped to one site — a count of mouse moves and clicks identifies no person, carries no device or network identifier, and the window is reclaimed by the same sweeper that clears the rate counters |
| IP reputation | Only with `IP_REPUTATION_FILE` | Transient CIDR lookup; the full IP is never persisted (the decision log truncates it — see `ANONYMIZE_LOG_IP`) |
| TLS fingerprint | Only with `TLS_FINGERPRINT_HEADER` + `TRUSTED_PROXIES` | The one device-fingerprint signal; opt-in via its own env vars |
| Geo country (dashboard only) | Only with `GEOIP_DB_PATH` | Not a scoring signal — observability only. Offline lookup on the already-truncated logged IP; resolves country-level, stores only a 2-letter code |

What keeps this defensible: no cookies or other terminal-device storage (so no ePrivacy Art. 5(3) consent), short-lived transient processing for security (legitimate interest, Art. 6(1)(f)), and IP truncation before anything durable is written. As always, the final compliance determination — including a DPIA if you enable IP reputation or TLS fingerprinting — rests with you as the data controller.

---

## Putting it all together

A production-leaning configuration:

```bash
LISTEN_ADDR=0.0.0.0:3000

# PoW defaults to argon2id (memory-hard) at DEFAULT_DIFFICULTY=5. To use the
# faster-but-GPU-parallelisable SHA-256 instead, set both:
#   PUZZLE_ALGORITHM=sha256
#   DEFAULT_DIFFICULTY=18

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
