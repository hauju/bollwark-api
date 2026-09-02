use std::env;
use std::net::SocketAddr;

use crate::puzzle::types::{Algorithm, Argon2idParams};
use crate::risk::LoadLadder;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub listen_addr: SocketAddr,
    /// Filesystem directory holding the bundled widget assets and landing page.
    /// Resolved relative to the process working directory unless absolute.
    pub static_dir: String,
    /// PoW algorithm for new challenges. `argon2id` (default) or `sha256`.
    /// The difficulty defaults below track the algorithm — each Argon2id
    /// hash is orders of magnitude slower than SHA-256, so argon2id's
    /// default 5 leading zero bits is comparable to SHA-256's default 18.
    pub puzzle_algorithm: Algorithm,
    pub default_difficulty: u32,
    /// Upper clamp on the final PoW difficulty after the tier bump and the
    /// `LOAD_LADDER` floor are applied.
    pub max_difficulty: u32,
    /// Aggregate site-load difficulty floor. When the per-site request count in
    /// the rate window crosses a configured threshold, the PoW difficulty is
    /// floored (raised for every visitor, not just high-risk ones). Empty by
    /// default — the floor is 0 until `LOAD_LADDER` is set. Never blocks; it
    /// only raises difficulty, composed with the per-request tier via `max()`.
    pub load_ladder: LoadLadder,
    pub challenge_ttl_secs: u64,
    /// Cadence of the background sweeper that reclaims expired challenges and
    /// stale rate-window entries. Coerced to at least 1s — `tokio::time::interval`
    /// panics on a zero period, which would silently kill the only reclaimer
    /// and let the in-memory maps grow unbounded.
    pub cleanup_interval_secs: u64,
    /// Global ceiling on the number of challenges held in memory at once. Once
    /// reached, `GET /v1/puzzle` sheds new issuance via the Block tier (429)
    /// regardless of per-IP score — a memory backstop against a distributed
    /// flood (or an IPv6 /64-spread attacker) that stays under `IP_HARD_LIMIT`
    /// per source. Default 1_000_000 (~200 MB of challenges); `0` disables the
    /// cap and skips the per-request count check entirely.
    pub max_active_challenges: usize,
    pub tier_checkbox_min: u32,
    pub tier_hard_pow_min: u32,
    pub tier_block_min: u32,
    /// Hard per-IP issuance cap: once an IP (IPv6: its /64 bucket) exceeds
    /// this many puzzle requests in the 60s rate window, further requests are
    /// throttled to a **max-difficulty** PoW regardless of score (not a 429).
    /// Risk scoring alone can't escalate a flood with clean browser headers
    /// (rate maxes at +45, below `TIER_BLOCK_MIN`). A hard block would also
    /// punish shared-IP populations (CGNAT / corporate NAT) with no recourse,
    /// so this throttles instead — max PoW slows an abuser while a legitimate
    /// user still gets through. Memory growth is bounded separately by
    /// `MAX_ACTIVE_CHALLENGES`. Default 500 — far above organic per-IP
    /// traffic. `0` disables.
    pub ip_hard_limit: u32,
    /// Path to a CIDR reputation file. If unset, the IP reputation signal contributes 0.
    pub ip_reputation_file: Option<String>,
    /// Path to a JSON file overriding any subset of the signal weights
    /// (`risk::weights::SignalWeights::NAMES`). Unset → the compiled-in
    /// defaults. A file that fails to parse refuses to boot.
    pub signal_weights_file: Option<String>,
    /// Verify-time score at/above which the request is shadow-failed (success
    /// returned, log emitted). Default 30.
    pub verify_shadow_min: u32,
    /// Verify-time score at/above which the request is hard-rejected. Default 60.
    pub verify_block_min: u32,
    /// Max failed PoW attempts a single challenge tolerates before the store
    /// evicts it. A wrong nonce leaves the challenge live for legitimate retry,
    /// so without this one challenge could absorb unlimited (with `argon2id`,
    /// memory-hard) verify attempts. Default 10; `0` disables the cap.
    pub verify_max_attempts: u32,
    /// When true, a verify request with no `behavior` blob at all scores like
    /// a flatline (+30) instead of 0. Off by default so server-to-server
    /// integrations aren't penalized; turn it on when every legitimate client
    /// is the bundled widget (which always sends the blob) — otherwise the
    /// behavioral layer is opt-in for attackers hitting the API directly.
    /// +30 alone lands in the shadow band; combine with a lower
    /// `VERIFY_BLOCK_MIN` to make a missing blob hard-block.
    pub verify_require_behavior: bool,
    /// Header name carrying the TLS fingerprint set by a trusted reverse proxy
    /// (e.g. `x-ja4`). If unset, the TLS fingerprint signal is disabled.
    pub tls_fingerprint_header: Option<String>,
    /// Path to a file listing known-bad TLS fingerprints (one per line, `#` comments).
    pub tls_fingerprint_file: Option<String>,
    /// CIDR allowlist of upstream proxies whose `tls_fingerprint_header` we
    /// trust. Comma- or whitespace-separated. Required when the TLS feature is
    /// enabled — without it, no peer is trusted and the signal never fires.
    pub trusted_proxies: Option<String>,
    /// Path to the SQLite database used to persist puzzle/verify decisions for
    /// the validation dashboard. When unset, dashboard logging and the admin
    /// endpoints are both disabled.
    pub admin_db_path: Option<String>,
    /// Bearer token required by `/v1/admin/*` and by `POST /v1/sites`.
    /// When unset, the dashboard endpoints are simply not mounted and
    /// `POST /v1/sites` returns 404 — no anonymous provisioning.
    pub admin_token: Option<String>,
    /// Path to a SQLite database for persistent site registrations.
    /// When unset, sites live only in memory (lost on restart). Strongly
    /// recommended for any deployment beyond local dev.
    pub site_db_path: Option<String>,
    /// Comma- or whitespace-separated allowlist of origins permitted to
    /// call `GET /v1/puzzle` from a browser. When unset, any origin is
    /// allowed. When set, only listed origins receive CORS headers —
    /// others get a same-origin response that browsers will block.
    /// Other endpoints never have CORS enabled.
    pub cors_allowed_origins: Option<String>,
    /// **Dev/test only.** When true, `POST /v1/sites` skips the
    /// `ADMIN_TOKEN` bearer check so local-dev pages and Playwright e2e
    /// can register sites anonymously. Refused outside `cfg!(debug_assertions)`
    /// builds — release binaries log a warning and ignore the flag. The
    /// admin dashboard endpoints (`/v1/admin/*`) are NOT bypassed.
    pub dev_disable_admin_auth: bool,
    /// Optional override URL for the bundled `/static/about.html` page.
    /// Must be an absolute `http(s)://` URL when set; the bundled default
    /// is used when unset. Surfaced to the widget via the puzzle response.
    pub info_about_url: Option<String>,
    /// Optional override URL for the bundled `/static/privacy.html` page.
    pub info_privacy_url: Option<String>,
    /// Optional override URL for the bundled `/static/terms.html` page.
    pub info_terms_url: Option<String>,
    /// Anonymize the client IP before it is written to the decision log
    /// (dashboard / `ADMIN_DB_PATH`): IPv4 is truncated to /24, IPv6 to /48.
    /// **Default true** — the durable log keeps only a network prefix, never
    /// a per-visitor address, which is what keeps the dashboard defensible
    /// under GDPR data-minimization. Live scoring always uses the full IP, so
    /// detection is unaffected. Set `ANONYMIZE_LOG_IP=false` to log full IPs
    /// (e.g. for abuse forensics where the operator is the data controller).
    pub anonymize_log_ip: bool,
    /// Retention window for the decision log, in hours. Rows older than this
    /// are pruned by a periodic sweeper (only runs when `ADMIN_DB_PATH` is
    /// set). **Default 72** — the same short window ALTCHA uses; together
    /// with `anonymize_log_ip` it keeps the dashboard's durable log
    /// defensible under GDPR storage-limitation. Set `LOG_RETENTION_HOURS=0`
    /// to disable pruning and keep rows forever (e.g. when the operator is
    /// the data controller and needs a longer forensic trail).
    pub log_retention_hours: u64,
    /// Path to a MaxMind GeoLite2/GeoIP2 *Country* database (`.mmdb`). When set
    /// (and `ADMIN_DB_PATH` is enabled), the decision-log writer stamps each
    /// puzzle row with the visitor's ISO country code, looked up offline on the
    /// already-anonymized IP, so the dashboard can show a country breakdown.
    /// Unset → the `country` column stays NULL and the Countries panel is empty.
    /// Nothing leaves the box; a /24-truncated IP still resolves country-level.
    pub geoip_db_path: Option<String>,
    /// Client failover: honor a widget-minted "I couldn't reach you" claim at
    /// `/v1/verify` while an outage is attested, so our downtime doesn't take
    /// every embedding form down with it. **Off by default** — honoring such a
    /// claim is a deliberate, bounded fail-open (see [`crate::failover`]), and
    /// that trade is the operator's to make. Requires `FAILOVER_STATE_PATH`.
    pub failover_enabled: bool,
    /// Where the failover heartbeat + attested outage windows are persisted.
    /// Unset disables failover outright: without durable state a heartbeat gap
    /// can't be detected across the restart that caused it, and a declared
    /// window would evaporate on the very restart it exists to cover.
    pub failover_state_path: Option<String>,
    /// Cadence of the liveness heartbeat written to `FAILOVER_STATE_PATH`.
    /// Bounds how much of a real outage goes unattested — the window starts at
    /// the *last* heartbeat, so a coarse cadence under-reports the outage's
    /// leading edge. Coerced to ≥1s (`tokio::time::interval` panics on zero).
    pub failover_heartbeat_interval_secs: u64,
    /// Minimum heartbeat gap treated as an outage. Below this, a restart is
    /// assumed routine (deploy, config reload) rather than downtime worth
    /// opening a fail-open window for. Default 60s.
    pub failover_min_gap_secs: u64,
    /// How long after an outage window closes a failover claim is still
    /// honored. Covers the visitor who loaded the form *during* the outage and
    /// submits it minutes later, once we're already back. This is also the
    /// blast radius: it's exactly how long the fail-open stays open after
    /// recovery. Default 300s.
    pub failover_grace_secs: u64,
    /// Per-site cap on *accepted* failover claims per rolling minute. Bounds
    /// how much traffic an attacker who catches a genuine outage can push
    /// through it. Default 600; `0` disables the cap.
    pub failover_max_per_min: u32,
}

impl AppConfig {
    pub fn from_env() -> Self {
        // Parse the algorithm first: the difficulty defaults are tuned per
        // algorithm (SHA-256 and Argon2id differ by orders of magnitude in
        // per-hash cost), so an unset DEFAULT_DIFFICULTY / MAX_DIFFICULTY must
        // follow the selected algorithm.
        let puzzle_algorithm = parse_algorithm_from_env();
        Self {
            listen_addr: env::var("LISTEN_ADDR")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 3000))),
            static_dir: env::var("STATIC_DIR").unwrap_or_else(|_| "static".to_string()),
            puzzle_algorithm,
            default_difficulty: env::var("DEFAULT_DIFFICULTY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| default_difficulty_for(puzzle_algorithm)),
            max_difficulty: env::var("MAX_DIFFICULTY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| max_difficulty_for(puzzle_algorithm)),
            load_ladder: parse_load_ladder(),
            challenge_ttl_secs: env::var("CHALLENGE_TTL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300),
            cleanup_interval_secs: env::var("CLEANUP_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60)
                .max(1),
            max_active_challenges: env::var("MAX_ACTIVE_CHALLENGES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1_000_000),
            tier_checkbox_min: env::var("TIER_CHECKBOX_MIN")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(20),
            tier_hard_pow_min: env::var("TIER_HARD_POW_MIN")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(40),
            tier_block_min: env::var("TIER_BLOCK_MIN")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(85),
            ip_hard_limit: env::var("IP_HARD_LIMIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(500),
            ip_reputation_file: env::var("IP_REPUTATION_FILE").ok(),
            signal_weights_file: env::var("SIGNAL_WEIGHTS_FILE").ok(),
            verify_shadow_min: env::var("VERIFY_SHADOW_MIN")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            verify_block_min: env::var("VERIFY_BLOCK_MIN")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            verify_max_attempts: env::var("VERIFY_MAX_ATTEMPTS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
            verify_require_behavior: parse_truthy(
                env::var("VERIFY_REQUIRE_BEHAVIOR").ok().as_deref(),
            ),
            tls_fingerprint_header: env::var("TLS_FINGERPRINT_HEADER").ok(),
            tls_fingerprint_file: env::var("TLS_FINGERPRINT_FILE").ok(),
            trusted_proxies: env::var("TRUSTED_PROXIES").ok(),
            admin_db_path: env::var("ADMIN_DB_PATH").ok(),
            admin_token: env::var("ADMIN_TOKEN").ok(),
            site_db_path: env::var("SITE_DB_PATH").ok(),
            cors_allowed_origins: env::var("CORS_ALLOWED_ORIGINS").ok(),
            dev_disable_admin_auth: parse_truthy(
                env::var("DEV_DISABLE_ADMIN_AUTH").ok().as_deref(),
            ),
            info_about_url: parse_info_url("INFO_ABOUT_URL"),
            info_privacy_url: parse_info_url("INFO_PRIVACY_URL"),
            info_terms_url: parse_info_url("INFO_TERMS_URL"),
            // Privacy default: on unless explicitly disabled. Any unset value
            // anonymizes; only a recognized truthy/falsey value flips it.
            anonymize_log_ip: env::var("ANONYMIZE_LOG_IP")
                .ok()
                .map(|v| parse_truthy(Some(&v)))
                .unwrap_or(true),
            log_retention_hours: env::var("LOG_RETENTION_HOURS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(72),
            geoip_db_path: env::var("GEOIP_DB_PATH").ok(),
            failover_enabled: parse_truthy(env::var("FAILOVER_ENABLED").ok().as_deref()),
            failover_state_path: env::var("FAILOVER_STATE_PATH").ok(),
            failover_heartbeat_interval_secs: env::var("FAILOVER_HEARTBEAT_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(15)
                .max(1),
            failover_min_gap_secs: env::var("FAILOVER_MIN_GAP_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            failover_grace_secs: env::var("FAILOVER_GRACE_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300),
            failover_max_per_min: env::var("FAILOVER_MAX_PER_MIN")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(600),
        }
        .validated()
    }

    /// Boot-time validation for settings where a single mistyped env var leaves
    /// the process running and apparently healthy while providing zero
    /// protection — the worst failure mode a CAPTCHA has, because the operator
    /// stops watching. Each check below guards a value that is silent when
    /// wrong: a difficulty of 0 passes every visitor without computing a hash,
    /// out-of-range Argon2 params make every verification fail forever, and an
    /// overflowing TTL or retention window panics a handler or a background
    /// sweeper with no further log line.
    ///
    /// Panics with an actionable message rather than clamping, matching the
    /// fail-loud stance of `parse_info_url` and `parse_load_ladder`: silently
    /// correcting a security-relevant value hides the misconfiguration instead
    /// of surfacing it.
    fn validated(self) -> Self {
        // `difficulty_for` computes `default + tier_bump`, clamped by `max`, so
        // the lowest difficulty any tier can produce is `min(default, max)`.
        // Either being 0 means `has_leading_zero_bits(_, 0)` returns true for
        // every hash — the PoW is disabled for everyone, with no error.
        if self.default_difficulty < MIN_DIFFICULTY || self.max_difficulty < MIN_DIFFICULTY {
            panic!(
                "DEFAULT_DIFFICULTY={} / MAX_DIFFICULTY={} — both must be at least {MIN_DIFFICULTY}. \
                 A difficulty of 0 accepts any nonce without computing a hash, so every visitor \
                 (including every bot) passes the proof-of-work. Note MAX_DIFFICULTY clamps \
                 DEFAULT_DIFFICULTY, so setting it to 0 disables the PoW even when \
                 DEFAULT_DIFFICULTY looks correct.",
                self.default_difficulty, self.max_difficulty
            );
        }

        // Argon2 rejects out-of-range costs at hash time, and `compute_argon2id`
        // degrades that to `None` → `verify() == false`. The server would boot
        // cleanly, advertise the invalid params to every browser, and reject
        // every correct solution forever without logging a reason.
        if let Algorithm::Argon2id(p) = self.puzzle_algorithm
            && let Err(e) = argon2::Params::new(p.m_cost, p.t_cost, p.p_cost, None)
        {
            panic!(
                "ARGON2_M_COST={} / ARGON2_T_COST={} / ARGON2_P_COST={} is not a valid Argon2id \
                 parameter set: {e}. The server would start and hand these to every browser, then \
                 fail *every* verification with no error. Valid ranges: m_cost >= {} KiB, \
                 t_cost >= 1, p_cost >= 1.",
                p.m_cost,
                p.t_cost,
                p.p_cost,
                argon2::Params::MIN_M_COST,
            );
        }

        // `generate()` computes `now + Duration::seconds(ttl as i64)`, which
        // panics on overflow — taking down every /v1/puzzle request while
        // /healthz still reports 200.
        if self.challenge_ttl_secs == 0 || self.challenge_ttl_secs > MAX_CHALLENGE_TTL_SECS {
            panic!(
                "CHALLENGE_TTL_SECS={} is out of range (expected 1..={MAX_CHALLENGE_TTL_SECS}). \
                 A TTL of 0 expires every challenge before the client can solve it; an oversized \
                 value overflows the expiry timestamp and panics every puzzle request.",
                self.challenge_ttl_secs
            );
        }

        // `DecisionLog::prune` builds a `chrono::Duration::hours`, which panics
        // above ~2.56e12 hours. The retention sweeper would die on its first
        // tick while the process stays up, so the log grows unbounded and
        // storage-limitation is silently unenforced.
        if self.log_retention_hours > MAX_LOG_RETENTION_HOURS {
            panic!(
                "LOG_RETENTION_HOURS={} is out of range (expected 0..={MAX_LOG_RETENTION_HOURS}, \
                 where 0 disables pruning). An oversized value panics the retention sweeper on its \
                 first tick — the process stays up but the decision log is never pruned again.",
                self.log_retention_hours
            );
        }

        // Failover without durable state is inert: a heartbeat gap can only be
        // detected by comparing against a timestamp that survived the restart,
        // and a declared window would be lost on the very restart it covers.
        // Warn rather than panic — the safe direction is "no failover", which
        // is exactly what happens, and refusing to boot would make an
        // availability feature into an availability risk.
        if self.failover_enabled && self.failover_state_path.is_none() {
            tracing::warn!(
                "FAILOVER_ENABLED is set but FAILOVER_STATE_PATH is not — client \
                 failover stays OFF. Outage attestation needs state that outlives \
                 a restart; without it every failover claim is refused."
            );
        }

        self
    }

    /// Project the failover knobs into the guard's own config type.
    pub fn failover_config(&self) -> crate::failover::FailoverConfig {
        crate::failover::FailoverConfig {
            enabled: self.failover_enabled,
            state_path: self.failover_state_path.as_ref().map(Into::into),
            heartbeat_interval_secs: self.failover_heartbeat_interval_secs,
            min_gap_secs: self.failover_min_gap_secs,
            grace_secs: self.failover_grace_secs,
            max_per_min: self.failover_max_per_min,
        }
    }
}

/// Lowest difficulty that still requires real work. At 0 the PoW predicate is
/// a tautology, so the challenge is free to "solve".
pub const MIN_DIFFICULTY: u32 = 1;

/// Upper bound on `CHALLENGE_TTL_SECS` (365 days). Far above any sane challenge
/// lifetime, and far below the point where `now + ttl` overflows.
const MAX_CHALLENGE_TTL_SECS: u64 = 31_536_000;

/// Upper bound on `LOG_RETENTION_HOURS` (10 years). Keeps both
/// `chrono::Duration::hours` and the `hours * 3600 / 24` sweep cadence well
/// inside their ranges.
const MAX_LOG_RETENTION_HOURS: u64 = 87_600;

/// Read an `INFO_*_URL` env var. Empty/whitespace-only values are treated
/// as unset. Non-empty values must be absolute (`http://` or `https://`),
/// otherwise we panic — a typo'd path here would silently produce a broken
/// widget link in every visitor's browser, which is exactly the kind of
/// misconfiguration we want to fail loud.
fn parse_info_url(name: &str) -> Option<String> {
    let value = env::var(name).ok()?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if !(trimmed.starts_with("https://") || trimmed.starts_with("http://")) {
        panic!(
            "{name}={value:?} must be an absolute http(s):// URL — relative paths and bare \
             filenames would produce broken links in the widget. Set the full URL or unset \
             the variable to use the bundled /static/ default."
        );
    }
    Some(trimmed.to_string())
}

/// Parse `LOAD_LADDER` (e.g. `"200:20,500:22,1000:24"`) into an aggregate
/// site-load difficulty floor. Unset or empty disables the floor. A malformed
/// spec panics at boot — silently dropping a misconfigured load ladder would
/// leave a site running without the flood protection its operator configured,
/// the same fail-loud stance as `parse_info_url`.
fn parse_load_ladder() -> LoadLadder {
    match env::var("LOAD_LADDER") {
        Ok(spec) => LoadLadder::parse(&spec).unwrap_or_else(|e| {
            panic!(
                "LOAD_LADDER is invalid: {e}. Expected comma-separated threshold:difficulty \
                 pairs in leading zero bits, e.g. \"200:20,500:22,1000:24\"."
            )
        }),
        Err(_) => LoadLadder::default(),
    }
}

fn parse_truthy(v: Option<&str>) -> bool {
    matches!(
        v.map(str::trim).map(str::to_ascii_lowercase).as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], 3000)),
            static_dir: "static".to_string(),
            puzzle_algorithm: Algorithm::Argon2id(Argon2idParams::default()),
            default_difficulty: 5,
            max_difficulty: 10,
            load_ladder: LoadLadder::default(),
            challenge_ttl_secs: 300,
            cleanup_interval_secs: 60,
            max_active_challenges: 1_000_000,
            tier_checkbox_min: 20,
            tier_hard_pow_min: 40,
            tier_block_min: 85,
            ip_hard_limit: 500,
            ip_reputation_file: None,
            signal_weights_file: None,
            verify_shadow_min: 30,
            verify_block_min: 60,
            verify_max_attempts: 10,
            verify_require_behavior: false,
            tls_fingerprint_header: None,
            tls_fingerprint_file: None,
            trusted_proxies: None,
            admin_db_path: None,
            admin_token: None,
            site_db_path: None,
            cors_allowed_origins: None,
            dev_disable_admin_auth: false,
            info_about_url: None,
            info_privacy_url: None,
            info_terms_url: None,
            anonymize_log_ip: true,
            log_retention_hours: 72,
            geoip_db_path: None,
            failover_enabled: false,
            failover_state_path: None,
            failover_heartbeat_interval_secs: 15,
            failover_min_gap_secs: 60,
            failover_grace_secs: 300,
            failover_max_per_min: 600,
        }
    }
}

/// Default base difficulty (leading zero bits) when `DEFAULT_DIFFICULTY` is
/// unset. SHA-256 needs ~18 bits to cost a browser a few seconds; each
/// Argon2id hash is orders of magnitude slower, so the same wall-clock cost
/// lands near 5 bits.
fn default_difficulty_for(algorithm: Algorithm) -> u32 {
    match algorithm {
        Algorithm::Sha256 => 18,
        Algorithm::Argon2id(_) => 5,
    }
}

/// Upper difficulty clamp when `MAX_DIFFICULTY` is unset. Argon2id's ceiling
/// is far lower so a tier bump or `LOAD_LADDER` rung can't push a memory-hard
/// solve into the minutes range.
fn max_difficulty_for(algorithm: Algorithm) -> u32 {
    match algorithm {
        Algorithm::Sha256 => 28,
        Algorithm::Argon2id(_) => 10,
    }
}

/// Parse `PUZZLE_ALGORITHM` (default `argon2id`). SHA-256 stays available via
/// `PUZZLE_ALGORITHM=sha256`, but is no longer the default: it verifies fast
/// yet is trivially GPU-parallelised, so it taxes honest browsers far more
/// than attackers. Argon2id is memory-hard, which collapses that asymmetry.
/// Unknown values fall back to argon2id with a warning printed to stderr at
/// boot — the rest of the service uses tracing, but this runs before the
/// subscriber is up.
fn parse_algorithm_from_env() -> Algorithm {
    match env::var("PUZZLE_ALGORITHM").as_deref() {
        Ok("sha256") => Algorithm::Sha256,
        Ok("argon2id") | Err(_) => argon2id_from_env(),
        Ok(other) => {
            eprintln!("PUZZLE_ALGORITHM={other:?} is unknown — defaulting to argon2id");
            argon2id_from_env()
        }
    }
}

/// Build the Argon2id algorithm variant, reading `ARGON2_M_COST` /
/// `ARGON2_T_COST` / `ARGON2_P_COST` (each falling back to the tuned default).
fn argon2id_from_env() -> Algorithm {
    let defaults = Argon2idParams::default();
    Algorithm::Argon2id(Argon2idParams {
        m_cost: env::var("ARGON2_M_COST")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(defaults.m_cost),
        t_cost: env::var("ARGON2_T_COST")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(defaults.t_cost),
        p_cost: env::var("ARGON2_P_COST")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(defaults.p_cost),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each case below is a value that leaves the process running and healthy
    /// while silently providing no protection (or refusing every solve), which
    /// is why they abort the boot rather than being clamped.
    #[test]
    #[should_panic(expected = "must be at least 1")]
    fn rejects_zero_max_difficulty() {
        // MAX_DIFFICULTY clamps DEFAULT_DIFFICULTY, so a zero here disables the
        // PoW even though DEFAULT_DIFFICULTY looks correct — the subtle case.
        AppConfig {
            max_difficulty: 0,
            ..AppConfig::default()
        }
        .validated();
    }

    #[test]
    #[should_panic(expected = "must be at least 1")]
    fn rejects_zero_default_difficulty() {
        AppConfig {
            default_difficulty: 0,
            ..AppConfig::default()
        }
        .validated();
    }

    #[test]
    #[should_panic(expected = "not a valid Argon2id parameter set")]
    fn rejects_out_of_range_argon2_params() {
        AppConfig {
            puzzle_algorithm: Algorithm::Argon2id(Argon2idParams {
                m_cost: 1,
                t_cost: 2,
                p_cost: 1,
            }),
            ..AppConfig::default()
        }
        .validated();
    }

    #[test]
    #[should_panic(expected = "CHALLENGE_TTL_SECS")]
    fn rejects_overflowing_ttl() {
        AppConfig {
            challenge_ttl_secs: u64::MAX,
            ..AppConfig::default()
        }
        .validated();
    }

    #[test]
    #[should_panic(expected = "CHALLENGE_TTL_SECS")]
    fn rejects_zero_ttl() {
        AppConfig {
            challenge_ttl_secs: 0,
            ..AppConfig::default()
        }
        .validated();
    }

    #[test]
    #[should_panic(expected = "LOG_RETENTION_HOURS")]
    fn rejects_overflowing_retention() {
        AppConfig {
            log_retention_hours: u64::MAX,
            ..AppConfig::default()
        }
        .validated();
    }

    #[test]
    fn accepts_defaults_and_documented_edge_values() {
        // The shipped defaults must pass, or every deployment breaks on upgrade.
        AppConfig::default().validated();
        // 0 is the documented "disable pruning" value and must stay valid.
        AppConfig {
            log_retention_hours: 0,
            ..AppConfig::default()
        }
        .validated();
        // A difficulty of exactly 1 is the lowest that still requires work.
        AppConfig {
            default_difficulty: 1,
            max_difficulty: 1,
            ..AppConfig::default()
        }
        .validated();
        // SHA-256 deployments carry no Argon2 params to validate.
        AppConfig {
            puzzle_algorithm: Algorithm::Sha256,
            default_difficulty: 18,
            max_difficulty: 28,
            ..AppConfig::default()
        }
        .validated();
    }
}
