use std::env;
use std::net::SocketAddr;

use crate::puzzle::types::{Algorithm, Argon2idParams};
use crate::risk::LoadLadder;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub listen_addr: SocketAddr,
    /// PoW algorithm for new challenges. `sha256` (default) or `argon2id`.
    /// When set to `argon2id`, lower the difficulty knobs accordingly —
    /// each Argon2id hash is orders of magnitude slower than SHA-256, so
    /// 4–6 leading zero bits is comparable to SHA-256's default 20 bits.
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
    pub cleanup_interval_secs: u64,
    pub tier_checkbox_min: u32,
    pub tier_hard_pow_min: u32,
    pub tier_block_min: u32,
    /// Hard per-IP issuance cap: once an IP (IPv6: its /64 bucket) exceeds
    /// this many puzzle requests in the 60s rate window, further requests get
    /// the Block tier (429) regardless of score. Risk scoring alone can't
    /// block a flood with clean browser headers (rate maxes at +45, below
    /// `TIER_BLOCK_MIN`), so without this cap a single host can mint
    /// challenges at line rate. Default 500 — far above organic per-IP
    /// traffic, low enough to bound memory/log growth. `0` disables.
    pub ip_hard_limit: u32,
    /// Path to a CIDR reputation file. If unset, the IP reputation signal contributes 0.
    pub ip_reputation_file: Option<String>,
    /// Verify-time score at/above which the request is shadow-failed (success
    /// returned, log emitted). Default 30.
    pub verify_shadow_min: u32,
    /// Verify-time score at/above which the request is hard-rejected. Default 60.
    pub verify_block_min: u32,
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
}

impl AppConfig {
    pub fn from_env() -> Self {
        Self {
            listen_addr: env::var("LISTEN_ADDR")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 3000))),
            puzzle_algorithm: parse_algorithm_from_env(),
            default_difficulty: env::var("DEFAULT_DIFFICULTY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(18),
            max_difficulty: env::var("MAX_DIFFICULTY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(28),
            load_ladder: parse_load_ladder(),
            challenge_ttl_secs: env::var("CHALLENGE_TTL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300),
            cleanup_interval_secs: env::var("CLEANUP_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
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
            verify_shadow_min: env::var("VERIFY_SHADOW_MIN")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            verify_block_min: env::var("VERIFY_BLOCK_MIN")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
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
        }
    }
}

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
            puzzle_algorithm: Algorithm::Sha256,
            default_difficulty: 18,
            max_difficulty: 28,
            load_ladder: LoadLadder::default(),
            challenge_ttl_secs: 300,
            cleanup_interval_secs: 60,
            tier_checkbox_min: 20,
            tier_hard_pow_min: 40,
            tier_block_min: 85,
            ip_hard_limit: 500,
            ip_reputation_file: None,
            verify_shadow_min: 30,
            verify_block_min: 60,
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
        }
    }
}

/// Parse `PUZZLE_ALGORITHM` (default `sha256`). When `argon2id`, also reads
/// `ARGON2_M_COST`, `ARGON2_T_COST`, `ARGON2_P_COST`. Unknown values fall
/// back to SHA-256 with a warning printed to stderr at boot — the rest of
/// the service uses tracing, but this runs before the subscriber is up.
fn parse_algorithm_from_env() -> Algorithm {
    match env::var("PUZZLE_ALGORITHM").as_deref() {
        Ok("sha256") | Err(_) => Algorithm::Sha256,
        Ok("argon2id") => {
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
        Ok(other) => {
            eprintln!("PUZZLE_ALGORITHM={other:?} is unknown — defaulting to sha256");
            Algorithm::Sha256
        }
    }
}
