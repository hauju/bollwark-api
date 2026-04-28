use std::env;
use std::net::SocketAddr;

use crate::puzzle::types::{Algorithm, Argon2idParams};

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub listen_addr: SocketAddr,
    /// PoW algorithm for new challenges. `sha256` (default) or `argon2id`.
    /// When set to `argon2id`, lower the difficulty knobs accordingly —
    /// each Argon2id hash is orders of magnitude slower than SHA-256, so
    /// 4–6 leading zero bits is comparable to SHA-256's default 20 bits.
    pub puzzle_algorithm: Algorithm,
    pub default_difficulty: u32,
    pub min_difficulty: u32,
    pub max_difficulty: u32,
    pub challenge_ttl_secs: u64,
    pub cleanup_interval_secs: u64,
    pub tier_checkbox_min: u32,
    pub tier_hard_pow_min: u32,
    pub tier_visual_min: u32,
    pub tier_block_min: u32,
    /// Path to a CIDR reputation file. If unset, the IP reputation signal contributes 0.
    pub ip_reputation_file: Option<String>,
    /// HMAC secret for the trust cookie. If unset, the cookie signal is disabled and
    /// no cookie is issued. Must be at least 16 bytes when set.
    pub cookie_signing_secret: Option<String>,
    /// Set the `Secure` attribute on issued cookies. Defaults to false (local dev / HTTP).
    pub cookie_secure: bool,
    /// Verify-time score at/above which the request is shadow-failed (success
    /// returned, log emitted). Default 30.
    pub verify_shadow_min: u32,
    /// Verify-time score at/above which the request is hard-rejected. Default 60.
    pub verify_block_min: u32,
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
    /// Bearer token required by the `/v1/admin/*` endpoints. Required when
    /// `admin_db_path` is set; the service refuses to start without it.
    pub admin_token: Option<String>,
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
                .unwrap_or(20),
            min_difficulty: env::var("MIN_DIFFICULTY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(16),
            max_difficulty: env::var("MAX_DIFFICULTY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(28),
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
            tier_visual_min: env::var("TIER_VISUAL_MIN")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(65),
            tier_block_min: env::var("TIER_BLOCK_MIN")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(85),
            ip_reputation_file: env::var("IP_REPUTATION_FILE").ok(),
            cookie_signing_secret: env::var("COOKIE_SIGNING_SECRET").ok(),
            cookie_secure: env::var("COOKIE_SECURE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
            verify_shadow_min: env::var("VERIFY_SHADOW_MIN")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            verify_block_min: env::var("VERIFY_BLOCK_MIN")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            tls_fingerprint_header: env::var("TLS_FINGERPRINT_HEADER").ok(),
            tls_fingerprint_file: env::var("TLS_FINGERPRINT_FILE").ok(),
            trusted_proxies: env::var("TRUSTED_PROXIES").ok(),
            admin_db_path: env::var("ADMIN_DB_PATH").ok(),
            admin_token: env::var("ADMIN_TOKEN").ok(),
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], 3000)),
            puzzle_algorithm: Algorithm::Sha256,
            default_difficulty: 20,
            min_difficulty: 16,
            max_difficulty: 28,
            challenge_ttl_secs: 300,
            cleanup_interval_secs: 60,
            tier_checkbox_min: 20,
            tier_hard_pow_min: 40,
            tier_visual_min: 65,
            tier_block_min: 85,
            ip_reputation_file: None,
            cookie_signing_secret: None,
            cookie_secure: false,
            verify_shadow_min: 30,
            verify_block_min: 60,
            tls_fingerprint_header: None,
            tls_fingerprint_file: None,
            trusted_proxies: None,
            admin_db_path: None,
            admin_token: None,
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
