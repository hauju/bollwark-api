use std::env;
use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub listen_addr: SocketAddr,
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
}

impl AppConfig {
    pub fn from_env() -> Self {
        Self {
            listen_addr: env::var("LISTEN_ADDR")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 3000))),
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
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], 3000)),
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
        }
    }
}
