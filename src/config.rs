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
        }
    }
}
