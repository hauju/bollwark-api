use std::sync::Arc;

use crate::api::types::InfoUrls;
use crate::config::AppConfig;
use crate::dashboard::DecisionLog;
use crate::puzzle::challenge::PuzzleEngine;
use crate::puzzle::difficulty::DifficultyCalculator;
use crate::risk::{
    CookieSigner, RiskScorer, TierThresholds, TrustedProxies, VerifyScorer, VerifyThresholds,
};
use crate::storage::memory::InMemoryStore;

pub type SharedState = Arc<AppState>;

pub struct AppState {
    pub store: Arc<InMemoryStore>,
    pub engine: PuzzleEngine,
    pub difficulty: DifficultyCalculator,
    pub risk: RiskScorer,
    pub verify_scorer: VerifyScorer,
    pub cookie_signer: Option<CookieSigner>,
    /// Header name to read for TLS fingerprint (e.g. `x-ja4`). `None` disables
    /// the signal entirely.
    pub tls_fingerprint_header: Option<String>,
    /// Trusted proxies whose TLS fingerprint header we honor (and whose
    /// `X-Forwarded-For` we walk to resolve the client IP). Empty if no
    /// proxies are configured — direct connections only.
    pub trusted_proxies: Arc<TrustedProxies>,
    /// Validation dashboard log. When `Some`, every puzzle/verify decision is
    /// also persisted to SQLite for the admin dashboard.
    pub decision_log: Option<DecisionLog>,
    /// Bearer token required to call mutating admin endpoints, including
    /// `POST /v1/sites`. When `None`, those endpoints are disabled (404).
    pub admin_token: Option<Arc<String>>,
    /// Operator-overridden info URLs surfaced in the puzzle response and
    /// the 429 block body. `None` when no `INFO_*_URL` env var is set; the
    /// widget then uses bundled `/static/*.html` defaults for every field.
    pub info_urls: Option<InfoUrls>,
    pub config: AppConfig,
}

/// Build the `info_urls` payload from config. Returns `None` when no
/// override is set so we don't serialize an empty object on every puzzle
/// response.
pub fn info_urls_from_config(config: &AppConfig) -> Option<InfoUrls> {
    let urls = InfoUrls {
        about: config.info_about_url.clone(),
        privacy: config.info_privacy_url.clone(),
        terms: config.info_terms_url.clone(),
    };
    if urls.is_empty() { None } else { Some(urls) }
}

pub fn tier_thresholds_from_config(config: &AppConfig) -> TierThresholds {
    TierThresholds {
        checkbox: config.tier_checkbox_min,
        hard_pow: config.tier_hard_pow_min,
        visual: config.tier_visual_min,
        block: config.tier_block_min,
    }
}

pub fn verify_thresholds_from_config(config: &AppConfig) -> VerifyThresholds {
    VerifyThresholds {
        shadow_min: config.verify_shadow_min,
        block_min: config.verify_block_min,
    }
}
