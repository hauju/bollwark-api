use std::sync::Arc;

use crate::api::types::InfoUrls;
use crate::config::AppConfig;
use crate::dashboard::DecisionLog;
use crate::failover::FailoverGuard;
use crate::puzzle::challenge::PuzzleEngine;
use crate::risk::{RiskScorer, TierThresholds, TrustedProxies, VerifyScorer, VerifyThresholds};
use crate::storage::memory::InMemoryStore;

pub type SharedState = Arc<AppState>;

pub struct AppState {
    pub store: Arc<InMemoryStore>,
    pub engine: PuzzleEngine,
    pub risk: RiskScorer,
    pub verify_scorer: VerifyScorer,
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
    /// Bounds how many Argon2id verifications run at once. Each one allocates
    /// `ARGON2_M_COST` KiB (8 MiB by default) for the duration of the hash, and
    /// tokio grows its blocking pool to 512 threads on demand — so without a
    /// bound, ~500 concurrent `/v1/verify` calls peak around 4 GiB and OOM a
    /// small VPS. Permits cap that at `parallelism * 8 MiB`. Requests queue for
    /// a permit rather than being refused; the global request timeout is what
    /// bounds the queue, so overload degrades into timeouts instead of an OOM.
    pub verify_permits: Arc<tokio::sync::Semaphore>,
    /// Outage attestation + the accept/refuse decision for client failover
    /// claims. Always present; a guard built from a default (disabled) config
    /// refuses every claim, so the verify path needs no `Option` handling.
    pub failover: Arc<FailoverGuard>,
    pub config: AppConfig,
}

/// Concurrency limit for memory-hard verification, as a multiple of available
/// parallelism. Argon2id is CPU- *and* memory-bound, so there's no throughput
/// gained past a small multiple of the core count — the extra concurrency buys
/// only resident memory.
pub const VERIFY_PERMITS_PER_CORE: usize = 2;

/// Permit count for [`AppState::verify_permits`], derived from the host's
/// parallelism. Falls back to a single core's worth when the platform can't
/// report it, which errs toward the safe side.
pub fn verify_permits() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        * VERIFY_PERMITS_PER_CORE
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
        block: config.tier_block_min,
    }
}

pub fn verify_thresholds_from_config(config: &AppConfig) -> VerifyThresholds {
    VerifyThresholds {
        shadow_min: config.verify_shadow_min,
        block_min: config.verify_block_min,
    }
}
