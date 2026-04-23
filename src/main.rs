use std::sync::Arc;

use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use rust_captcha::api;
use rust_captcha::api::state::{AppState, tier_thresholds_from_config};
use rust_captcha::config::AppConfig;
use rust_captcha::puzzle::challenge::PuzzleEngine;
use rust_captcha::puzzle::difficulty::DifficultyCalculator;
use rust_captcha::puzzle::types::PuzzleConfig;
use rust_captcha::risk::{CidrListReputation, CookieSigner, RiskScorer};
use rust_captcha::storage::Store;
use rust_captcha::storage::memory::InMemoryStore;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let config = AppConfig::from_env();

    let puzzle_config = PuzzleConfig {
        default_difficulty: config.default_difficulty,
        min_difficulty: config.min_difficulty,
        max_difficulty: config.max_difficulty,
        ttl_secs: config.challenge_ttl_secs,
    };

    let store = Arc::new(InMemoryStore::new());

    // Spawn cleanup task
    let cleanup_store = Arc::clone(&store);
    let cleanup_interval = config.cleanup_interval_secs;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(cleanup_interval));
        loop {
            interval.tick().await;
            if let Err(e) = cleanup_store.cleanup_expired().await {
                tracing::error!("Cleanup error: {e}");
            }
        }
    });

    // IP reputation: load CIDR list if a path is configured.
    let reputation = match &config.ip_reputation_file {
        Some(path) => match CidrListReputation::from_file(path) {
            Ok(rep) => {
                tracing::info!("IP reputation loaded: {} entries from {path}", rep.len());
                Arc::new(rep)
            }
            Err(e) => {
                tracing::warn!("IP reputation: {e} — falling back to empty list");
                Arc::new(CidrListReputation::empty())
            }
        },
        None => Arc::new(CidrListReputation::empty()),
    };

    // Cookie signing: only enabled when a secret is configured.
    let cookie_signer = match &config.cookie_signing_secret {
        Some(secret) if secret.len() >= 16 => {
            tracing::info!("Trust cookie signing enabled");
            Some(CookieSigner::new(secret.clone().into_bytes()))
        }
        Some(_) => {
            tracing::warn!("COOKIE_SIGNING_SECRET set but shorter than 16 bytes — ignored");
            None
        }
        None => None,
    };

    let state = Arc::new(AppState {
        store,
        engine: PuzzleEngine::new(puzzle_config),
        difficulty: DifficultyCalculator::new(&config),
        risk: RiskScorer::new(tier_thresholds_from_config(&config), reputation),
        cookie_signer,
        config: config.clone(),
    });

    let app = api::router(state);

    let listener = TcpListener::bind(config.listen_addr).await.unwrap();
    tracing::info!("Listening on {}", config.listen_addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .unwrap();
}
