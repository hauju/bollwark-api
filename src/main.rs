use std::sync::Arc;

use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use rust_captcha::api;
use rust_captcha::api::state::{
    AppState, tier_thresholds_from_config, verify_thresholds_from_config,
};
use rust_captcha::config::AppConfig;
use rust_captcha::dashboard::{DecisionLog, Sessions, routes::AdminState};
use rust_captcha::puzzle::challenge::PuzzleEngine;
use rust_captcha::puzzle::difficulty::DifficultyCalculator;
use rust_captcha::puzzle::types::PuzzleConfig;
use rust_captcha::risk::{
    CidrListReputation, CookieSigner, FingerprintBlocklist, RiskScorer, TrustedProxies,
    VerifyScorer,
};
use rust_captcha::storage::Store;
use rust_captcha::storage::memory::InMemoryStore;

#[tokio::main]
async fn main() {
    // Load .env if present so operators can keep ADMIN_TOKEN, secrets, etc.
    // out of their shell history. Existing env vars take precedence.
    let dotenv_loaded = dotenvy::dotenv().ok();

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let json_logs = std::env::var("LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    if json_logs {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .with_span_list(false)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .init();
    }

    if let Some(path) = dotenv_loaded {
        tracing::info!("Loaded environment from {}", path.display());
    }

    let config = AppConfig::from_env();

    let puzzle_config = PuzzleConfig {
        algorithm: config.puzzle_algorithm,
        default_difficulty: config.default_difficulty,
        min_difficulty: config.min_difficulty,
        max_difficulty: config.max_difficulty,
        ttl_secs: config.challenge_ttl_secs,
    };
    tracing::info!(algorithm = ?config.puzzle_algorithm, "Puzzle engine initialised");

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

    // TLS fingerprint signal: optional, requires both a header name and a
    // trusted-proxies CIDR list. The blocklist is loaded if a path is given.
    let tls_blocklist = match &config.tls_fingerprint_file {
        Some(path) => match FingerprintBlocklist::from_file(path) {
            Ok(bl) => {
                tracing::info!(
                    "TLS fingerprint blocklist loaded: {} entries from {path}",
                    bl.len()
                );
                Arc::new(bl)
            }
            Err(e) => {
                tracing::warn!("TLS fingerprint blocklist: {e} — falling back to empty");
                Arc::new(FingerprintBlocklist::empty())
            }
        },
        None => Arc::new(FingerprintBlocklist::empty()),
    };

    let trusted_proxies = match &config.trusted_proxies {
        Some(spec) => match TrustedProxies::parse(spec) {
            Ok(tp) => Arc::new(tp),
            Err(e) => {
                tracing::warn!("TRUSTED_PROXIES parse error: {e} — falling back to empty");
                Arc::new(TrustedProxies::empty())
            }
        },
        None => Arc::new(TrustedProxies::empty()),
    };

    if config.tls_fingerprint_header.is_some() {
        if trusted_proxies.is_empty() {
            tracing::warn!(
                "TLS_FINGERPRINT_HEADER is set but TRUSTED_PROXIES is empty — signal will never fire"
            );
        } else {
            tracing::info!(
                "TLS fingerprint signal enabled (header={:?}, trusted proxies={})",
                config.tls_fingerprint_header.as_deref().unwrap(),
                trusted_proxies.len()
            );
        }
    }

    // Validation dashboard: open the SQLite log and (if a token is set) build
    // the admin sub-router. We refuse to start with a path but no token —
    // that would expose the admin endpoints anonymously.
    let admin_state = match (&config.admin_db_path, &config.admin_token) {
        (Some(path), Some(token)) if !token.is_empty() => {
            let log = DecisionLog::open(path)
                .unwrap_or_else(|e| panic!("failed to open ADMIN_DB_PATH={path}: {e}"));
            tracing::info!("Validation dashboard enabled (db={path})");
            let sessions = Sessions::new(log.db_path().to_string());
            Some((
                log.clone(),
                AdminState {
                    sessions,
                    log,
                    token: Arc::new(token.clone()),
                },
            ))
        }
        (Some(_), _) => {
            panic!("ADMIN_DB_PATH is set but ADMIN_TOKEN is missing — refusing to start");
        }
        _ => None,
    };

    let (decision_log, admin_routes) = match admin_state {
        Some((log, admin)) => (Some(log), Some(admin)),
        None => (None, None),
    };

    let state = Arc::new(AppState {
        store,
        engine: PuzzleEngine::new(puzzle_config),
        difficulty: DifficultyCalculator::new(&config),
        risk: RiskScorer::new(
            tier_thresholds_from_config(&config),
            reputation,
            tls_blocklist,
        ),
        verify_scorer: VerifyScorer::new(verify_thresholds_from_config(&config)),
        cookie_signer,
        tls_fingerprint_header: config.tls_fingerprint_header.clone(),
        trusted_proxies,
        decision_log,
        config: config.clone(),
    });

    let app = api::router(state, admin_routes);

    let listener = TcpListener::bind(config.listen_addr).await.unwrap();
    tracing::info!("Listening on {}", config.listen_addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .unwrap();
}
