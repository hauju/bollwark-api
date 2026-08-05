use std::sync::Arc;

use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use bollwark::api;
use bollwark::api::state::{
    AppState, info_urls_from_config, tier_thresholds_from_config, verify_permits,
    verify_thresholds_from_config,
};
use bollwark::config::AppConfig;
use bollwark::dashboard::{DecisionLog, GeoIp, Sessions, routes::AdminState};
use bollwark::failover::FailoverGuard;
use bollwark::puzzle::challenge::PuzzleEngine;
use bollwark::puzzle::types::{Algorithm, PuzzleConfig};
use bollwark::risk::{
    CidrListReputation, EscalationTier, FingerprintBlocklist, ReputationStore, RiskScorer,
    TrustedProxies, VerifyScorer, difficulty_for,
};
use bollwark::storage::Store;
use bollwark::storage::memory::InMemoryStore;

#[tokio::main]
async fn main() {
    // Load .env if present so operators can keep ADMIN_TOKEN, secrets, etc.
    // out of their shell history. Existing env vars take precedence.
    let dotenv_loaded = dotenvy::dotenv().ok();

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let json_logs = std::env::var("LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    // Log through a bounded, lossy background writer rather than straight to
    // stderr. `std::io::Stderr` is a process-global mutex around a blocking
    // `write_all`, and every /v1/puzzle emits a decision event — so at load the
    // hot path funnels thousands of syscalls per second through one lock, and a
    // stalled log consumer (slow disk, log rotation, a wedged sidecar) blocks
    // every tokio worker that touches the handler. This gives logging the same
    // posture the decision log already has: drop under pressure rather than
    // apply backpressure to request handling.
    //
    // `_log_guard` must outlive the server — dropping it flushes and shuts down
    // the writer thread, so binding it here keeps logs flowing until main exits.
    let (log_writer, _log_guard) = tracing_appender::non_blocking(std::io::stderr());
    if json_logs {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(log_writer)
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .with_span_list(false)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(log_writer)
            .init();
    }

    if let Some(path) = dotenv_loaded {
        tracing::info!("Loaded environment from {}", path.display());
    }

    let mut config = AppConfig::from_env();

    if config.dev_disable_admin_auth {
        if cfg!(debug_assertions) {
            tracing::warn!(
                "⚠️  DEV_DISABLE_ADMIN_AUTH=1 — POST /v1/sites is OPEN to anonymous callers. \
                 This is a dev/test-only flag; never enable it in production."
            );
        } else {
            tracing::error!(
                "DEV_DISABLE_ADMIN_AUTH=1 ignored: this is a release build. \
                 The flag only takes effect in debug builds."
            );
            config.dev_disable_admin_auth = false;
        }
    }

    // Argon2id is orders of magnitude slower per hash than SHA-256, so the
    // SHA-256-tuned default difficulty makes puzzles effectively unsolvable in
    // the browser (a 2^18 target at ~10ms/hash is tens of minutes). This is a
    // one-env-var footgun — warn loudly rather than silently shipping a widget
    // that never completes. Difficulty is a continuum, so this warns rather
    // than refusing to start.
    // `max_difficulty` is checked as well as `default_difficulty`, because it is
    // the one an escalated visitor actually gets: risk scoring raises the tier
    // and `difficulty_for(HardPow, …)` returns the max. A config whose default
    // is survivable but whose max is not looks healthy at boot and only breaks
    // for the subset of visitors that score badly — the hardest kind of failure
    // to attribute. That is not hypothetical: the e2e harness ran for a month
    // with argon2id (the new default) at a SHA-256-scale max of 16, and only
    // the tests that escalated to HardPow hung.
    if let Algorithm::Argon2id(_) = config.puzzle_algorithm {
        const ARGON2_SANE_MAX_DIFFICULTY: u32 = 12;
        for (name, value) in [
            ("DEFAULT_DIFFICULTY", config.default_difficulty),
            ("MAX_DIFFICULTY", config.max_difficulty),
        ] {
            if value > ARGON2_SANE_MAX_DIFFICULTY {
                tracing::warn!(
                    setting = name,
                    difficulty = value,
                    "PUZZLE_ALGORITHM=argon2id with {name}={value} is almost certainly far too \
                     high — each Argon2id hash is orders of magnitude slower than SHA-256, so \
                     solves can take minutes in the browser and the widget may never complete. \
                     Drop it to ~4–6 (default) / ~10 (max) for argon2id."
                );
            }
        }
    }

    let puzzle_config = PuzzleConfig {
        algorithm: config.puzzle_algorithm,
        default_difficulty: config.default_difficulty,
        ttl_secs: config.challenge_ttl_secs,
    };
    // Log the difficulty each tier actually resolves to, not just the configured
    // base. The final value is `default + tier_bump` clamped by MAX_DIFFICULTY,
    // so a too-low MAX silently flattens every tier — printing the effective
    // ladder makes that visible in the first few lines of output instead of
    // only showing up as an unexplained drop in solve times.
    let effective = |tier| {
        difficulty_for(tier, config.default_difficulty, config.max_difficulty)
            .map(|d| d.to_string())
            .unwrap_or_else(|| "block (429)".to_string())
    };
    tracing::info!(
        algorithm = ?config.puzzle_algorithm,
        invisible_pass = %effective(EscalationTier::InvisiblePass),
        checkbox = %effective(EscalationTier::Checkbox),
        hard_pow = %effective(EscalationTier::HardPow),
        max_difficulty = config.max_difficulty,
        "Puzzle engine initialised (effective difficulty per tier)"
    );

    // Site registrations: persist to SQLite when SITE_DB_PATH is set so
    // restarts don't invalidate every integrator's stored secret_key.
    let store = match &config.site_db_path {
        Some(path) => match InMemoryStore::with_site_persistence(path) {
            Ok(s) => {
                tracing::info!(
                    sites_loaded = s.site_count(),
                    "Persistent site store enabled (path={path})"
                );
                Arc::new(s)
            }
            Err(e) => {
                panic!("failed to open SITE_DB_PATH={path}: {e}");
            }
        },
        None => {
            tracing::warn!(
                "SITE_DB_PATH is unset — sites are in-memory only and will be lost on restart"
            );
            Arc::new(InMemoryStore::new())
        }
    };

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

    // IP reputation: load CIDR list if a path is configured. The store is
    // hot-swappable; when a path is set we also spawn an fs-watcher that
    // reloads the file on change (debounced to coalesce editor save bursts).
    let reputation = Arc::new(ReputationStore::empty());
    if let Some(path) = config.ip_reputation_file.clone() {
        match CidrListReputation::from_file(&path) {
            Ok(rep) => {
                tracing::info!("IP reputation loaded: {} entries from {path}", rep.len());
                reputation.replace(rep);
            }
            Err(e) => {
                tracing::warn!("IP reputation: {e} — falling back to empty list");
            }
        }
        spawn_reputation_watcher(path, Arc::clone(&reputation));
    }

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
            // Geo enrichment is tied to the decision log existing — load it
            // here so we don't open the GeoIP db when there's nothing to stamp.
            let geoip = open_geoip(config.geoip_db_path.as_deref());
            let log = DecisionLog::open(path, geoip)
                .unwrap_or_else(|e| panic!("failed to open ADMIN_DB_PATH={path}: {e}"));
            tracing::info!("Validation dashboard enabled (db={path})");
            let sessions = Sessions::new(log.db_path().to_string());
            Some((
                log.clone(),
                AdminState {
                    sessions,
                    log,
                    token: Arc::new(token.clone()),
                    store: Arc::clone(&store),
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

    // Decision-log retention sweeper. Only runs when the dashboard log exists
    // and a retention window is configured (`LOG_RETENTION_HOURS`, default 72,
    // 0 disables). Prunes rows older than the window so the durable log obeys
    // GDPR storage-limitation instead of growing forever. Sweep cadence is
    // 1/24 of the window — rows never outlive it by more than ~4% — clamped to
    // [60s, 1h]. The interval fires immediately, so stale rows from a prior
    // run are cleaned at boot.
    if let Some(log) = &decision_log {
        let retention_hours = config.log_retention_hours;
        if retention_hours == 0 {
            tracing::info!(
                "LOG_RETENTION_HOURS=0 — decision-log pruning disabled (rows kept forever)"
            );
        } else {
            let sweep_secs = (retention_hours * 3600 / 24).clamp(60, 3600);
            tracing::info!(
                "Decision-log retention: pruning rows older than {retention_hours}h every {sweep_secs}s"
            );
            let prune_log = log.clone();
            tokio::spawn(async move {
                let mut interval =
                    tokio::time::interval(std::time::Duration::from_secs(sweep_secs));
                loop {
                    interval.tick().await;
                    match prune_log.prune(retention_hours).await {
                        Ok(0) => {}
                        Ok(n) => tracing::info!("decision-log retention: pruned {n} rows"),
                        Err(e) => tracing::error!("decision-log retention sweep failed: {e}"),
                    }
                }
            });
        }
    }

    // ADMIN_TOKEN gates `POST /v1/sites` whether or not the dashboard is
    // enabled. Without it, `/v1/sites` returns 404 — no anonymous
    // provisioning. Empty strings are rejected so a misconfigured
    // `ADMIN_TOKEN=` doesn't accidentally accept anyone with `Bearer `.
    let admin_token = config
        .admin_token
        .as_ref()
        .filter(|t| !t.is_empty())
        .map(|t| Arc::new(t.clone()));
    if admin_token.is_none() {
        tracing::warn!(
            "ADMIN_TOKEN is unset — POST /v1/sites is disabled (returns 404). Set ADMIN_TOKEN to enable provisioning."
        );
    }

    // Info-page URLs: per-field fallback to bundled /static/*.html. Warn
    // when the operator partially overrides — almost always a footgun
    // (custom privacy notice, but bundled boilerplate terms shipped from
    // the OSS still served). Doesn't block boot, since "I only want to
    // override one" is a legitimate-if-rare choice.
    let info_urls = info_urls_from_config(&config);
    if let Some(urls) = &info_urls {
        let set = [
            ("INFO_ABOUT_URL", urls.about.is_some()),
            ("INFO_PRIVACY_URL", urls.privacy.is_some()),
            ("INFO_TERMS_URL", urls.terms.is_some()),
        ];
        let count = set.iter().filter(|(_, v)| *v).count();
        if count > 0 && count < 3 {
            let missing: Vec<&str> = set
                .iter()
                .filter(|(_, v)| !v)
                .map(|(name, _)| *name)
                .collect();
            tracing::warn!(
                "INFO_*_URL partially set — missing {missing:?}. Widget will fall back to the \
                 bundled /static/ default for those, which may not reflect your operator's \
                 legal text. Set the missing variables to suppress this warning."
            );
        }
    }

    tracing::info!(
        "Cookie-free operation — live decisions use rate + header anomaly + honeypot + \
         time-on-page + behavior + PoW (plus IP reputation / TLS fingerprint when configured). \
         No client-side storage; signals run under legitimate interest with data minimization."
    );

    // A handle kept out of AppState so we can flush the writer after the
    // server stops (AppState's copy is owned by the router by then).
    let shutdown_log = decision_log.clone();

    // Concurrency ceiling for memory-hard verification. Surfaced at boot because
    // it, together with ARGON2_M_COST, is what actually bounds peak RSS under a
    // verify flood — an operator sizing a container needs both numbers.
    let verify_permits = verify_permits();
    if let Algorithm::Argon2id(p) = config.puzzle_algorithm {
        tracing::info!(
            permits = verify_permits,
            m_cost_kib = p.m_cost,
            peak_mib = (verify_permits as u64 * p.m_cost as u64) / 1024,
            "Argon2id verification concurrency bounded"
        );
    }

    // Load failover state and, if the heartbeat shows the process was gone
    // longer than FAILOVER_MIN_GAP_SECS, attest an outage window for the gap.
    // This must happen before the listener binds: the window's grace tail is
    // what lets visitors who loaded a form during the outage still submit it,
    // and they start arriving the moment we're reachable again.
    let failover = Arc::new(FailoverGuard::load(config.failover_config()));
    if failover.enabled() {
        tracing::info!(
            heartbeat_secs = failover.heartbeat_interval_secs(),
            min_gap_secs = config.failover_min_gap_secs,
            grace_secs = config.failover_grace_secs,
            max_per_min = config.failover_max_per_min,
            active_windows = failover.active_windows().len(),
            "Client failover enabled — verify will honor widget failover claims \
             during attested outages"
        );

        // Heartbeat: the gap between the last of these and the next boot is
        // the whole basis for automatic outage attestation, so it runs for the
        // life of the process and is never gated on request traffic.
        let hb = failover.clone();
        let hb_secs = failover.heartbeat_interval_secs();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(hb_secs));
            loop {
                interval.tick().await;
                hb.heartbeat();
            }
        });
    }

    let state = Arc::new(AppState {
        store,
        engine: PuzzleEngine::new(puzzle_config),
        risk: RiskScorer::new(
            tier_thresholds_from_config(&config),
            reputation,
            tls_blocklist,
        ),
        verify_scorer: VerifyScorer::new(
            verify_thresholds_from_config(&config),
            config.verify_require_behavior,
        ),
        tls_fingerprint_header: config.tls_fingerprint_header.clone(),
        trusted_proxies,
        decision_log,
        admin_token,
        info_urls,
        verify_permits: Arc::new(tokio::sync::Semaphore::new(verify_permits)),
        failover,
        config: config.clone(),
    });

    let app = api::router(state, admin_routes);

    let listener = TcpListener::bind(config.listen_addr).await.unwrap();
    tracing::info!("Listening on {}", config.listen_addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .unwrap();

    // Graceful shutdown drained in-flight HTTP requests, so their decision-log
    // records are already queued. Flush the writer before exiting so they land
    // on disk instead of dying with the process.
    if let Some(log) = &shutdown_log
        && log.flush().await.is_err()
    {
        tracing::warn!("decision-log flush on shutdown failed (writer already gone)");
    }

    tracing::info!("Shutdown complete");
}

/// Load the optional GeoLite2/GeoIP2 *Country* database for decision-log geo
/// enrichment. `None` (no `GEOIP_DB_PATH`, or an unreadable file) leaves the
/// `country` column NULL — geo is best-effort and never blocks boot, the same
/// stance as the IP reputation / TLS blocklist file loaders.
fn open_geoip(path: Option<&str>) -> Option<GeoIp> {
    let path = path?;
    match GeoIp::open(path) {
        Ok(g) => {
            tracing::info!("Geo enrichment enabled (GeoIP db={path})");
            Some(g)
        }
        Err(e) => {
            tracing::warn!("GEOIP_DB_PATH={path}: {e} — geo enrichment disabled");
            None
        }
    }
}

/// Wait for SIGINT (Ctrl-C) or SIGTERM (orchestrator stop). Either signal
/// Watch the IP reputation file for changes and hot-swap the in-memory list
/// when it's rewritten. The debouncer coalesces atomic-rename save bursts
/// (vim/sed) into a single reload. Runs on a dedicated OS thread because
/// the debouncer hands us a synchronous `mpsc::Receiver`. Errors during
/// reload (e.g. transient ENOENT mid-rename) are logged and the previous
/// list is kept — the request path can never observe an empty/partial list.
fn spawn_reputation_watcher(path: String, store: Arc<ReputationStore>) {
    use notify_debouncer_full::new_debouncer;
    use notify_debouncer_full::notify::RecursiveMode;
    use std::path::PathBuf;
    use std::time::Duration;

    let target = PathBuf::from(&path);
    // Watch the parent directory: many editors save by writing a temp file
    // and renaming it over the target, which invalidates a direct file watch
    // on some platforms. Filtering by filename inside the handler is robust
    // to that pattern.
    let watch_dir = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let target_name = target.file_name().map(|n| n.to_owned());

    std::thread::Builder::new()
        .name("ip-reputation-watcher".into())
        .spawn(move || {
            let (tx, rx) = std::sync::mpsc::channel();
            let mut debouncer = match new_debouncer(Duration::from_millis(500), None, tx) {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!("IP reputation watcher: failed to create debouncer: {e}");
                    return;
                }
            };
            if let Err(e) = debouncer.watch(&watch_dir, RecursiveMode::NonRecursive) {
                tracing::warn!(
                    "IP reputation watcher: failed to watch {}: {e}",
                    watch_dir.display()
                );
                return;
            }
            tracing::info!(
                "IP reputation watcher: watching {} for changes to {}",
                watch_dir.display(),
                target.display()
            );

            for result in rx {
                let events = match result {
                    Ok(events) => events,
                    Err(errors) => {
                        for e in errors {
                            tracing::warn!("IP reputation watcher: {e}");
                        }
                        continue;
                    }
                };
                let touched = events.iter().any(|e| {
                    // Only react to content changes (create / write / rename).
                    // Our own reload reads the file, which on Linux emits
                    // inotify Access events for the same filename — reacting to
                    // those would spin a read→event→read feedback loop.
                    is_content_change(&e.event.kind)
                        && e.event
                            .paths
                            .iter()
                            .any(|p| match (&target_name, p.file_name()) {
                                (Some(want), Some(got)) => want == got,
                                _ => false,
                            })
                });
                if !touched {
                    continue;
                }
                match CidrListReputation::from_file(&target) {
                    Ok(rep) => {
                        tracing::info!(
                            "IP reputation reloaded: {} entries from {}",
                            rep.len(),
                            target.display()
                        );
                        store.replace(rep);
                    }
                    Err(e) => {
                        tracing::warn!("IP reputation reload failed: {e} — keeping previous list");
                    }
                }
            }
        })
        .expect("spawn ip-reputation-watcher thread");
}

/// Whether a filesystem event actually changes file content. Excludes
/// `Access` (reads — which our own reload triggers) and `Modify(Metadata)`
/// (atime/permission changes), both of which would otherwise spin a
/// read→event→read loop on Linux/inotify.
fn is_content_change(kind: &notify_debouncer_full::notify::EventKind) -> bool {
    use notify_debouncer_full::notify::EventKind;
    use notify_debouncer_full::notify::event::ModifyKind;
    matches!(
        kind,
        EventKind::Create(_)
            | EventKind::Remove(_)
            | EventKind::Modify(ModifyKind::Data(_))
            | EventKind::Modify(ModifyKind::Name(_))
            | EventKind::Modify(ModifyKind::Any)
    )
}

/// completes the future; whichever fires first is the signal we shut down on.
/// SIGTERM is the one Kubernetes / Docker / systemd send on stop, so it must
/// be handled — without it, in-flight requests are killed mid-flight and the
/// process is SIGKILLed after the grace period.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install ctrl_c handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => tracing::info!("Received SIGINT (Ctrl-C), shutting down"),
        () = terminate => tracing::info!("Received SIGTERM, shutting down"),
    }
}
