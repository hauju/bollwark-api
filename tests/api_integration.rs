use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use bollwark::api;
use bollwark::api::state::AppState;
use bollwark::api::types::{CreateSiteResponse, PuzzleResponse, RiskBand, VerifyResponse};
use bollwark::config::AppConfig;
use bollwark::dashboard::{DecisionLog, Sessions, routes::AdminState};
use bollwark::puzzle::challenge::{
    PuzzleEngine, compute_argon2id, compute_sha256, has_leading_zero_bits,
    solve_argon2id_challenge, solve_challenge,
};
use bollwark::puzzle::types::{Algorithm, Argon2idParams, PuzzleConfig};
use bollwark::risk::behavior::BEHAVIOR_DUPLICATE_MIN;
use bollwark::risk::{
    CidrListReputation, EscalationTier, FingerprintBlocklist, ReputationStore, RiskScorer,
    TrustedProxies, VerifyScorer,
};
use bollwark::storage::Store;
use bollwark::storage::memory::InMemoryStore;

fn test_app() -> axum::Router {
    test_app_with(|_| {})
}

fn test_app_with(customize: impl FnOnce(&mut TestAppBuilder)) -> axum::Router {
    let mut builder = TestAppBuilder::default();
    customize(&mut builder);
    builder.build()
}

/// Like `test_app_with`, but also returns the underlying store so a test can
/// reach in and backdate a challenge (see `backdate_challenge`) to simulate a
/// realistic dwell time — the verify handler derives time-on-page from the
/// challenge's `created_at`, which is otherwise milliseconds in-test.
fn test_app_with_store(
    customize: impl FnOnce(&mut TestAppBuilder),
) -> (axum::Router, Arc<InMemoryStore>) {
    let mut builder = TestAppBuilder::default();
    customize(&mut builder);
    builder.build_with_store()
}

/// Move a stored challenge back by `secs` so the verify-time time-on-page
/// signal sees a realistic elapsed time instead of the ~0ms gap between
/// issuing and verifying in a test.
///
/// Moves `dwell_since` as well as `created_at`: the handler derives dwell from
/// the former (it survives pre-expiry refreshes), so backdating only
/// `created_at` would leave the signal reading ~0ms and quietly defeat every
/// caller's intent.
async fn backdate_challenge(store: &InMemoryStore, id: uuid::Uuid, secs: i64) {
    use bollwark::storage::Store;
    let mut challenge = store.get_challenge(&id).await.unwrap().unwrap();
    let shift = chrono::Duration::seconds(secs);
    challenge.created_at -= shift;
    challenge.dwell_since -= shift;
    store.store_challenge(&challenge).await.unwrap();
}

#[derive(Default)]
struct TestAppBuilder {
    reputation_cidrs: Option<String>,
    tls_blocklist: Option<String>,
    tls_header: Option<&'static str>,
    trusted_proxies: Option<&'static str>,
    algorithm: Option<Algorithm>,
    /// `LOAD_LADDER` spec for the aggregate site-load difficulty floor.
    load_ladder: Option<&'static str>,
    /// `IP_HARD_LIMIT` override (hard per-IP issuance cap; 0 disables).
    ip_hard_limit: Option<u32>,
    /// `VERIFY_MAX_ATTEMPTS` override (failed PoW attempts per challenge; 0 disables).
    verify_max_attempts: Option<u32>,
    /// `MAX_ACTIVE_CHALLENGES` override (global challenge-map ceiling; 0 disables).
    max_active_challenges: Option<usize>,
    /// Mount the `/v1/admin/*` router backed by a temp-file decision log.
    enable_admin: bool,
    /// `VERIFY_REQUIRE_BEHAVIOR`: score an absent behavior blob as flatline.
    verify_require_behavior: bool,
    /// Override the admin token. Default is the constant `TEST_ADMIN_TOKEN`,
    /// which `create_test_site` sends as a bearer to satisfy the gate.
    /// Set to `Some(None)` to disable the token entirely (so `/v1/sites`
    /// returns 404).
    admin_token: Option<Option<&'static str>>,
    /// Enable client failover (`FAILOVER_ENABLED` + `FAILOVER_STATE_PATH`),
    /// backed by a temp state file unique to this app instance.
    enable_failover: bool,
    /// Override the Argon2id verify-concurrency permit count. Default is the
    /// production `verify_permits()` (cores * 2); tests that assert on permit
    /// accounting set it to 1 so the numbers are unambiguous.
    verify_permits: Option<usize>,
}

const TEST_ADMIN_TOKEN: &str = "test-admin-token-32bytes-of-entropy";

impl TestAppBuilder {
    fn build(self) -> axum::Router {
        self.build_with_store().0
    }

    fn build_with_store(self) -> (axum::Router, Arc<InMemoryStore>) {
        let (router, store, _state) = self.build_with_state();
        (router, store)
    }

    /// Also hands back the `AppState`, so a test can observe internals the HTTP
    /// surface deliberately doesn't expose (currently the verify semaphore).
    fn build_with_state(self) -> (axum::Router, Arc<InMemoryStore>, Arc<AppState>) {
        let algorithm = self.algorithm.unwrap_or(Algorithm::Sha256);
        // Argon2id needs a much lower default difficulty than SHA-256 — even
        // 4 leading zero bits at minimum-cost params already takes a few
        // hundred ms in the test solver, which is fine but anything higher
        // makes tests slow.
        let default_difficulty = match algorithm {
            Algorithm::Sha256 => 8,
            Algorithm::Argon2id(_) => 4,
        };
        let load_ladder = self
            .load_ladder
            .map(|spec| bollwark::risk::LoadLadder::parse(spec).unwrap())
            .unwrap_or_default();
        let config = AppConfig {
            puzzle_algorithm: algorithm,
            default_difficulty,
            max_difficulty: 16,
            load_ladder,
            challenge_ttl_secs: 300,
            tls_fingerprint_header: self.tls_header.map(String::from),
            ip_hard_limit: self
                .ip_hard_limit
                .unwrap_or(AppConfig::default().ip_hard_limit),
            verify_max_attempts: self
                .verify_max_attempts
                .unwrap_or(AppConfig::default().verify_max_attempts),
            max_active_challenges: self
                .max_active_challenges
                .unwrap_or(AppConfig::default().max_active_challenges),
            failover_enabled: self.enable_failover,
            failover_state_path: self
                .enable_failover
                .then(|| temp_failover_path().to_string_lossy().into_owned()),
            ..AppConfig::default()
        };
        let puzzle_config = PuzzleConfig {
            algorithm: config.puzzle_algorithm,
            default_difficulty: config.default_difficulty,
            ttl_secs: 300,
        };
        let reputation = std::sync::Arc::new(match self.reputation_cidrs {
            Some(content) => ReputationStore::new(CidrListReputation::parse(&content).unwrap()),
            None => ReputationStore::empty(),
        });
        let tls_blocklist = std::sync::Arc::new(match self.tls_blocklist {
            Some(content) => FingerprintBlocklist::parse(&content).unwrap(),
            None => FingerprintBlocklist::empty(),
        });
        let trusted_proxies = std::sync::Arc::new(match self.trusted_proxies {
            Some(spec) => TrustedProxies::parse(spec).unwrap(),
            None => TrustedProxies::empty(),
        });
        let risk = RiskScorer::new(reputation, tls_blocklist);
        let verify_scorer = VerifyScorer::new(self.verify_require_behavior);
        let admin_token = match self.admin_token {
            Some(None) => None,
            Some(Some(t)) => Some(Arc::new(t.to_string())),
            None => Some(Arc::new(TEST_ADMIN_TOKEN.to_string())),
        };
        let store = Arc::new(InMemoryStore::new());

        // Optionally mount the admin dashboard: a real (temp-file) decision log
        // shared between AppState (so handlers record decisions) and AdminState
        // (so the admin endpoints read them), plus the admin sub-router.
        let (decision_log, admin) = if self.enable_admin {
            let path = temp_db_path();
            let log = DecisionLog::open(&path, None).expect("open admin decision log");
            let sessions = Sessions::new(log.db_path().to_string());
            let admin = AdminState {
                sessions,
                log: log.clone(),
                token: Arc::new(TEST_ADMIN_TOKEN.to_string()),
                store: store.clone(),
                config: config.clone(),
            };
            (Some(log), Some(admin))
        } else {
            (None, None)
        };

        let failover = Arc::new(bollwark::failover::FailoverGuard::load(
            config.failover_config(),
        ));

        let state = Arc::new(AppState {
            store: store.clone(),
            engine: PuzzleEngine::new(puzzle_config),
            risk,
            verify_scorer,
            tls_fingerprint_header: self.tls_header.map(String::from),
            trusted_proxies,
            decision_log,
            admin_token,
            info_urls: None,
            verify_permits: Arc::new(tokio::sync::Semaphore::new(
                self.verify_permits
                    .unwrap_or_else(bollwark::api::state::verify_permits),
            )),
            failover,
            config,
        });
        (api::router(state.clone(), admin), store, state)
    }
}

/// Unique temp path for a failover state file, so each test app attests
/// independently and a leftover file can't leak a window between tests.
fn temp_failover_path() -> std::path::PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "bollwark-failover-test-{}-{}.json",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    dir
}

/// Unique temp path for an admin decision-log SQLite file.
fn temp_db_path() -> std::path::PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "bollwark-admin-test-{}-{}.db",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    dir
}

fn with_connect_info(req: Request<Body>) -> Request<Body> {
    with_connect_info_ip(req, "127.0.0.1")
}

fn with_connect_info_ip(req: Request<Body>, ip: &str) -> Request<Body> {
    let (mut parts, body) = req.into_parts();
    let addr: SocketAddr = format!("{ip}:1234").parse().unwrap();
    parts.extensions.insert(axum::extract::ConnectInfo(addr));
    Request::from_parts(parts, body)
}

/// Build a GET /v1/puzzle request with the given headers.
/// Pass `None` for a header to omit it entirely. Always carries the
/// fetch-metadata triple a browser attaches to `fetch()` on its own, so a
/// request with a UA reads as a browser; the impersonation test builds its
/// own request without it.
fn puzzle_request(
    site_key: &str,
    user_agent: Option<&str>,
    accept_language: Option<&str>,
    accept_encoding: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method("GET")
        .uri(format!("/v1/puzzle?site_key={site_key}"));

    if let Some(ua) = user_agent {
        builder = builder.header("User-Agent", ua);
    }
    if let Some(al) = accept_language {
        builder = builder.header("Accept-Language", al);
    }
    if let Some(ae) = accept_encoding {
        builder = builder.header("Accept-Encoding", ae);
    }
    builder = builder
        .header("Sec-Fetch-Mode", "cors")
        .header("Sec-Fetch-Site", "cross-site")
        .header("Sec-Fetch-Dest", "empty");

    builder.body(Body::empty()).unwrap()
}

const CLEAN_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15";
const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                         (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36";
const CLEAN_LANG: &str = "en-US,en;q=0.9";
const CLEAN_ENC: &str = "gzip, deflate, br";

async fn create_test_site(app: &axum::Router) -> CreateSiteResponse {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/sites")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {TEST_ADMIN_TOKEN}"))
        .body(Body::from(r#"{"name":"test site"}"#))
        .unwrap();

    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// Like `create_test_site` but registers an origin allowlist. `origins` is
/// serialized into the `allowed_origins` field of the provisioning request.
async fn create_test_site_with_origins(app: &axum::Router, origins: &[&str]) -> CreateSiteResponse {
    let body = serde_json::json!({ "name": "test site", "allowed_origins": origins });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/sites")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {TEST_ADMIN_TOKEN}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// Build a clean GET /v1/puzzle request, optionally carrying an `Origin`
/// header (pass `None` to omit it entirely).
fn puzzle_request_with_origin(site_key: &str, origin: Option<&str>) -> Request<Body> {
    let mut req = puzzle_request(site_key, Some(CLEAN_UA), Some(CLEAN_LANG), Some(CLEAN_ENC));
    if let Some(o) = origin {
        req.headers_mut().insert("origin", o.parse().unwrap());
    }
    req
}

async fn get_test_puzzle(
    app: &axum::Router,
    site_key: &str,
) -> (StatusCode, Option<PuzzleResponse>) {
    let req = puzzle_request(site_key, Some(CLEAN_UA), Some(CLEAN_LANG), Some(CLEAN_ENC));

    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    let status = resp.status();

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();

    if status == StatusCode::OK {
        (status, Some(serde_json::from_slice(&body).unwrap()))
    } else {
        (status, None)
    }
}

// --- Tests ---

#[tokio::test]
async fn test_full_flow() {
    let app = test_app();

    // 1. Create a site
    let site = create_test_site(&app).await;
    assert!(!site.secret_key.is_empty());

    // 2. Get a puzzle
    let (status, puzzle) = get_test_puzzle(&app, &site.site_key.to_string()).await;
    assert_eq!(status, StatusCode::OK);
    let puzzle = puzzle.unwrap();
    assert_eq!(puzzle.tier, EscalationTier::InvisiblePass);

    // 3. Solve the puzzle
    let nonce = solve_challenge(&puzzle.prefix, puzzle.difficulty);

    // 4. Verify the solution
    let verify_body = serde_json::json!({
        "challenge_id": puzzle.challenge_id,
        "nonce": nonce,
    });

    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", site.secret_key))
        .body(Body::from(serde_json::to_vec(&verify_body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: VerifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(result.success);
}

#[tokio::test]
async fn test_verify_requires_auth() {
    let app = test_app();
    let site = create_test_site(&app).await;
    let (_, puzzle) = get_test_puzzle(&app, &site.site_key.to_string()).await;
    let puzzle = puzzle.unwrap();

    let nonce = solve_challenge(&puzzle.prefix, puzzle.difficulty);

    // No auth header
    let verify_body = serde_json::json!({
        "challenge_id": puzzle.challenge_id,
        "nonce": nonce,
    });

    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&verify_body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_verify_wrong_secret() {
    let app = test_app();
    let site = create_test_site(&app).await;
    let (_, puzzle) = get_test_puzzle(&app, &site.site_key.to_string()).await;
    let puzzle = puzzle.unwrap();

    let nonce = solve_challenge(&puzzle.prefix, puzzle.difficulty);

    let verify_body = serde_json::json!({
        "challenge_id": puzzle.challenge_id,
        "nonce": nonce,
    });

    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", "Bearer wrong_secret")
        .body(Body::from(serde_json::to_vec(&verify_body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_verify_rejects_challenge_from_different_site() {
    let app = test_app();
    let site_a = create_test_site(&app).await;
    let site_b = create_test_site(&app).await;
    let (_, puzzle) = get_test_puzzle(&app, &site_a.site_key.to_string()).await;
    let puzzle = puzzle.unwrap();

    let nonce = solve_challenge(&puzzle.prefix, puzzle.difficulty);

    let verify_body = serde_json::json!({
        "challenge_id": puzzle.challenge_id,
        "nonce": nonce,
    });

    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", site_b.secret_key))
        .body(Body::from(serde_json::to_vec(&verify_body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_replay_rejection() {
    let app = test_app();
    let site = create_test_site(&app).await;
    let (_, puzzle) = get_test_puzzle(&app, &site.site_key.to_string()).await;
    let puzzle = puzzle.unwrap();

    let nonce = solve_challenge(&puzzle.prefix, puzzle.difficulty);

    let verify_body = serde_json::json!({
        "challenge_id": puzzle.challenge_id,
        "nonce": nonce,
    });

    // First verify succeeds
    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", site.secret_key))
        .body(Body::from(serde_json::to_vec(&verify_body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Second verify with same challenge fails (challenge deleted after success)
    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", site.secret_key))
        .body(Body::from(serde_json::to_vec(&verify_body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_invalid_site_key() {
    let app = test_app();

    let (status, _) = get_test_puzzle(&app, "00000000-0000-0000-0000-000000000000").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_wrong_nonce() {
    let app = test_app();
    let site = create_test_site(&app).await;
    let (_, puzzle) = get_test_puzzle(&app, &site.site_key.to_string()).await;
    let puzzle = puzzle.unwrap();

    let verify_body = serde_json::json!({
        "challenge_id": puzzle.challenge_id,
        "nonce": u64::MAX,
    });

    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", site.secret_key))
        .body(Body::from(serde_json::to_vec(&verify_body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: VerifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(!result.success);
    // A failed proof is not a risk verdict, so there is no band to report.
    assert_eq!(result.risk, None);
}

/// POST /v1/verify with an explicit nonce; returns the status and the parsed
/// body on 200.
async fn verify_nonce(
    app: &axum::Router,
    secret: &str,
    challenge_id: uuid::Uuid,
    nonce: u64,
) -> (StatusCode, Option<VerifyResponse>) {
    let verify_body = serde_json::json!({ "challenge_id": challenge_id, "nonce": nonce });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {secret}"))
        .body(Body::from(serde_json::to_vec(&verify_body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    if status == StatusCode::OK {
        (status, Some(serde_json::from_slice(&body).unwrap()))
    } else {
        (status, None)
    }
}

/// The first `n` nonces that do NOT satisfy the difficulty target — guaranteed
/// wrong solutions for exercising the failed-attempt path.
fn wrong_nonces(prefix: &str, difficulty: u32, n: usize) -> Vec<u64> {
    (0u64..)
        .filter(|&nonce| !has_leading_zero_bits(&compute_sha256(prefix, nonce), difficulty))
        .take(n)
        .collect()
}

#[tokio::test]
async fn test_failed_attempts_evict_challenge() {
    // Cap failed attempts at 3; the 3rd wrong nonce evicts the challenge so it
    // can't absorb further (potentially memory-hard) verify attempts.
    let app = test_app_with(|b| b.verify_max_attempts = Some(3));
    let site = create_test_site(&app).await;
    let (_, puzzle) = get_test_puzzle(&app, &site.site_key.to_string()).await;
    let puzzle = puzzle.unwrap();

    let wrong = wrong_nonces(&puzzle.prefix, puzzle.difficulty, 3);
    let correct = solve_challenge(&puzzle.prefix, puzzle.difficulty);

    // First two wrong nonces fail but leave the challenge live for retry.
    for &nonce in &wrong[..2] {
        let (status, body) = verify_nonce(&app, &site.secret_key, puzzle.challenge_id, nonce).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!body.unwrap().success);
    }
    // Third failed attempt reaches the cap and evicts the challenge.
    let (status, body) = verify_nonce(&app, &site.secret_key, puzzle.challenge_id, wrong[2]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.unwrap().success);

    // Even the correct nonce now finds no challenge — it was evicted.
    let (status, _) = verify_nonce(&app, &site.secret_key, puzzle.challenge_id, correct).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_max_active_challenges_blocks_new_issuance() {
    // Ceiling of 2 active challenges: the third puzzle request is shed with a
    // 429 (Block tier) even though its per-IP score is clean.
    let app = test_app_with(|b| b.max_active_challenges = Some(2));
    let site = create_test_site(&app).await;
    let site_key = site.site_key.to_string();

    let (s1, p1) = get_test_puzzle(&app, &site_key).await;
    assert_eq!(s1, StatusCode::OK);
    assert!(p1.is_some());
    let (s2, p2) = get_test_puzzle(&app, &site_key).await;
    assert_eq!(s2, StatusCode::OK);
    assert!(p2.is_some());

    // The map now holds 2 challenges == the cap, so the next one is shed.
    let (s3, _) = get_test_puzzle(&app, &site_key).await;
    assert_eq!(s3, StatusCode::TOO_MANY_REQUESTS);
}

/// Issue a puzzle from a specific client IP so a test can distinguish a
/// flooding source from an unrelated visitor.
async fn get_test_puzzle_from_ip(
    app: &axum::Router,
    site_key: &str,
    ip: &str,
) -> (StatusCode, Option<PuzzleResponse>) {
    let req = puzzle_request(site_key, Some(CLEAN_UA), Some(CLEAN_LANG), Some(CLEAN_ENC));
    let resp = app
        .clone()
        .oneshot(with_connect_info_ip(req, ip))
        .await
        .unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    if status == StatusCode::OK {
        (status, Some(serde_json::from_slice(&body).unwrap()))
    } else {
        (status, None)
    }
}

#[tokio::test]
async fn test_pressure_sheds_flooding_ip_before_the_map_fills() {
    // The global ceiling alone is indiscriminate: at 100% it refuses everyone,
    // so one flooding IP could 429 every tenant. Past 80% of capacity we refuse
    // the sources that are over IP_HARD_LIMIT instead, which is what stops the
    // map ever reaching the ceiling on a single source's account.
    //
    // Ceiling 10 → shed threshold is 8 held challenges. IP_HARD_LIMIT 3 → the
    // flooder trips the per-IP cap on its 4th request.
    let app = test_app_with(|b| {
        b.max_active_challenges = Some(10);
        b.ip_hard_limit = Some(3);
    });
    let site = create_test_site(&app).await;
    let site_key = site.site_key.to_string();

    // The flooder is served while headroom remains — being over IP_HARD_LIMIT
    // only throttles difficulty until the map is under pressure.
    let mut issued = 0;
    let mut shed_at = None;
    for attempt in 1..=12 {
        let (status, _) = get_test_puzzle_from_ip(&app, &site_key, "203.0.113.9").await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            shed_at = Some(attempt);
            break;
        }
        assert_eq!(status, StatusCode::OK, "attempt {attempt} should be served");
        issued += 1;
    }

    // Shed on the 9th request, with 8 of 10 slots used — *not* at the ceiling.
    assert_eq!(
        shed_at,
        Some(9),
        "flooder should be shed once 80% is reached"
    );
    assert_eq!(issued, 8);

    // The critical property: at that same moment the map still has headroom, so
    // an unrelated visitor (nowhere near the per-IP cap) is still served. This
    // is what the old global-only shed got wrong — it refused this request too.
    let (status, puzzle) = get_test_puzzle_from_ip(&app, &site_key, "198.51.100.4").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an unrelated IP must still be served while the map has headroom"
    );
    assert!(puzzle.is_some());
}

#[tokio::test]
async fn test_full_map_still_sheds_everyone_as_last_resort() {
    // Pressure-based shedding targets sources over IP_HARD_LIMIT. A distributed
    // flood that stays under the per-IP cap slips past it, so the global ceiling
    // must still refuse everyone once the map is genuinely full.
    let app = test_app_with(|b| {
        b.max_active_challenges = Some(3);
        // Disable the per-IP cap so nothing is shed for flooding — the only
        // thing that can refuse a request here is the ceiling itself.
        b.ip_hard_limit = Some(0);
    });
    let site = create_test_site(&app).await;
    let site_key = site.site_key.to_string();

    for (i, ip) in ["203.0.113.1", "203.0.113.2", "203.0.113.3"]
        .iter()
        .enumerate()
    {
        let (status, _) = get_test_puzzle_from_ip(&app, &site_key, ip).await;
        assert_eq!(status, StatusCode::OK, "challenge {i} should be issued");
    }

    let (status, _) = get_test_puzzle_from_ip(&app, &site_key, "203.0.113.4").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn test_create_site_empty_name() {
    let app = test_app();

    let req = Request::builder()
        .method("POST")
        .uri("/v1/sites")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {TEST_ADMIN_TOKEN}"))
        .body(Body::from(r#"{"name":""}"#))
        .unwrap();

    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_create_site_without_admin_token_returns_404() {
    let app = test_app_with(|b| {
        b.admin_token = Some(None);
    });

    let req = Request::builder()
        .method("POST")
        .uri("/v1/sites")
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"name":"hello"}"#))
        .unwrap();

    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_create_site_wrong_admin_token_unauthorized() {
    let app = test_app();

    let req = Request::builder()
        .method("POST")
        .uri("/v1/sites")
        .header("Content-Type", "application/json")
        .header(
            "Authorization",
            "Bearer wrong-token-but-same-length-padding",
        )
        .body(Body::from(r#"{"name":"hello"}"#))
        .unwrap();

    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_create_site_missing_authorization_unauthorized() {
    let app = test_app();

    let req = Request::builder()
        .method("POST")
        .uri("/v1/sites")
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"name":"hello"}"#))
        .unwrap();

    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// --- Per-site origin allowlist tests ---

#[tokio::test]
async fn test_origin_allowlist_matching_origin_passes() {
    let app = test_app();
    let site = create_test_site_with_origins(&app, &["https://example.com"]).await;
    let key = site.site_key.to_string();

    let req = puzzle_request_with_origin(&key, Some("https://example.com"));
    let (status, _) = send_puzzle(&app, with_connect_info(req)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_origin_allowlist_mismatched_origin_forbidden() {
    let app = test_app();
    let site = create_test_site_with_origins(&app, &["https://example.com"]).await;
    let key = site.site_key.to_string();

    let req = puzzle_request_with_origin(&key, Some("https://evil.example"));
    let (status, _) = send_puzzle(&app, with_connect_info(req)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_origin_allowlist_missing_origin_passes() {
    // No Origin header → always allowed (same-origin embeds and
    // server-to-server fetches don't send one).
    let app = test_app();
    let site = create_test_site_with_origins(&app, &["https://example.com"]).await;
    let key = site.site_key.to_string();

    let req = puzzle_request_with_origin(&key, None);
    let (status, _) = send_puzzle(&app, with_connect_info(req)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_no_allowlist_allows_any_origin() {
    // A site registered without an allowlist accepts any Origin.
    let app = test_app();
    let site = create_test_site(&app).await;
    let key = site.site_key.to_string();

    let req = puzzle_request_with_origin(&key, Some("https://anything.example"));
    let (status, _) = send_puzzle(&app, with_connect_info(req)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_origin_allowlist_lowercases_header_before_matching() {
    // The stored entry is normalized to lowercase; a mixed-case Origin header
    // that lowercases to an allowed value must still match.
    let app = test_app();
    let site = create_test_site_with_origins(&app, &["https://example.com"]).await;
    let key = site.site_key.to_string();

    let req = puzzle_request_with_origin(&key, Some("HTTPS://Example.COM"));
    let (status, _) = send_puzzle(&app, with_connect_info(req)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_create_site_rejects_invalid_origin() {
    let app = test_app();
    let body = serde_json::json!({ "name": "bad", "allowed_origins": ["not-an-origin"] });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/sites")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {TEST_ADMIN_TOKEN}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_create_site_echoes_normalized_origins() {
    let app = test_app();
    let site = create_test_site_with_origins(&app, &["HTTPS://Example.COM"]).await;
    assert_eq!(site.allowed_origins, vec!["https://example.com"]);
}

#[tokio::test]
async fn test_healthz_ok() {
    let app = test_app();
    let req = Request::builder()
        .method("GET")
        .uri("/healthz")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&body[..], b"ok");
}

#[tokio::test]
async fn test_xff_honored_only_from_trusted_peer() {
    // Trusted-proxy peer (127.0.0.1 in 127/8) sends XFF claiming the
    // original client is 8.8.8.8. The puzzle handler should use 8.8.8.8
    // (not 127.0.0.1) for rate-counting and IP reputation.
    let app = test_app_with(|b| {
        // Mark 8.8.8.0/24 as Tor → score 40 → HardPow tier. If the
        // handler ignored XFF and used the peer (127.0.0.1) instead,
        // the request would hit InvisiblePass.
        b.reputation_cidrs = Some("8.8.8.0/24 tor\n".into());
        b.trusted_proxies = Some("127.0.0.0/8");
    });
    let site = create_test_site(&app).await;
    let key = site.site_key.to_string();

    let mut req = puzzle_request(&key, Some(CLEAN_UA), Some(CLEAN_LANG), Some(CLEAN_ENC));
    req.headers_mut()
        .insert("x-forwarded-for", "8.8.8.8".parse().unwrap());
    let (status, puzzle) = send_puzzle(&app, with_connect_info(req)).await;

    assert_eq!(status, StatusCode::OK);
    let p = puzzle.unwrap();
    assert_eq!(p.tier, EscalationTier::HardPow);
}

#[tokio::test]
async fn test_xff_ignored_from_untrusted_peer() {
    // Same setup but the peer is NOT in trusted_proxies. Spoofed XFF
    // must be ignored — we score the actual peer instead.
    let app = test_app_with(|b| {
        b.reputation_cidrs = Some("8.8.8.0/24 tor\n".into());
        // 10/8, but peer below is 127.0.0.1.
        b.trusted_proxies = Some("10.0.0.0/8");
    });
    let site = create_test_site(&app).await;
    let key = site.site_key.to_string();

    let mut req = puzzle_request(&key, Some(CLEAN_UA), Some(CLEAN_LANG), Some(CLEAN_ENC));
    req.headers_mut()
        .insert("x-forwarded-for", "8.8.8.8".parse().unwrap());
    let (status, puzzle) = send_puzzle(&app, with_connect_info(req)).await;

    assert_eq!(status, StatusCode::OK);
    let p = puzzle.unwrap();
    // XFF ignored → 127.0.0.1 isn't in the reputation list → InvisiblePass.
    assert_eq!(p.tier, EscalationTier::InvisiblePass);
}

// --- Risk scoring / escalation tier tests ---

async fn send_puzzle(
    app: &axum::Router,
    req: Request<Body>,
) -> (StatusCode, Option<PuzzleResponse>) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    if status == StatusCode::OK {
        (status, Some(serde_json::from_slice(&body).unwrap()))
    } else {
        (status, None)
    }
}

#[tokio::test]
async fn test_clean_headers_low_rate_yields_invisible_pass() {
    let app = test_app();
    let site = create_test_site(&app).await;
    let key = site.site_key.to_string();

    let req = puzzle_request(&key, Some(CLEAN_UA), Some(CLEAN_LANG), Some(CLEAN_ENC));
    let (status, puzzle) = send_puzzle(&app, with_connect_info(req)).await;

    assert_eq!(status, StatusCode::OK);
    let puzzle = puzzle.unwrap();
    assert_eq!(puzzle.tier, EscalationTier::InvisiblePass);
    assert_eq!(puzzle.difficulty, 8); // default_difficulty in test_app
}

#[tokio::test]
async fn test_load_ladder_floors_difficulty_under_site_load() {
    // Floor difficulty to 12 bits once the site sees >= 3 requests in the
    // window. The clients are individually clean (InvisiblePass), so this
    // isolates the aggregate load floor from per-request risk.
    let app = test_app_with(|b| b.load_ladder = Some("3:12"));
    let site = create_test_site(&app).await;
    let key = site.site_key.to_string();

    // Each request comes from a distinct IP so per-IP rate never escalates the
    // tier — only the per-site counter climbs toward the ladder threshold.
    let mut difficulties = Vec::new();
    let mut tiers = Vec::new();
    for i in 0..3 {
        let req = puzzle_request(&key, Some(CLEAN_UA), Some(CLEAN_LANG), Some(CLEAN_ENC));
        let ip = format!("10.0.0.{}", 100 + i);
        let (status, puzzle) = send_puzzle(&app, with_connect_info_ip(req, &ip)).await;
        assert_eq!(status, StatusCode::OK);
        let puzzle = puzzle.unwrap();
        difficulties.push(puzzle.difficulty);
        tiers.push(puzzle.tier);
    }

    // Below the threshold (site_count 1 and 2) the floor is 0 → base 8.
    assert_eq!(difficulties[0], 8);
    assert_eq!(difficulties[1], 8);
    // The 3rd request meets the threshold → floor 12 = max(base 8, 12).
    assert_eq!(difficulties[2], 12);
    // The floor never changes the tier — it only raises difficulty.
    assert!(tiers.iter().all(|t| *t == EscalationTier::InvisiblePass));
}

#[tokio::test]
async fn test_missing_user_agent_bumps_to_checkbox() {
    let app = test_app();
    let site = create_test_site(&app).await;
    let key = site.site_key.to_string();

    // No UA → header_anomaly = 30 → >= TIER_CHECKBOX_MIN (20), < TIER_HARD_POW_MIN (40)
    let req = puzzle_request(&key, None, Some(CLEAN_LANG), Some(CLEAN_ENC));
    let (status, puzzle) = send_puzzle(&app, with_connect_info(req)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(puzzle.unwrap().tier, EscalationTier::Checkbox);
}

/// A Chrome UA string on a request with neither fetch metadata nor client
/// hints is the signature of an HTTP library with a copied User-Agent. The two
/// impersonation checks sum to 30 — the same weight as omitting the UA — which
/// is Checkbox under the default bands.
#[tokio::test]
async fn test_copied_chrome_ua_without_browser_headers_bumps_to_checkbox() {
    let app = test_app();
    let site = create_test_site(&app).await;
    let key = site.site_key.to_string();

    let req = Request::builder()
        .method("GET")
        .uri(format!("/v1/puzzle?site_key={key}"))
        .header("User-Agent", CHROME_UA)
        .header("Accept-Language", CLEAN_LANG)
        .header("Accept-Encoding", CLEAN_ENC)
        .body(Body::empty())
        .unwrap();
    let (status, puzzle) = send_puzzle(&app, with_connect_info(req)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(puzzle.unwrap().tier, EscalationTier::Checkbox);
}

#[tokio::test]
async fn test_spammed_ip_with_clean_headers_escalates_to_checkbox() {
    let app = test_app();
    let site = create_test_site(&app).await;
    let key = site.site_key.to_string();

    // ip_count > 50 on its own contributes 30 to the risk score, which lands in the
    // Checkbox band (>=20, <40). Clean headers keep header_anomaly at 0.
    let spam_ip = "10.0.0.42";
    let mut last: Option<PuzzleResponse> = None;
    for _ in 0..55 {
        let req = puzzle_request(&key, Some(CLEAN_UA), Some(CLEAN_LANG), Some(CLEAN_ENC));
        let (status, puzzle) = send_puzzle(&app, with_connect_info_ip(req, spam_ip)).await;
        assert_eq!(status, StatusCode::OK);
        last = puzzle;
    }

    let final_puzzle = last.expect("last request returned a puzzle");
    assert_eq!(final_puzzle.tier, EscalationTier::Checkbox);
    // Difficulty bump for Checkbox tier in tier::difficulty_for is +2.
    assert_eq!(final_puzzle.difficulty, 10);
}

#[tokio::test]
async fn test_spam_plus_suspicious_ua_serves_hard_pow() {
    let app = test_app();
    let site = create_test_site(&app).await;
    let key = site.site_key.to_string();

    // Warm the IP counter with 55 clean-UA requests so ip_count > 50 → rate = 30.
    let attacker_ip = "10.0.0.7";
    for _ in 0..55 {
        let req = puzzle_request(&key, Some(CLEAN_UA), Some(CLEAN_LANG), Some(CLEAN_ENC));
        let (status, _) = send_puzzle(&app, with_connect_info_ip(req, attacker_ip)).await;
        assert_eq!(status, StatusCode::OK);
    }

    // Now send a request with curl UA and no language/encoding:
    //   header_anomaly = 25 (UA) + 10 (lang) + 10 (enc) = 45
    //   rate = 30
    //   total = 75 → HardPow band (>=40, <85). The old VisualChallenge band
    //   folded into HardPow, so this serves a harder PoW (no image-text).
    let bad = puzzle_request(&key, Some("curl/8.0"), None, None);
    let (status, puzzle) = send_puzzle(&app, with_connect_info_ip(bad, attacker_ip)).await;
    assert_eq!(status, StatusCode::OK);
    let puzzle = puzzle.expect("HardPow tier returns a puzzle");
    assert_eq!(puzzle.tier, EscalationTier::HardPow);
    // Difficulty bump for HardPow in tier::difficulty_for is +4 (base 8 → 12).
    assert_eq!(puzzle.difficulty, 12);
    assert!(!puzzle.prefix.is_empty(), "PoW challenge carries a prefix");
}

#[tokio::test]
async fn test_ip_hard_limit_throttles_to_max_pow_regardless_of_score() {
    let app = test_app_with(|b| b.ip_hard_limit = Some(5));
    let site = create_test_site(&app).await;
    let key = site.site_key.to_string();

    // Clean headers keep the risk score at ~0 — the scoring path alone would
    // never escalate this client, which is exactly what the hard cap is for.
    // Below the cap, puzzles come out at the base InvisiblePass difficulty.
    let flood_ip = "10.9.9.9";
    for _ in 0..5 {
        let req = puzzle_request(&key, Some(CLEAN_UA), Some(CLEAN_LANG), Some(CLEAN_ENC));
        let (status, puzzle) = send_puzzle(&app, with_connect_info_ip(req, flood_ip)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(puzzle.unwrap().tier, EscalationTier::InvisiblePass);
    }

    // Request 6 crosses IP_HARD_LIMIT=5 → still issued, but throttled to the
    // max-difficulty HardPow tier rather than hard-blocked, so a shared IP
    // (CGNAT) isn't 429'd with no recourse. (max_difficulty is 16 in tests.)
    let req = puzzle_request(&key, Some(CLEAN_UA), Some(CLEAN_LANG), Some(CLEAN_ENC));
    let (status, puzzle) = send_puzzle(&app, with_connect_info_ip(req, flood_ip)).await;
    assert_eq!(status, StatusCode::OK);
    let puzzle = puzzle.unwrap();
    assert_eq!(puzzle.tier, EscalationTier::HardPow);
    assert_eq!(puzzle.difficulty, 16);

    // The cap is per-IP: a different client is unaffected (base difficulty).
    let req = puzzle_request(&key, Some(CLEAN_UA), Some(CLEAN_LANG), Some(CLEAN_ENC));
    let (status, puzzle) = send_puzzle(&app, with_connect_info_ip(req, "10.9.9.10")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(puzzle.unwrap().tier, EscalationTier::InvisiblePass);
}

#[tokio::test]
async fn test_ip_hard_limit_zero_disables_cap() {
    let app = test_app_with(|b| b.ip_hard_limit = Some(0));
    let site = create_test_site(&app).await;
    let key = site.site_key.to_string();

    for _ in 0..12 {
        let req = puzzle_request(&key, Some(CLEAN_UA), Some(CLEAN_LANG), Some(CLEAN_ENC));
        let (status, _) = send_puzzle(&app, with_connect_info_ip(req, "10.9.9.11")).await;
        assert_eq!(status, StatusCode::OK);
    }
}

#[tokio::test]
async fn test_very_fast_submit_shadow_fails() {
    // No backdating: the challenge is issued and verified ~instantly, so the
    // server-derived time-on-page is well under 500ms → +50. With default
    // VERIFY_BLOCK_MIN=60 that's ShadowFail (success=true), not Block.
    //
    // For this assertion we verify the ShadowFail path: success returned
    // despite a suspicious time. A future test with tightened thresholds can
    // exercise Block.
    let app = test_app();
    let site = create_test_site(&app).await;
    let (_, puzzle) = get_test_puzzle(&app, &site.site_key.to_string()).await;
    let puzzle = puzzle.unwrap();
    let nonce = solve_challenge(&puzzle.prefix, puzzle.difficulty);

    let verify_body = serde_json::json!({
        "challenge_id": puzzle.challenge_id,
        "nonce": nonce,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", site.secret_key))
        .body(Body::from(serde_json::to_vec(&verify_body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: VerifyResponse = serde_json::from_slice(&body).unwrap();
    // ShadowFail returns success: true; the band is how the caller sees it.
    assert!(result.success, "shadow-fail still returns success=true");
    assert_eq!(result.risk, Some(RiskBand::Elevated));
}

#[tokio::test]
async fn test_clean_verify_reports_low_risk() {
    let (app, store) = test_app_with_store(|_| {});
    let site = create_test_site(&app).await;
    let (_, puzzle) = get_test_puzzle(&app, &site.site_key.to_string()).await;
    let puzzle = puzzle.unwrap();
    let nonce = solve_challenge(&puzzle.prefix, puzzle.difficulty);
    backdate_challenge(&store, puzzle.challenge_id, 5).await;

    let verify_body = serde_json::json!({
        "challenge_id": puzzle.challenge_id,
        "nonce": nonce,
        "behavior": {
            "mouse_moves": 20,
            "touches": 0,
            "interactions": 2,
            "first_interaction_ms": 800,
        },
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", site.secret_key))
        .body(Body::from(serde_json::to_vec(&verify_body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: VerifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(result.success);
    assert_eq!(result.risk, Some(RiskBand::Low));
}

#[tokio::test]
async fn test_require_behavior_blocks_blobless_fast_submit() {
    // With VERIFY_REQUIRE_BEHAVIOR, an instant submit with no behavior blob
    // stacks absent(+30) on time<500ms(+50) = 80 ≥ VERIFY_BLOCK_MIN(60) →
    // Block (success=false). The same request with the flag off is only
    // ShadowFail — covered by test_very_fast_submit_shadow_fails above.
    let app = test_app_with(|b| b.verify_require_behavior = true);
    let site = create_test_site(&app).await;
    let (_, puzzle) = get_test_puzzle(&app, &site.site_key.to_string()).await;
    let puzzle = puzzle.unwrap();
    let nonce = solve_challenge(&puzzle.prefix, puzzle.difficulty);

    let verify_body = serde_json::json!({
        "challenge_id": puzzle.challenge_id,
        "nonce": nonce,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", site.secret_key))
        .body(Body::from(serde_json::to_vec(&verify_body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: VerifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(
        !result.success,
        "absent blob + instant submit must block when behavior is required"
    );
}

#[tokio::test]
async fn test_require_behavior_passes_widget_style_submit() {
    // The flag must not penalize clients that do send the blob: organic
    // behavior + realistic dwell scores 0 → Pass.
    let (app, store) = test_app_with_store(|b| b.verify_require_behavior = true);
    let site = create_test_site(&app).await;
    let (_, puzzle) = get_test_puzzle(&app, &site.site_key.to_string()).await;
    let puzzle = puzzle.unwrap();
    backdate_challenge(&store, puzzle.challenge_id, 10).await;
    let nonce = solve_challenge(&puzzle.prefix, puzzle.difficulty);

    let verify_body = serde_json::json!({
        "challenge_id": puzzle.challenge_id,
        "nonce": nonce,
        "behavior": {
            "mouse_moves": 18,
            "touches": 0,
            "interactions": 3,
            "first_interaction_ms": 900,
            "webdriver": false,
        },
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", site.secret_key))
        .body(Body::from(serde_json::to_vec(&verify_body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: VerifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(result.success);
}

#[tokio::test]
async fn test_normal_submit_with_reasonable_time_passes() {
    let (app, store) = test_app_with_store(|_| {});
    let site = create_test_site(&app).await;
    let (_, puzzle) = get_test_puzzle(&app, &site.site_key.to_string()).await;
    let puzzle = puzzle.unwrap();
    let nonce = solve_challenge(&puzzle.prefix, puzzle.difficulty);
    // Simulate a real visitor who dwelled 5s before submitting.
    backdate_challenge(&store, puzzle.challenge_id, 5).await;

    let verify_body = serde_json::json!({
        "challenge_id": puzzle.challenge_id,
        "nonce": nonce,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", site.secret_key))
        .body(Body::from(serde_json::to_vec(&verify_body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: VerifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(result.success);
}

#[tokio::test]
async fn test_verify_accepts_opaque_token() {
    // The widget hex-encodes a JSON blob and the form host forwards it as a
    // single opaque `token` — no parsing on the host side.
    let (app, store) = test_app_with_store(|_| {});
    let site = create_test_site(&app).await;
    let (_, puzzle) = get_test_puzzle(&app, &site.site_key.to_string()).await;
    let puzzle = puzzle.unwrap();
    let nonce = solve_challenge(&puzzle.prefix, puzzle.difficulty);
    backdate_challenge(&store, puzzle.challenge_id, 5).await;

    let inner = serde_json::json!({ "challenge_id": puzzle.challenge_id, "nonce": nonce });
    let token = hex::encode(serde_json::to_vec(&inner).unwrap());

    let verify_body = serde_json::json!({ "token": token });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", site.secret_key))
        .body(Body::from(serde_json::to_vec(&verify_body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: VerifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(result.success, "opaque token round-trip should verify");
}

#[tokio::test]
async fn test_verify_rejects_malformed_token() {
    let app = test_app();
    let site = create_test_site(&app).await;

    let verify_body = serde_json::json!({ "token": "not-valid-hex-zzz" });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", site.secret_key))
        .body(Body::from(serde_json::to_vec(&verify_body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_honeypot_filled_fails_verify() {
    let app = test_app();
    let site = create_test_site(&app).await;
    let (_, puzzle) = get_test_puzzle(&app, &site.site_key.to_string()).await;
    let puzzle = puzzle.unwrap();

    let nonce = solve_challenge(&puzzle.prefix, puzzle.difficulty);
    let verify_body = serde_json::json!({
        "challenge_id": puzzle.challenge_id,
        "nonce": nonce,
        "honeypot": "spam@example.com",
    });

    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", site.secret_key))
        .body(Body::from(serde_json::to_vec(&verify_body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: VerifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(!result.success, "honeypot should reject");
}

#[tokio::test]
async fn test_honeypot_empty_or_missing_passes() {
    let app = test_app();
    let site = create_test_site(&app).await;
    let (_, puzzle) = get_test_puzzle(&app, &site.site_key.to_string()).await;
    let puzzle = puzzle.unwrap();

    let nonce = solve_challenge(&puzzle.prefix, puzzle.difficulty);
    // Empty string honeypot — same as not setting it.
    let verify_body = serde_json::json!({
        "challenge_id": puzzle.challenge_id,
        "nonce": nonce,
        "honeypot": "",
    });

    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", site.secret_key))
        .body(Body::from(serde_json::to_vec(&verify_body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: VerifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(result.success);
}

#[tokio::test]
async fn test_tor_ip_escalates_to_hard_pow() {
    // 198.51.100.0/24 is RFC 5737 documentation space; mapped to "tor" here.
    let app = test_app_with(|b| {
        b.reputation_cidrs = Some("198.51.100.0/24 tor\n".into());
    });
    let site = create_test_site(&app).await;
    let key = site.site_key.to_string();

    let req = puzzle_request(&key, Some(CLEAN_UA), Some(CLEAN_LANG), Some(CLEAN_ENC));
    let (status, puzzle) = send_puzzle(&app, with_connect_info_ip(req, "198.51.100.42")).await;

    assert_eq!(status, StatusCode::OK);
    let p = puzzle.unwrap();
    // Tor alone scores 40 → HardPow band (>=40, <65)
    assert_eq!(p.tier, EscalationTier::HardPow);
}

#[tokio::test]
async fn test_no_cookie_is_ever_set() {
    // Cookie-free: the puzzle endpoint must never emit a Set-Cookie header.
    let app = test_app();
    let site = create_test_site(&app).await;
    let key = site.site_key.to_string();

    let req = puzzle_request(&key, Some(CLEAN_UA), Some(CLEAN_LANG), Some(CLEAN_ENC));
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get("set-cookie").is_none(),
        "service is cookie-free — no Set-Cookie should ever be issued"
    );
}

#[tokio::test]
async fn test_suspicious_ua_without_spam_stays_below_block() {
    let app = test_app();
    let site = create_test_site(&app).await;
    let key = site.site_key.to_string();

    // curl UA alone: header_anomaly = 25, rate = 0 → total 25 → Checkbox (not Block).
    let req = puzzle_request(&key, Some("curl/8.0"), Some(CLEAN_LANG), Some(CLEAN_ENC));
    let (status, puzzle) = send_puzzle(&app, with_connect_info(req)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(puzzle.unwrap().tier, EscalationTier::Checkbox);
}

// --- Argon2id end-to-end ---

#[tokio::test]
async fn test_argon2id_full_flow() {
    // Server configured for Argon2id with minimum-cost params (kept tiny so
    // the test brute-force solver returns in a few hundred ms).
    let params = Argon2idParams {
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
    };
    let (app, store) = test_app_with_store(|b| {
        b.algorithm = Some(Algorithm::Argon2id(params));
    });
    let site = create_test_site(&app).await;

    let (status, puzzle) = get_test_puzzle(&app, &site.site_key.to_string()).await;
    assert_eq!(status, StatusCode::OK);
    let puzzle = puzzle.unwrap();

    // Wire format: Argon2id serialises as a tagged object so the worker
    // knows which params to use.
    let algorithm_json = serde_json::to_value(puzzle.algorithm).unwrap();
    assert!(
        algorithm_json.get("argon2id").is_some(),
        "wire format includes argon2id key, got {algorithm_json}"
    );

    let nonce = solve_argon2id_challenge(&puzzle.prefix, puzzle.difficulty, params);
    backdate_challenge(&store, puzzle.challenge_id, 5).await;
    let verify_body = serde_json::json!({
        "challenge_id": puzzle.challenge_id,
        "nonce": nonce,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", site.secret_key))
        .body(Body::from(serde_json::to_vec(&verify_body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: VerifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(result.success, "valid Argon2id solve should verify");
}

#[tokio::test]
async fn test_argon2id_wrong_nonce_fails() {
    let params = Argon2idParams {
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
    };
    let app = test_app_with(|b| {
        b.algorithm = Some(Algorithm::Argon2id(params));
    });
    let site = create_test_site(&app).await;
    let (_, puzzle) = get_test_puzzle(&app, &site.site_key.to_string()).await;
    let puzzle = puzzle.unwrap();

    // At difficulty 4, ~1/16 random nonces satisfy the challenge by luck.
    // Pick one we've locally verified does NOT satisfy so the rejection path
    // is exercised deterministically.
    let mut bad_nonce = 1u64;
    loop {
        let hash = compute_argon2id(&puzzle.prefix, bad_nonce, params).unwrap();
        if !has_leading_zero_bits(&hash, puzzle.difficulty) {
            break;
        }
        bad_nonce += 1;
    }
    let verify_body = serde_json::json!({
        "challenge_id": puzzle.challenge_id,
        "nonce": bad_nonce,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", site.secret_key))
        .body(Body::from(serde_json::to_vec(&verify_body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: VerifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(!result.success);
}

// --- Behavior signal tests ---

#[tokio::test]
async fn test_behavior_flatline_with_fast_submit_blocks() {
    let app = test_app();
    let site = create_test_site(&app).await;
    let (_, puzzle) = get_test_puzzle(&app, &site.site_key.to_string()).await;
    let puzzle = puzzle.unwrap();
    let nonce = solve_challenge(&puzzle.prefix, puzzle.difficulty);

    // 0 mouse moves + 0 touches + 0 interactions → flatline = 30
    // instant submit (no backdating) → server-derived time < 500ms → +50
    // total = 80 → above default block_min (60) → success: false
    let verify_body = serde_json::json!({
        "challenge_id": puzzle.challenge_id,
        "nonce": nonce,
        "behavior": {
            "mouse_moves": 0,
            "touches": 0,
            "interactions": 0,
        },
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", site.secret_key))
        .body(Body::from(serde_json::to_vec(&verify_body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: VerifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(!result.success, "flatline + fast submit should block");
}

#[tokio::test]
async fn test_webdriver_flag_alone_shadow_fails() {
    // webdriver=true alone scores 30 → exactly at shadow_min, so the
    // request still returns success=true but the WARN log records it.
    // Backdate so the server-derived time-on-page is 0 and webdriver is the
    // only contributing signal.
    let (app, store) = test_app_with_store(|_| {});
    let site = create_test_site(&app).await;
    let (_, puzzle) = get_test_puzzle(&app, &site.site_key.to_string()).await;
    let puzzle = puzzle.unwrap();
    let nonce = solve_challenge(&puzzle.prefix, puzzle.difficulty);
    backdate_challenge(&store, puzzle.challenge_id, 5).await;

    let verify_body = serde_json::json!({
        "challenge_id": puzzle.challenge_id,
        "nonce": nonce,
        "behavior": {
            "mouse_moves": 25,
            "interactions": 3,
            "first_interaction_ms": 1_200,
            "webdriver": true,
        },
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", site.secret_key))
        .body(Body::from(serde_json::to_vec(&verify_body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: VerifyResponse = serde_json::from_slice(&body).unwrap();
    // ShadowFail returns success=true (caller is the form host; the log
    // is the audit trail).
    assert!(
        result.success,
        "webdriver alone should shadow-fail, not block"
    );
}

#[tokio::test]
async fn test_webdriver_plus_flatline_blocks() {
    // CDP-driven Chrome with no mouse interaction — exactly the
    // browser-harness baseline pattern: flatline (30) + webdriver (30) = 60
    // → block_min boundary → success=false. Backdate so time-on-page is 0
    // and the two behaviour signals are exactly what tips it over.
    let (app, store) = test_app_with_store(|_| {});
    let site = create_test_site(&app).await;
    let (_, puzzle) = get_test_puzzle(&app, &site.site_key.to_string()).await;
    let puzzle = puzzle.unwrap();
    let nonce = solve_challenge(&puzzle.prefix, puzzle.difficulty);
    backdate_challenge(&store, puzzle.challenge_id, 5).await;

    let verify_body = serde_json::json!({
        "challenge_id": puzzle.challenge_id,
        "nonce": nonce,
        "behavior": {
            "mouse_moves": 0,
            "touches": 0,
            "interactions": 0,
            "webdriver": true,
        },
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", site.secret_key))
        .body(Body::from(serde_json::to_vec(&verify_body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: VerifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(!result.success, "webdriver + flatline should block");
}

#[tokio::test]
async fn test_behavior_organic_passes() {
    let (app, store) = test_app_with_store(|_| {});
    let site = create_test_site(&app).await;
    let (_, puzzle) = get_test_puzzle(&app, &site.site_key.to_string()).await;
    let puzzle = puzzle.unwrap();
    let nonce = solve_challenge(&puzzle.prefix, puzzle.difficulty);
    backdate_challenge(&store, puzzle.challenge_id, 5).await;

    let verify_body = serde_json::json!({
        "challenge_id": puzzle.challenge_id,
        "nonce": nonce,
        "behavior": {
            "mouse_moves": 25,
            "touches": 0,
            "interactions": 3,
            "first_interaction_ms": 1_200,
        },
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", site.secret_key))
        .body(Body::from(serde_json::to_vec(&verify_body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: VerifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(result.success);
}

/// One full puzzle → solve → verify cycle carrying `behavior`, with the
/// challenge backdated so the dwell band contributes nothing and the behaviour
/// blob is the only thing being measured. Returns the response's `success`.
async fn solve_and_verify_with_behavior(
    app: &axum::Router,
    store: &InMemoryStore,
    site: &CreateSiteResponse,
    behavior: serde_json::Value,
) -> bool {
    let (_, puzzle) = get_test_puzzle(app, &site.site_key.to_string()).await;
    let puzzle = puzzle.unwrap();
    let nonce = solve_challenge(&puzzle.prefix, puzzle.difficulty);
    backdate_challenge(store, puzzle.challenge_id, 5).await;

    let verify_body = serde_json::json!({
        "challenge_id": puzzle.challenge_id,
        "nonce": nonce,
        "behavior": behavior,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", site.secret_key))
        .body(Body::from(serde_json::to_vec(&verify_body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: VerifyResponse = serde_json::from_slice(&body).unwrap();
    result.success
}

#[tokio::test]
async fn test_duplicate_behavior_blob_escalates_after_the_threshold() {
    // A script replaying one fabricated organic-looking blob — the exact
    // payload that scored 0 before this signal existed. The site pulls
    // verify_block_min down to the duplicate weight so the escalation is
    // observable over HTTP at all: a ShadowFail still answers success=true.
    let (app, store) = test_app_with_store(|_| {});
    let site =
        create_test_site_with_policy(&app, serde_json::json!({ "verify_block_min": 30 })).await;
    let n = BEHAVIOR_DUPLICATE_MIN;

    let blob = serde_json::json!({
        "mouse_moves": 20,
        "touches": 0,
        "interactions": 2,
        "first_interaction_ms": 800,
    });

    for i in 1..n {
        assert!(
            solve_and_verify_with_behavior(&app, &store, &site, blob.clone()).await,
            "submission {i} is still below the duplicate threshold — \
             {n} identical blobs is the evidence, fewer is coincidence"
        );
    }
    for i in n..=n + 1 {
        assert!(
            !solve_and_verify_with_behavior(&app, &store, &site, blob.clone()).await,
            "submission {i} repeats a blob this site has already seen {} times",
            i - 1
        );
    }
}

#[tokio::test]
async fn test_distinct_behavior_blobs_do_not_escalate() {
    // The same traffic volume from N+1 different visitors. Real widgets differ
    // in at least the millisecond of their first interaction, so nothing here
    // is a duplicate and the identical policy leaves every submission alone.
    let (app, store) = test_app_with_store(|_| {});
    let site =
        create_test_site_with_policy(&app, serde_json::json!({ "verify_block_min": 30 })).await;
    let n = BEHAVIOR_DUPLICATE_MIN;

    for i in 0..=n {
        let blob = serde_json::json!({
            "mouse_moves": 20 + i,
            "touches": 0,
            "interactions": 2,
            "first_interaction_ms": 800 + i,
        });
        assert!(
            solve_and_verify_with_behavior(&app, &store, &site, blob).await,
            "distinct blob {i} must not be treated as a repeat"
        );
    }
}

#[tokio::test]
async fn test_behavior_absent_doesnt_penalise_legacy_clients() {
    // No behavior field at all → BehaviorPresence::Absent → 0 contribution.
    // Combined with everything else clean, should still pass.
    let (app, store) = test_app_with_store(|_| {});
    let site = create_test_site(&app).await;
    let (_, puzzle) = get_test_puzzle(&app, &site.site_key.to_string()).await;
    let puzzle = puzzle.unwrap();
    let nonce = solve_challenge(&puzzle.prefix, puzzle.difficulty);
    backdate_challenge(&store, puzzle.challenge_id, 5).await;

    let verify_body = serde_json::json!({
        "challenge_id": puzzle.challenge_id,
        "nonce": nonce,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", site.secret_key))
        .body(Body::from(serde_json::to_vec(&verify_body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: VerifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(result.success);
}

// --- TLS fingerprint tests ---

#[tokio::test]
async fn test_tls_fingerprint_from_trusted_peer_scores() {
    let app = test_app_with(|b| {
        b.tls_header = Some("x-ja4");
        b.tls_blocklist = Some("badfp\n".into());
        b.trusted_proxies = Some("127.0.0.0/8");
    });
    let site = create_test_site(&app).await;
    let key = site.site_key.to_string();

    let mut req = puzzle_request(&key, Some(CLEAN_UA), Some(CLEAN_LANG), Some(CLEAN_ENC));
    req.headers_mut().insert("x-ja4", "badfp".parse().unwrap());
    let (status, puzzle) = send_puzzle(&app, with_connect_info(req)).await;

    assert_eq!(status, StatusCode::OK);
    let p = puzzle.unwrap();
    // 35 (TLS fingerprint match) → Checkbox band (>=20, <40)
    assert_eq!(p.tier, EscalationTier::Checkbox);
}

#[tokio::test]
async fn test_tls_fingerprint_from_untrusted_peer_ignored() {
    let app = test_app_with(|b| {
        b.tls_header = Some("x-ja4");
        b.tls_blocklist = Some("badfp\n".into());
        // Trusted proxies: 10.0.0.0/8 only — 127.0.0.1 (test peer) is NOT trusted.
        b.trusted_proxies = Some("10.0.0.0/8");
    });
    let site = create_test_site(&app).await;
    let key = site.site_key.to_string();

    let mut req = puzzle_request(&key, Some(CLEAN_UA), Some(CLEAN_LANG), Some(CLEAN_ENC));
    req.headers_mut().insert("x-ja4", "badfp".parse().unwrap());
    let (status, puzzle) = send_puzzle(&app, with_connect_info(req)).await;

    assert_eq!(status, StatusCode::OK);
    let p = puzzle.unwrap();
    // Header was ignored because peer (127.0.0.1) isn't in trusted proxies.
    // Score should be 0 → InvisiblePass.
    assert_eq!(p.tier, EscalationTier::InvisiblePass);
}

#[tokio::test]
async fn test_tls_fingerprint_unknown_value_passes() {
    let app = test_app_with(|b| {
        b.tls_header = Some("x-ja4");
        b.tls_blocklist = Some("badfp\n".into());
        b.trusted_proxies = Some("127.0.0.0/8");
    });
    let site = create_test_site(&app).await;
    let key = site.site_key.to_string();

    let mut req = puzzle_request(&key, Some(CLEAN_UA), Some(CLEAN_LANG), Some(CLEAN_ENC));
    req.headers_mut()
        .insert("x-ja4", "legit-chrome-fp".parse().unwrap());
    let (status, puzzle) = send_puzzle(&app, with_connect_info(req)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(puzzle.unwrap().tier, EscalationTier::InvisiblePass);
}

#[tokio::test]
async fn test_tls_fingerprint_disabled_when_header_unset() {
    // No tls_header configured → handler never reads any header, even from
    // trusted peers.
    let app = test_app_with(|b| {
        b.tls_blocklist = Some("badfp\n".into());
        b.trusted_proxies = Some("127.0.0.0/8");
    });
    let site = create_test_site(&app).await;
    let key = site.site_key.to_string();

    let mut req = puzzle_request(&key, Some(CLEAN_UA), Some(CLEAN_LANG), Some(CLEAN_ENC));
    req.headers_mut().insert("x-ja4", "badfp".parse().unwrap());
    let (status, puzzle) = send_puzzle(&app, with_connect_info(req)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(puzzle.unwrap().tier, EscalationTier::InvisiblePass);
}

// --- Admin router (/v1/admin/*) ---

/// Issue an admin request; returns the status and parsed JSON body (Null if
/// the body isn't JSON).
async fn admin_req(
    app: &axum::Router,
    method: &str,
    uri: &str,
    bearer: Option<&str>,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(b) = bearer {
        builder = builder.header("Authorization", format!("Bearer {b}"));
    }
    let req = match body {
        Some(json) => builder
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&json).unwrap()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn test_admin_requires_bearer() {
    let (app, _store) = test_app_with_store(|b| b.enable_admin = true);
    // No bearer at all.
    let (status, _) = admin_req(&app, "GET", "/v1/admin/stats", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Wrong bearer.
    let (status, _) = admin_req(&app, "GET", "/v1/admin/stats", Some("nope"), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_admin_stats_exposes_dropped_records() {
    let (app, _store) = test_app_with_store(|b| b.enable_admin = true);
    let (status, body) =
        admin_req(&app, "GET", "/v1/admin/stats", Some(TEST_ADMIN_TOKEN), None).await;
    assert_eq!(status, StatusCode::OK);
    // The drop counter is surfaced (0 on a fresh log) — the field must exist.
    assert_eq!(body["dropped_records"], serde_json::json!(0));
}

#[tokio::test]
async fn test_admin_update_origins_happy_path() {
    let (app, store) = test_app_with_store(|b| b.enable_admin = true);
    let site = create_test_site(&app).await;
    let uri = format!("/v1/admin/sites/{}/origins", site.site_key);
    let body = serde_json::json!({ "allowed_origins": ["https://Allowed.Example"] });

    let (status, resp) = admin_req(&app, "PUT", &uri, Some(TEST_ADMIN_TOKEN), Some(body)).await;
    assert_eq!(status, StatusCode::OK);
    // Response echoes the normalized (lowercased) origin.
    assert_eq!(resp["allowed_origins"][0], "https://allowed.example");
    // And the store actually reflects it.
    let reloaded = store
        .get_site_by_key(&site.site_key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reloaded.allowed_origins, vec!["https://allowed.example"]);
}

#[tokio::test]
async fn test_admin_update_origins_rejects_bad_input() {
    let (app, _store) = test_app_with_store(|b| b.enable_admin = true);
    let site = create_test_site(&app).await;

    // Invalid UUID in the path → 400.
    let (status, _) = admin_req(
        &app,
        "PUT",
        "/v1/admin/sites/not-a-uuid/origins",
        Some(TEST_ADMIN_TOKEN),
        Some(serde_json::json!({ "allowed_origins": [] })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Malformed origin (no scheme) → 400.
    let uri = format!("/v1/admin/sites/{}/origins", site.site_key);
    let (status, _) = admin_req(
        &app,
        "PUT",
        &uri,
        Some(TEST_ADMIN_TOKEN),
        Some(serde_json::json!({ "allowed_origins": ["notaurl"] })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Unknown (but well-formed) site_key → 404.
    let uri = format!("/v1/admin/sites/{}/origins", uuid::Uuid::new_v4());
    let (status, _) = admin_req(
        &app,
        "PUT",
        &uri,
        Some(TEST_ADMIN_TOKEN),
        Some(serde_json::json!({ "allowed_origins": ["https://x.example"] })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_admin_rename_site() {
    let (app, store) = test_app_with_store(|b| b.enable_admin = true);
    let site = create_test_site(&app).await;
    let uri = format!("/v1/admin/sites/{}/name", site.site_key);

    let (status, resp) = admin_req(
        &app,
        "PUT",
        &uri,
        Some(TEST_ADMIN_TOKEN),
        Some(serde_json::json!({ "name": "  checkout  " })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // Trimmed, exactly as `POST /v1/sites` would have.
    assert_eq!(resp["name"], "checkout");

    let reloaded = store
        .get_site_by_key(&site.site_key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reloaded.name, "checkout");
    // A rename is a label change, not a re-provisioning: the credentials an
    // integrator already embedded must be untouched.
    assert_eq!(reloaded.secret_key, site.secret_key);
    assert!(
        store
            .get_site_by_secret(&site.secret_key)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn test_admin_rename_site_rejects_bad_input() {
    let (app, _store) = test_app_with_store(|b| b.enable_admin = true);
    let site = create_test_site(&app).await;

    // Invalid UUID in the path → 400.
    let (status, _) = admin_req(
        &app,
        "PUT",
        "/v1/admin/sites/not-a-uuid/name",
        Some(TEST_ADMIN_TOKEN),
        Some(serde_json::json!({ "name": "fine" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Blank name → 400, same rule as provisioning.
    let uri = format!("/v1/admin/sites/{}/name", site.site_key);
    let (status, _) = admin_req(
        &app,
        "PUT",
        &uri,
        Some(TEST_ADMIN_TOKEN),
        Some(serde_json::json!({ "name": "   " })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Over the length cap → 400.
    let (status, _) = admin_req(
        &app,
        "PUT",
        &uri,
        Some(TEST_ADMIN_TOKEN),
        Some(serde_json::json!({ "name": "a".repeat(201) })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Unknown (but well-formed) site_key → 404.
    let uri = format!("/v1/admin/sites/{}/name", uuid::Uuid::new_v4());
    let (status, _) = admin_req(
        &app,
        "PUT",
        &uri,
        Some(TEST_ADMIN_TOKEN),
        Some(serde_json::json!({ "name": "fine" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // No bearer → 401, and the site is not renamed on the way past.
    let uri = format!("/v1/admin/sites/{}/name", site.site_key);
    let (status, _) = admin_req(
        &app,
        "PUT",
        &uri,
        None,
        Some(serde_json::json!({ "name": "hijacked" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_admin_rotate_and_delete_site() {
    let (app, store) = test_app_with_store(|b| b.enable_admin = true);
    let site = create_test_site(&app).await;

    // Rotate: 200 with a new secret; the old one stops resolving.
    let uri = format!("/v1/admin/sites/{}/rotate", site.site_key);
    let (status, resp) = admin_req(&app, "POST", &uri, Some(TEST_ADMIN_TOKEN), None).await;
    assert_eq!(status, StatusCode::OK);
    let new_secret = resp["secret_key"].as_str().unwrap();
    assert_ne!(new_secret, site.secret_key);
    assert!(
        store
            .get_site_by_secret(&site.secret_key)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get_site_by_secret(new_secret)
            .await
            .unwrap()
            .is_some()
    );

    // Delete: 200, then a second delete is 404.
    let uri = format!("/v1/admin/sites/{}", site.site_key);
    let (status, _) = admin_req(&app, "DELETE", &uri, Some(TEST_ADMIN_TOKEN), None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = admin_req(&app, "DELETE", &uri, Some(TEST_ADMIN_TOKEN), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_malformed_query_returns_json_error_envelope() {
    let app = test_app();
    // site_key isn't a UUID → the query extractor rejects → 400 with the JSON
    // envelope, not axum's default plain-text 400.
    let req = Request::builder()
        .method("GET")
        .uri("/v1/puzzle?site_key=not-a-uuid")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        json.get("error").is_some(),
        "expected JSON error envelope, got {json}"
    );
}

#[tokio::test]
async fn test_malformed_verify_body_returns_json_error_envelope() {
    let app = test_app();
    let site = create_test_site(&app).await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", site.secret_key))
        .body(Body::from("this is not json"))
        .unwrap();
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        json.get("error").is_some(),
        "expected JSON error envelope, got {json}"
    );
}

// ── Widget asset bundle ──
//
// The widget, its worker and the vendored Argon2 build are separate cache
// entries that must never be mixed across versions. These cover the contract
// that prevents that: one short-lived entry point naming one immutable,
// content-hashed directory.

/// GET the widget entry point and return `(cache-control, body)`.
async fn fetch_widget_entry(app: &axum::Router) -> (String, String) {
    let req = Request::builder()
        .method("GET")
        .uri("/v1/widget.js")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let cache_control = resp
        .headers()
        .get("cache-control")
        .expect("entry point must declare Cache-Control")
        .to_str()
        .unwrap()
        .to_string();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (cache_control, String::from_utf8(bytes.to_vec()).unwrap())
}

/// Pull the `/assets/<hash>` directory the entry point points at, straight
/// out of the served JavaScript — the same string the browser will use.
///
/// Anchored on the opening quote of the substituted string literal, not on
/// `/assets/` alone: the file's own comments mention the path shape, and
/// matching one of those would silently test a directory nothing loads from.
fn asset_base_from(source: &str) -> String {
    let start = source
        .find("\"/assets/")
        .expect("entry point must name its asset directory")
        + 1;
    let rest = &source[start..];
    let end = rest.find('"').expect("unterminated asset base literal");
    rest[..end].to_string()
}

#[tokio::test]
async fn widget_entry_point_is_short_lived_and_names_its_bundle() {
    let app = test_app();
    let (cache_control, source) = fetch_widget_entry(&app).await;

    assert_eq!(cache_control, "public, max-age=300");
    // The placeholder surviving substitution is the silent failure mode: the
    // widget would fall back to unversioned paths and nothing would error.
    assert!(
        !source.contains("__BOLLWARK_ASSET_BASE__"),
        "asset base placeholder must be substituted before serving"
    );
    assert!(source.contains("/assets/"));
}

#[tokio::test]
async fn hashed_assets_are_served_immutable() {
    let app = test_app();
    let (_, source) = fetch_widget_entry(&app).await;
    let base = asset_base_from(&source);

    for asset in [
        "captcha-worker.js",
        "captcha-widget.css",
        "vendor/argon2.umd.min.js",
    ] {
        let req = Request::builder()
            .method("GET")
            .uri(format!("{base}/{asset}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "{asset} should be served from {base}"
        );
        assert_eq!(
            resp.headers().get("cache-control").unwrap(),
            "public, max-age=31536000, immutable",
            "{asset} is content-addressed and should be cacheable indefinitely"
        );
    }
}

#[tokio::test]
async fn a_stale_asset_hash_is_not_served() {
    let app = test_app();
    // A year-long TTL is only safe if an old hash stops resolving instead of
    // quietly serving whatever the current build has at that filename.
    let req = Request::builder()
        .method("GET")
        .uri("/assets/00000000deadbeef/captcha-worker.js")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn legacy_static_widget_path_still_serves() {
    let app = test_app();
    // Every embed predating /v1/widget.js points here, including the ones on
    // the instance being migrated away from. This path is permanent.
    let req = Request::builder()
        .method("GET")
        .uri("/static/captcha-widget.js")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("cache-control").unwrap(),
        "public, max-age=300",
        "unversioned assets must not be cached beyond the entry point's window"
    );
}

// ── Client failover ───────────────────────────────────────────────────────
//
// A failover claim asserts "I could not reach you at all", so it carries no
// challenge and no proof of work. These tests pin the two things that keep it
// from being a free bypass: it is refused unless the server itself attests an
// outage, and the browser-local evidence is still scored when it is honored.

/// Mint the token the widget produces when `/v1/puzzle` is unreachable.
fn failover_token(site_key: uuid::Uuid, issued_at_ms: i64) -> String {
    failover_token_with(site_key, issued_at_ms, serde_json::Map::new())
}

/// As above, plus any extra fields the widget would have collected locally
/// (honeypot, behaviour blob) — they go inside the token, not beside it.
fn failover_token_with(
    site_key: uuid::Uuid,
    issued_at_ms: i64,
    extras: serde_json::Map<String, serde_json::Value>,
) -> String {
    let mut payload = serde_json::json!({
        "failover": true,
        "site_key": site_key,
        "issued_at": issued_at_ms,
    });
    let obj = payload.as_object_mut().unwrap();
    obj.extend(extras);
    hex::encode(serde_json::to_vec(&payload).unwrap())
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// POST a failover token to `/v1/verify` and return the decoded response.
///
/// Everything the claim carries lives *inside* the token, as the widget emits
/// it — `resolve()` gives the token precedence, so a behaviour blob passed
/// alongside it at the top level would be silently ignored.
async fn post_failover(
    app: &axum::Router,
    secret: &str,
    token: String,
) -> (StatusCode, Option<VerifyResponse>) {
    let body = serde_json::json!({ "token": token });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {secret}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).ok())
}

/// Declare an outage window ending now, as the external monitor would.
async fn declare_outage(app: &axum::Router, duration_secs: u64) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/admin/outages")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {TEST_ADMIN_TOKEN}"))
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({ "duration_secs": duration_secs })).unwrap(),
        ))
        .unwrap();
    app.clone()
        .oneshot(with_connect_info(req))
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn test_failover_claim_refused_without_an_attested_outage() {
    // The whole point: "the captcha was down" is not self-certifying. With
    // failover enabled but nothing attested, the claim must still fail.
    let app = test_app_with(|b| b.enable_failover = true);
    let site = create_test_site(&app).await;

    let (status, body) = post_failover(
        &app,
        &site.secret_key,
        failover_token(site.site_key, now_ms()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let body = body.unwrap();
    assert!(
        !body.success,
        "an unattested failover claim must not pass — otherwise the flag is \
         just an unauthenticated skip-the-puzzle switch"
    );
    assert!(!body.failover);
}

#[tokio::test]
async fn test_failover_claim_honored_inside_a_declared_outage() {
    let app = test_app_with(|b| b.enable_failover = true);
    let site = create_test_site(&app).await;
    assert_eq!(declare_outage(&app, 120).await, StatusCode::OK);

    let (status, body) = post_failover(
        &app,
        &site.secret_key,
        failover_token(site.site_key, now_ms()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let body = body.unwrap();
    assert!(body.success, "attested outage should honor the claim");
    assert!(
        body.failover,
        "an acceptance must be marked so integrators can accept-but-flag \
         instead of treating it as a clean pass"
    );
}

#[tokio::test]
async fn test_failover_disabled_by_default() {
    // Existing deployments must not silently gain a fail-open path on upgrade.
    let app = test_app();
    let site = create_test_site(&app).await;

    let (_, body) = post_failover(
        &app,
        &site.secret_key,
        failover_token(site.site_key, now_ms()),
    )
    .await;
    assert!(!body.unwrap().success);
}

#[tokio::test]
async fn test_failover_claim_for_another_site_is_unauthorized() {
    // The claim names its own site_key; spending another tenant's failover
    // budget with your own secret must not be possible.
    let app = test_app_with(|b| b.enable_failover = true);
    let site = create_test_site(&app).await;
    declare_outage(&app, 120).await;

    let (status, _) = post_failover(
        &app,
        &site.secret_key,
        failover_token(uuid::Uuid::new_v4(), now_ms()),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_failover_still_scores_browser_local_evidence() {
    // An outage is not a reason to stop reading the evidence that survives it.
    // A flatline + webdriver blob blocks at verify-time normally; it must also
    // block on the failover path, inside an attested window.
    let app = test_app_with(|b| b.enable_failover = true);
    let site = create_test_site(&app).await;
    declare_outage(&app, 120).await;

    let mut extras = serde_json::Map::new();
    extras.insert(
        "behavior".into(),
        serde_json::json!({
            "mouse_moves": 0,
            "touches": 0,
            "interactions": 0,
            "webdriver": true,
        }),
    );
    let (_, body) = post_failover(
        &app,
        &site.secret_key,
        failover_token_with(site.site_key, now_ms(), extras),
    )
    .await;
    let body = body.unwrap();
    assert!(
        !body.success,
        "an attested outage must not launder an obviously-automated client"
    );
}

#[tokio::test]
async fn test_failover_honeypot_still_blocks() {
    let app = test_app_with(|b| b.enable_failover = true);
    let site = create_test_site(&app).await;
    declare_outage(&app, 120).await;

    let token = hex::encode(
        serde_json::to_vec(&serde_json::json!({
            "failover": true,
            "site_key": site.site_key,
            "issued_at": now_ms(),
            "honeypot": "filled-by-a-bot",
        }))
        .unwrap(),
    );
    let (_, body) = post_failover(&app, &site.secret_key, token).await;
    assert!(!body.unwrap().success, "honeypot must block on any path");
}

#[tokio::test]
async fn test_failover_backdated_claim_cannot_reopen_a_stale_window() {
    // Declare a window that closed well outside the grace tail, then claim
    // with a timestamp from inside it. Acceptance keys on *now*, not on the
    // client's forgeable `issued_at`, so this must fail.
    let app = test_app_with(|b| b.enable_failover = true);
    let site = create_test_site(&app).await;

    let old_end = chrono::Utc::now() - chrono::Duration::hours(6);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/admin/outages")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {TEST_ADMIN_TOKEN}"))
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "start": old_end - chrono::Duration::minutes(10),
                "end": old_end,
            }))
            .unwrap(),
        ))
        .unwrap();
    assert_eq!(
        app.clone()
            .oneshot(with_connect_info(req))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    let (_, body) = post_failover(
        &app,
        &site.secret_key,
        failover_token(site.site_key, old_end.timestamp_millis()),
    )
    .await;
    assert!(
        !body.unwrap().success,
        "a closed window must not be reopenable by backdating a claim"
    );
}

#[tokio::test]
async fn test_declare_outage_requires_admin_token() {
    let app = test_app_with(|b| b.enable_failover = true);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/admin/outages")
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({ "duration_secs": 60 })).unwrap(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_declare_outage_rejects_an_unbounded_window() {
    // A window far in the future would hold the fail-open open indefinitely —
    // the one mistake here that isn't visible from outside.
    let app = test_app_with(|b| b.enable_failover = true);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/admin/outages")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {TEST_ADMIN_TOKEN}"))
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({ "duration_secs": 60 * 60 * 24 * 30u64 }))
                .unwrap(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_declare_outage_refused_when_failover_is_off() {
    let app = test_app();
    assert_eq!(declare_outage(&app, 60).await, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_solved_verify_is_never_marked_failover() {
    // The response field must distinguish a real solve from a fail-open, or
    // an integrator branching on it learns nothing.
    let (app, store) = test_app_with_store(|b| b.enable_failover = true);
    let site = create_test_site(&app).await;
    let (_, puzzle) = get_test_puzzle(&app, &site.site_key.to_string()).await;
    let puzzle = puzzle.unwrap();
    let nonce = solve_challenge(&puzzle.prefix, puzzle.difficulty);
    backdate_challenge(&store, puzzle.challenge_id, 5).await;

    let verify_body = serde_json::json!({ "challenge_id": puzzle.challenge_id, "nonce": nonce });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", site.secret_key))
        .body(Body::from(serde_json::to_vec(&verify_body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: VerifyResponse = serde_json::from_slice(&bytes).unwrap();
    assert!(body.success);
    assert!(!body.failover, "a real solve must never be marked failover");
}

/// Give a stored challenge a deliberately expensive Argon2id cost so the
/// server-side verify hash runs long enough to observe mid-flight. `t_cost`
/// scales the work linearly at constant memory, which keeps the test cheap in
/// RAM while making it slow in wall-clock — the opposite trade to raising
/// `m_cost`.
async fn make_verify_slow(store: &InMemoryStore, id: uuid::Uuid, t_cost: u32) {
    let mut challenge = store.get_challenge(&id).await.unwrap().unwrap();
    challenge.algorithm = Algorithm::Argon2id(Argon2idParams {
        m_cost: 8_192,
        t_cost,
        p_cost: 1,
    });
    store.store_challenge(&challenge).await.unwrap();
}

/// A cancelled `/v1/verify` must not hand its permit to the next request while
/// its hash is still running.
///
/// `spawn_blocking` tasks cannot be cancelled. When the request future is
/// dropped mid-hash — the request timeout firing, or a caller whose HTTP client
/// gives up early and retries — tokio detaches the blocking task and its
/// ~8 MiB allocation lives until the hash returns. If the permit were released
/// with the future rather than with the hash, a caller retrying faster than the
/// hash completes would over-commit the very bound `verify_permits` exists to
/// enforce, and could push resident memory past it.
///
/// The permit is therefore moved into the blocking closure. This test pins that:
/// with the permit merely held by the future, the first assertion sees the
/// permit already back in the semaphore and fails.
#[tokio::test(flavor = "multi_thread")]
async fn cancelled_verify_holds_its_permit_until_the_hash_finishes() {
    let (app, store, state) = TestAppBuilder {
        algorithm: Some(Algorithm::Argon2id(Argon2idParams::default())),
        // One permit makes the accounting unambiguous: 1 = free, 0 = in use.
        verify_permits: Some(1),
        ..Default::default()
    }
    .build_with_state();

    let site = create_test_site(&app).await;
    let (status, puzzle) = get_test_puzzle(&app, &site.site_key.to_string()).await;
    assert_eq!(status, StatusCode::OK);
    let puzzle = puzzle.unwrap();

    // ~30x the default work, so the hash comfortably outlives the cancellation
    // below even on hardware much faster than the machine this was written on.
    make_verify_slow(&store, puzzle.challenge_id, 64).await;

    assert_eq!(
        state.verify_permits.available_permits(),
        1,
        "permit should be free before the verify starts",
    );

    // The nonce is irrelevant: verify computes the hash before it can know
    // whether the nonce is right, which is the window this test needs.
    let verify_body = serde_json::json!({
        "challenge_id": puzzle.challenge_id,
        "nonce": 1u64,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", site.secret_key))
        .body(Body::from(serde_json::to_vec(&verify_body).unwrap()))
        .unwrap();

    // Dropping this future is what a request timeout or a disconnected caller
    // does to the handler.
    let cancelled = tokio::time::timeout(
        std::time::Duration::from_millis(40),
        app.clone().oneshot(with_connect_info(req)),
    )
    .await;
    assert!(
        cancelled.is_err(),
        "the verify should still have been hashing when it was cancelled — if this \
         fails the challenge cost is too low to exercise the race",
    );

    assert_eq!(
        state.verify_permits.available_permits(),
        0,
        "the detached hash still owns ~8 MiB, so its permit must not be reissued yet",
    );

    // ...and it must come back once the hash finishes, or a cancelled request
    // would leak a permit and the endpoint would wedge after enough of them.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while state.verify_permits.available_permits() == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "permit was never released — a cancelled verify leaks it",
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(state.verify_permits.available_permits(), 1);
}

// --- Per-site policy (SitePolicy) ---

/// Register a site carrying a policy. Returns the provisioning response so a
/// test can assert on the echoed policy as well as use the keys.
async fn create_test_site_with_policy(
    app: &axum::Router,
    policy: serde_json::Value,
) -> CreateSiteResponse {
    let body = serde_json::json!({ "name": "policy site", "policy": policy });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/sites")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {TEST_ADMIN_TOKEN}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// A request missing only the User-Agent header: scores exactly +30 on header
/// anomaly, which is Checkbox under the default bands. Every tier test below
/// works from this fixed score so the policy is the only variable.
fn no_ua_puzzle_request(site_key: &str) -> Request<Body> {
    puzzle_request(site_key, None, Some(CLEAN_LANG), Some(CLEAN_ENC))
}

async fn puzzle_status_and_tier(
    app: &axum::Router,
    req: Request<Body>,
) -> (StatusCode, Option<PuzzleResponse>) {
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).ok())
}

#[tokio::test]
async fn test_site_policy_shifts_the_puzzle_tier() {
    let app = test_app();

    // Same score (+30 header anomaly), two sites, two outcomes.
    let default_site = create_test_site(&app).await;
    let strict_site = create_test_site_with_policy(
        &app,
        serde_json::json!({
            "tier_checkbox_min": 5,
            "tier_hard_pow_min": 10,
            "tier_block_min": 20,
        }),
    )
    .await;

    let (status, puzzle) = puzzle_status_and_tier(
        &app,
        no_ua_puzzle_request(&default_site.site_key.to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(puzzle.unwrap().tier, EscalationTier::Checkbox);

    // The strict site's block band starts at 20, so the same +30 is a 429.
    let (status, _) = puzzle_status_and_tier(
        &app,
        no_ua_puzzle_request(&strict_site.site_key.to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn test_site_policy_overrides_difficulty() {
    let app = test_app();
    let site = create_test_site_with_policy(
        &app,
        // Test config is default 8 / max 16; ask for a distinguishable value.
        serde_json::json!({ "default_difficulty": 12, "max_difficulty": 14 }),
    )
    .await;

    let (status, puzzle) = get_test_puzzle(&app, &site.site_key.to_string()).await;
    assert_eq!(status, StatusCode::OK);
    // Clean request → InvisiblePass → no tier bump, so the base value lands.
    assert_eq!(puzzle.unwrap().difficulty, 12);
}

#[tokio::test]
async fn test_site_policy_max_difficulty_clamps_the_tier_bump() {
    let app = test_app();
    let site = create_test_site_with_policy(
        &app,
        serde_json::json!({ "default_difficulty": 10, "max_difficulty": 11 }),
    )
    .await;

    // +30 header anomaly → Checkbox → +2 bump → 12, clamped to the site's 11.
    let (status, puzzle) =
        puzzle_status_and_tier(&app, no_ua_puzzle_request(&site.site_key.to_string())).await;
    assert_eq!(status, StatusCode::OK);
    let puzzle = puzzle.unwrap();
    assert_eq!(puzzle.tier, EscalationTier::Checkbox);
    assert_eq!(puzzle.difficulty, 11);
}

#[tokio::test]
async fn test_site_policy_overrides_verify_thresholds() {
    let app = test_app();
    // A same-instant submit scores +50 on time-on-page: ShadowFail under the
    // default 30/60 bands (success stays true), Block once the site pulls
    // verify_block_min down to 40.
    let lenient = create_test_site(&app).await;
    let strict =
        create_test_site_with_policy(&app, serde_json::json!({ "verify_block_min": 40 })).await;

    for (site, expected_success) in [(&lenient, true), (&strict, false)] {
        let (_, puzzle) = get_test_puzzle(&app, &site.site_key.to_string()).await;
        let puzzle = puzzle.unwrap();
        let nonce = solve_challenge(&puzzle.prefix, puzzle.difficulty);
        let req = Request::builder()
            .method("POST")
            .uri("/v1/verify")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", site.secret_key))
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "challenge_id": puzzle.challenge_id,
                    "nonce": nonce,
                }))
                .unwrap(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: VerifyResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(result.success, expected_success);
    }
}

#[tokio::test]
async fn test_site_without_policy_is_unchanged() {
    // The regression guard for every pre-existing deployment: a site that
    // omits `policy` must score exactly as it did before policies existed.
    let app = test_app();
    let site = create_test_site(&app).await;
    assert_eq!(
        serde_json::to_value(site.policy).unwrap(),
        serde_json::json!({})
    );

    let (status, puzzle) = get_test_puzzle(&app, &site.site_key.to_string()).await;
    assert_eq!(status, StatusCode::OK);
    let puzzle = puzzle.unwrap();
    assert_eq!(puzzle.tier, EscalationTier::InvisiblePass);
    assert_eq!(puzzle.difficulty, 8); // the test config's DEFAULT_DIFFICULTY
}

#[tokio::test]
async fn test_create_site_rejects_invalid_policy() {
    let app = test_app();
    // Zero difficulty would accept any nonce — every visitor passes the PoW.
    let body = serde_json::json!({
        "name": "bad site",
        "policy": { "default_difficulty": 0 },
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/sites")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {TEST_ADMIN_TOKEN}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_create_site_rejects_policy_that_only_breaks_against_globals() {
    // block_min=10 is fine on its own but sits below the global
    // TIER_CHECKBOX_MIN=20 once merged, making two bands unreachable.
    let app = test_app();
    let body = serde_json::json!({
        "name": "bad site",
        "policy": { "tier_block_min": 10 },
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/sites")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {TEST_ADMIN_TOKEN}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_admin_update_policy_happy_path_and_clear() {
    let (app, store) = test_app_with_store(|b| b.enable_admin = true);
    let site = create_test_site(&app).await;
    let uri = format!("/v1/admin/sites/{}/policy", site.site_key);

    let (status, resp) = admin_req(
        &app,
        "PUT",
        &uri,
        Some(TEST_ADMIN_TOKEN),
        Some(serde_json::json!({ "tier_block_min": 60 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resp["policy"]["tier_block_min"], 60);
    let reloaded = store
        .get_site_by_key(&site.site_key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reloaded.policy.tier_block_min, Some(60));

    // An empty body replaces wholesale, so it clears every override.
    let (status, resp) = admin_req(
        &app,
        "PUT",
        &uri,
        Some(TEST_ADMIN_TOKEN),
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resp["policy"], serde_json::json!({}));
    let reloaded = store
        .get_site_by_key(&site.site_key)
        .await
        .unwrap()
        .unwrap();
    assert!(reloaded.policy.is_empty());
}

#[tokio::test]
async fn test_admin_update_policy_validates_and_404s() {
    let (app, _store) = test_app_with_store(|b| b.enable_admin = true);
    let site = create_test_site(&app).await;

    let (status, _) = admin_req(
        &app,
        "PUT",
        &format!("/v1/admin/sites/{}/policy", site.site_key),
        Some(TEST_ADMIN_TOKEN),
        Some(serde_json::json!({ "verify_block_min": 0 })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = admin_req(
        &app,
        "PUT",
        &format!("/v1/admin/sites/{}/policy", uuid::Uuid::new_v4()),
        Some(TEST_ADMIN_TOKEN),
        Some(serde_json::json!({ "tier_block_min": 60 })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = admin_req(
        &app,
        "PUT",
        &format!("/v1/admin/sites/{}/policy", site.site_key),
        None,
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_admin_list_sites_includes_policy() {
    let (app, _store) = test_app_with_store(|b| b.enable_admin = true);
    create_test_site_with_policy(&app, serde_json::json!({ "tier_block_min": 60 })).await;

    let (status, body) =
        admin_req(&app, "GET", "/v1/admin/sites", Some(TEST_ADMIN_TOKEN), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["sites"][0]["policy"]["tier_block_min"], 60);
}

#[tokio::test]
async fn test_admin_update_policy_takes_effect_immediately() {
    // The knob has to bite on the next request, not on restart — otherwise
    // tuning a live site under attack is useless.
    let (app, _store) = test_app_with_store(|b| b.enable_admin = true);
    let site = create_test_site(&app).await;
    let key = site.site_key.to_string();

    let (status, _) = puzzle_status_and_tier(&app, no_ua_puzzle_request(&key)).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = admin_req(
        &app,
        "PUT",
        &format!("/v1/admin/sites/{}/policy", site.site_key),
        Some(TEST_ADMIN_TOKEN),
        Some(serde_json::json!({
            "tier_checkbox_min": 5,
            "tier_hard_pow_min": 10,
            "tier_block_min": 20,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = puzzle_status_and_tier(&app, no_ua_puzzle_request(&key)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

// --- Monitor mode (SiteMode::Monitor) ---

/// Thresholds low enough that the fixed +30 header anomaly of
/// `no_ua_puzzle_request` lands in the Block band, so the only variable
/// between the enforce and monitor cases is the mode.
fn blocking_policy(mode: Option<&str>) -> serde_json::Value {
    let mut p = serde_json::json!({
        "tier_checkbox_min": 5,
        "tier_hard_pow_min": 10,
        "tier_block_min": 20,
    });
    if let Some(m) = mode {
        p["mode"] = serde_json::json!(m);
    }
    p
}

#[tokio::test]
async fn test_monitor_mode_issues_a_puzzle_where_enforce_would_429() {
    let app = test_app();
    let enforcing = create_test_site_with_policy(&app, blocking_policy(None)).await;
    let monitoring = create_test_site_with_policy(&app, blocking_policy(Some("monitor"))).await;

    let (status, _) =
        puzzle_status_and_tier(&app, no_ua_puzzle_request(&enforcing.site_key.to_string())).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    // Same score, same bands — the monitored site gets a puzzle instead, at
    // the max difficulty, since "observe don't refuse" still means the
    // strongest non-blocking response.
    let (status, puzzle) =
        puzzle_status_and_tier(&app, no_ua_puzzle_request(&monitoring.site_key.to_string())).await;
    assert_eq!(status, StatusCode::OK);
    let puzzle = puzzle.unwrap();
    assert_eq!(puzzle.difficulty, 16); // the test config's MAX_DIFFICULTY
    // The client is told what it must actually solve. A `block` tier carrying
    // a puzzle would be incoherent to the widget.
    assert_eq!(puzzle.tier, EscalationTier::HardPow);
}

#[tokio::test]
async fn test_monitor_mode_passes_a_verify_that_would_block() {
    let app = test_app();
    // A tripped honeypot scores +100 — unambiguously past any block threshold.
    for (mode, expected_success) in [(None, false), (Some("monitor"), true)] {
        let site = create_test_site_with_policy(
            &app,
            match mode {
                Some(m) => serde_json::json!({ "mode": m }),
                None => serde_json::json!({}),
            },
        )
        .await;
        let (_, puzzle) = get_test_puzzle(&app, &site.site_key.to_string()).await;
        let puzzle = puzzle.unwrap();
        let nonce = solve_challenge(&puzzle.prefix, puzzle.difficulty);

        let req = Request::builder()
            .method("POST")
            .uri("/v1/verify")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", site.secret_key))
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "challenge_id": puzzle.challenge_id,
                    "nonce": nonce,
                    "honeypot": "spam@example.com",
                }))
                .unwrap(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: VerifyResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            result.success, expected_success,
            "honeypot under mode {mode:?}"
        );
        // The band is the verdict and does not change with the mode; a
        // monitored site is exactly `success: true` next to `risk: high`.
        assert_eq!(
            result.risk,
            Some(RiskBand::High),
            "band under mode {mode:?}"
        );
    }
}

#[tokio::test]
async fn test_monitor_mode_does_not_disable_the_load_shed() {
    // The safety property: monitoring is scoped to *risk* verdicts. The
    // challenge-map ceiling protects every other tenant on the instance, so a
    // monitored site must still be shed when the map is full — otherwise one
    // customer left in observe mode can exhaust memory for all of them.
    let app = test_app_with(|b| b.max_active_challenges = Some(1));
    let site = create_test_site_with_policy(&app, serde_json::json!({ "mode": "monitor" })).await;
    let key = site.site_key.to_string();

    // First request fills the map to the ceiling.
    let (status, _) = get_test_puzzle(&app, &key).await;
    assert_eq!(status, StatusCode::OK);

    // Second is over capacity: 429 despite monitor mode, and despite this
    // request's own score being clean.
    let (status, _) = get_test_puzzle(&app, &key).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn test_monitor_mode_does_not_excuse_an_invalid_pow() {
    // A wrong nonce is a failed proof, not a judgement about the visitor —
    // there is nothing to "observe rather than enforce".
    let app = test_app();
    let site = create_test_site_with_policy(&app, serde_json::json!({ "mode": "monitor" })).await;
    let (_, puzzle) = get_test_puzzle(&app, &site.site_key.to_string()).await;
    let puzzle = puzzle.unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", site.secret_key))
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "challenge_id": puzzle.challenge_id,
                "nonce": 1u64, // almost certainly not a solution
            }))
            .unwrap(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: VerifyResponse = serde_json::from_slice(&bytes).unwrap();
    assert!(!result.success);
}

#[tokio::test]
async fn test_monitor_mode_can_be_toggled_without_rotating_the_secret() {
    // The onboarding flow: run a live site in observe mode, then enforce.
    let (app, _store) = test_app_with_store(|b| b.enable_admin = true);
    let site = create_test_site_with_policy(&app, blocking_policy(Some("monitor"))).await;
    let key = site.site_key.to_string();

    let (status, _) = puzzle_status_and_tier(&app, no_ua_puzzle_request(&key)).await;
    assert_eq!(status, StatusCode::OK);

    let (status, resp) = admin_req(
        &app,
        "PUT",
        &format!("/v1/admin/sites/{}/policy", site.site_key),
        Some(TEST_ADMIN_TOKEN),
        Some(blocking_policy(Some("enforce"))),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resp["policy"]["mode"], "enforce");

    let (status, _) = puzzle_status_and_tier(&app, no_ua_puzzle_request(&key)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

// --- Dwell anchor across a pre-expiry refresh (`refresh_of`) ---

/// Fetch a puzzle citing a prior challenge, as the widget's pre-expiry
/// refresh does.
async fn get_refreshed_puzzle(
    app: &axum::Router,
    site_key: &str,
    refresh_of: uuid::Uuid,
) -> (StatusCode, Option<PuzzleResponse>) {
    let uri = format!("/v1/puzzle?site_key={site_key}&refresh_of={refresh_of}");
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("User-Agent", CLEAN_UA)
        .header("Accept-Language", CLEAN_LANG)
        .header("Accept-Encoding", CLEAN_ENC)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).ok())
}

/// Solve a puzzle and verify it immediately, returning `success`.
async fn solve_and_verify_now(
    app: &axum::Router,
    site: &CreateSiteResponse,
    puzzle: &PuzzleResponse,
) -> bool {
    let nonce = solve_challenge(&puzzle.prefix, puzzle.difficulty);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", site.secret_key))
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "challenge_id": puzzle.challenge_id,
                "nonce": nonce,
            }))
            .unwrap(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice::<VerifyResponse>(&bytes)
        .unwrap()
        .success
}

#[tokio::test]
async fn test_refresh_carries_the_dwell_anchor() {
    // The load-bearing pair. A site strict enough that the <500ms band alone
    // decides the outcome, so the only variable is where dwell is anchored.
    let (app, store) = test_app_with_store(|_| {});
    let site =
        create_test_site_with_policy(&app, serde_json::json!({ "verify_block_min": 50 })).await;
    let key = site.site_key.to_string();

    // Without a refresh: fresh challenge, immediate submit → +50 → blocked.
    let (_, fresh) = get_test_puzzle(&app, &key).await;
    let fresh = fresh.unwrap();
    assert!(
        !solve_and_verify_now(&app, &site, &fresh).await,
        "an immediate submit on a fresh challenge must still trip the fast-submit band"
    );

    // With a refresh: the visitor has been on the form for 10s, the widget
    // refreshes, they submit at once. The dwell is theirs, not the refresh's.
    let (_, original) = get_test_puzzle(&app, &key).await;
    let original = original.unwrap();
    backdate_challenge(&store, original.challenge_id, 10).await;

    let (status, refreshed) = get_refreshed_puzzle(&app, &key, original.challenge_id).await;
    assert_eq!(status, StatusCode::OK);
    let refreshed = refreshed.unwrap();
    assert_ne!(refreshed.challenge_id, original.challenge_id);
    assert!(
        solve_and_verify_now(&app, &site, &refreshed).await,
        "a refresh must not reset the visitor's dwell clock"
    );
}

#[tokio::test]
async fn test_refresh_of_another_sites_challenge_is_ignored() {
    // The citation is a proof of possession scoped to one site. Honouring a
    // cross-site id would let any tenant mint aged anchors from another's.
    let (app, store) = test_app_with_store(|_| {});
    let victim = create_test_site(&app).await;
    let attacker =
        create_test_site_with_policy(&app, serde_json::json!({ "verify_block_min": 50 })).await;

    let (_, aged) = get_test_puzzle(&app, &victim.site_key.to_string()).await;
    let aged = aged.unwrap();
    backdate_challenge(&store, aged.challenge_id, 60).await;

    let (status, puzzle) =
        get_refreshed_puzzle(&app, &attacker.site_key.to_string(), aged.challenge_id).await;
    // Still issued — a bad citation is ignored, never an error.
    assert_eq!(status, StatusCode::OK);
    assert!(
        !solve_and_verify_now(&app, &attacker, &puzzle.unwrap()).await,
        "a cross-site citation must not confer a backdated dwell anchor"
    );
}

#[tokio::test]
async fn test_unknown_refresh_of_is_ignored_not_an_error() {
    // Stale or already-consumed ids are routine: a visitor whose challenge
    // expired between refreshes must get a normal puzzle, not a failure.
    let app = test_app();
    let site = create_test_site(&app).await;
    let (status, puzzle) =
        get_refreshed_puzzle(&app, &site.site_key.to_string(), uuid::Uuid::new_v4()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(puzzle.is_some());
}

#[tokio::test]
async fn test_refresh_chain_keeps_the_original_anchor() {
    // A long-lived form refreshes repeatedly. Propagating `dwell_since` (not
    // `created_at`) is what keeps every link pointing at the visitor's
    // arrival rather than at the previous refresh.
    let (app, store) = test_app_with_store(|_| {});
    let site =
        create_test_site_with_policy(&app, serde_json::json!({ "verify_block_min": 50 })).await;
    let key = site.site_key.to_string();

    let (_, first) = get_test_puzzle(&app, &key).await;
    let first = first.unwrap();
    backdate_challenge(&store, first.challenge_id, 30).await;

    let (_, second) = get_refreshed_puzzle(&app, &key, first.challenge_id).await;
    let second = second.unwrap();
    let (_, third) = get_refreshed_puzzle(&app, &key, second.challenge_id).await;
    let third = third.unwrap();

    assert!(
        solve_and_verify_now(&app, &site, &third).await,
        "the anchor must survive a chain of refreshes, not just one"
    );
}

#[tokio::test]
async fn test_refresh_does_not_consume_the_cited_challenge() {
    // A submit can race the refresh: the widget refreshes 60s before expiry
    // while the visitor is mid-submit. If the citation deleted the old
    // challenge, that honest verification would 404.
    let app = test_app();
    let site = create_test_site(&app).await;
    let key = site.site_key.to_string();

    let (_, original) = get_test_puzzle(&app, &key).await;
    let original = original.unwrap();
    let (status, _) = get_refreshed_puzzle(&app, &key, original.challenge_id).await;
    assert_eq!(status, StatusCode::OK);

    // The cited challenge is still solvable.
    assert!(solve_and_verify_now(&app, &site, &original).await);
}
