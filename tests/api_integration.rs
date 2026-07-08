use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use bollwark::api;
use bollwark::api::state::{AppState, tier_thresholds_from_config, verify_thresholds_from_config};
use bollwark::api::types::{CreateSiteResponse, PuzzleResponse, VerifyResponse};
use bollwark::config::AppConfig;
use bollwark::puzzle::challenge::{
    PuzzleEngine, compute_argon2id, has_leading_zero_bits, solve_argon2id_challenge,
    solve_challenge,
};
use bollwark::puzzle::difficulty::DifficultyCalculator;
use bollwark::puzzle::types::{Algorithm, Argon2idParams, PuzzleConfig};
use bollwark::risk::{
    CidrListReputation, EscalationTier, FingerprintBlocklist, ReputationStore, RiskScorer,
    TrustedProxies, VerifyScorer,
};
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

/// Move a stored challenge's `created_at` back by `secs` so the verify-time
/// time-on-page signal sees a realistic elapsed time instead of the ~0ms gap
/// between issuing and verifying in a test.
async fn backdate_challenge(store: &InMemoryStore, id: uuid::Uuid, secs: i64) {
    use bollwark::storage::Store;
    let mut challenge = store.get_challenge(&id).await.unwrap().unwrap();
    challenge.created_at -= chrono::Duration::seconds(secs);
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
    /// Override the admin token. Default is the constant `TEST_ADMIN_TOKEN`,
    /// which `create_test_site` sends as a bearer to satisfy the gate.
    /// Set to `Some(None)` to disable the token entirely (so `/v1/sites`
    /// returns 404).
    admin_token: Option<Option<&'static str>>,
}

const TEST_ADMIN_TOKEN: &str = "test-admin-token-32bytes-of-entropy";

impl TestAppBuilder {
    fn build(self) -> axum::Router {
        self.build_with_store().0
    }

    fn build_with_store(self) -> (axum::Router, Arc<InMemoryStore>) {
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
            min_difficulty: 1,
            max_difficulty: 16,
            load_ladder,
            challenge_ttl_secs: 300,
            tls_fingerprint_header: self.tls_header.map(String::from),
            ..AppConfig::default()
        };
        let puzzle_config = PuzzleConfig {
            algorithm: config.puzzle_algorithm,
            default_difficulty: config.default_difficulty,
            min_difficulty: config.min_difficulty,
            max_difficulty: config.max_difficulty,
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
        let risk = RiskScorer::new(
            tier_thresholds_from_config(&config),
            reputation,
            tls_blocklist,
        );
        let verify_scorer = VerifyScorer::new(verify_thresholds_from_config(&config));
        let admin_token = match self.admin_token {
            Some(None) => None,
            Some(Some(t)) => Some(Arc::new(t.to_string())),
            None => Some(Arc::new(TEST_ADMIN_TOKEN.to_string())),
        };
        let store = Arc::new(InMemoryStore::new());
        let state = Arc::new(AppState {
            store: store.clone(),
            engine: PuzzleEngine::new(puzzle_config),
            difficulty: DifficultyCalculator::new(&config),
            risk,
            verify_scorer,
            tls_fingerprint_header: self.tls_header.map(String::from),
            trusted_proxies,
            decision_log: None,
            admin_token,
            info_urls: None,
            config,
        });
        (api::router(state, None), store)
    }
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
/// Pass `None` for a header to omit it entirely.
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

    builder.body(Body::empty()).unwrap()
}

const CLEAN_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15";
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
    // ShadowFail returns success: true (caller doesn't see it; only the log does)
    assert!(result.success, "shadow-fail still returns success=true");
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
