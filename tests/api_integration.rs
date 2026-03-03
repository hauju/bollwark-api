use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use rust_captcha::api;
use rust_captcha::api::state::AppState;
use rust_captcha::api::types::{CreateSiteResponse, PuzzleResponse, VerifyResponse};
use rust_captcha::config::AppConfig;
use rust_captcha::puzzle::challenge::{PuzzleEngine, solve_challenge};
use rust_captcha::puzzle::difficulty::DifficultyCalculator;
use rust_captcha::puzzle::types::PuzzleConfig;
use rust_captcha::storage::memory::InMemoryStore;

fn test_app() -> axum::Router {
    let config = AppConfig {
        default_difficulty: 8,
        min_difficulty: 4,
        max_difficulty: 16,
        challenge_ttl_secs: 300,
        ..AppConfig::default()
    };

    let puzzle_config = PuzzleConfig {
        default_difficulty: 8,
        min_difficulty: 4,
        max_difficulty: 16,
        ttl_secs: 300,
    };

    let state = Arc::new(AppState {
        store: Arc::new(InMemoryStore::new()),
        engine: PuzzleEngine::new(puzzle_config),
        difficulty: DifficultyCalculator::new(&config),
        config,
    });

    api::router(state)
}

fn with_connect_info(req: Request<Body>) -> Request<Body> {
    let (mut parts, body) = req.into_parts();
    let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
    parts.extensions.insert(axum::extract::ConnectInfo(addr));
    Request::from_parts(parts, body)
}

async fn create_test_site(app: &axum::Router) -> CreateSiteResponse {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/sites")
        .header("Content-Type", "application/json")
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
    let req = Request::builder()
        .method("GET")
        .uri(format!("/v1/puzzle?site_key={site_key}"))
        .body(Body::empty())
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
        .body(Body::from(r#"{"name":""}"#))
        .unwrap();

    let resp = app.clone().oneshot(with_connect_info(req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
