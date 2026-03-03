use std::net::IpAddr;

use axum::Json;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;

use crate::error::CaptchaError;
use crate::site::types::Site;
use crate::storage::Store;

use super::state::SharedState;
use super::types::*;

pub async fn get_puzzle(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Query(params): Query<GetPuzzleParams>,
) -> Result<Json<PuzzleResponse>, CaptchaError> {
    // Validate site key exists
    state
        .store
        .get_site_by_key(&params.site_key)
        .await?
        .ok_or(CaptchaError::InvalidSiteKey)?;

    // Get rate counters for adaptive difficulty
    let ip: IpAddr = addr.ip();

    let ip_count = state.store.increment_ip_count(&ip).await?;
    let site_count = state.store.increment_site_count(&params.site_key).await?;

    let difficulty = state.difficulty.compute(ip_count, site_count);
    let challenge = state.engine.generate(params.site_key, difficulty);

    let response = PuzzleResponse {
        challenge_id: challenge.id,
        algorithm: challenge.algorithm,
        prefix: challenge.prefix.clone(),
        difficulty: challenge.difficulty,
        expires_at: challenge.expires_at.to_rfc3339(),
    };

    state.store.store_challenge(&challenge).await?;

    Ok(Json(response))
}

pub async fn verify(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, CaptchaError> {
    // Extract and validate bearer token
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(CaptchaError::Unauthorized)?;

    state
        .store
        .get_site_by_secret(token)
        .await?
        .ok_or(CaptchaError::Unauthorized)?;

    // Look up challenge
    let challenge = state
        .store
        .get_challenge(&body.challenge_id)
        .await?
        .ok_or(CaptchaError::ChallengeNotFound)?;

    // Check expiry
    if challenge.expires_at < chrono::Utc::now() {
        state.store.delete_challenge(&challenge.id).await?;
        return Err(CaptchaError::ChallengeExpired);
    }

    // Check replay
    if challenge.solved {
        return Err(CaptchaError::ChallengeAlreadyUsed);
    }

    // Verify proof-of-work
    let valid = state.engine.verify(&challenge, body.nonce);

    if valid {
        state.store.mark_solution_used(&challenge.id).await?;
        state.store.delete_challenge(&challenge.id).await?;
    }

    Ok(Json(VerifyResponse { success: valid }))
}

pub async fn create_site(
    State(state): State<SharedState>,
    Json(body): Json<CreateSiteRequest>,
) -> Result<Json<CreateSiteResponse>, CaptchaError> {
    if body.name.trim().is_empty() {
        return Err(CaptchaError::BadRequest("name is required".into()));
    }

    let site_key = uuid::Uuid::new_v4();
    let secret_key = hex::encode(rand::random::<[u8; 32]>());

    let site = Site {
        site_key,
        secret_key: secret_key.clone(),
        name: body.name,
        created_at: chrono::Utc::now(),
    };

    state.store.store_site(&site).await?;

    Ok(Json(CreateSiteResponse {
        site_key,
        secret_key,
    }))
}
