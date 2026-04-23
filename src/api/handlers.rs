use std::net::IpAddr;

use axum::Json;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE, HeaderValue, SET_COOKIE};
use axum::response::IntoResponse;

use crate::error::CaptchaError;
use crate::risk::cookie::{extract_cookie, now_secs, set_cookie_header};
use crate::risk::{CookiePresence, SignalContext, difficulty_for};
use crate::site::types::Site;
use crate::storage::Store;

use super::state::SharedState;
use super::types::*;

pub async fn get_puzzle(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<GetPuzzleParams>,
) -> Result<axum::response::Response, CaptchaError> {
    // Validate site key exists
    state
        .store
        .get_site_by_key(&params.site_key)
        .await?
        .ok_or(CaptchaError::InvalidSiteKey)?;

    // Get rate counters (feeds the rate signal)
    let ip: IpAddr = addr.ip();
    let ip_count = state.store.increment_ip_count(&ip).await?;
    let site_count = state.store.increment_site_count(&params.site_key).await?;

    // Trust cookie: if signing is configured, read & verify the existing cookie
    // and feed its age into the score. Issue a fresh cookie when missing/invalid.
    let now = now_secs();
    let mut cookie = CookiePresence::Disabled;
    let mut new_cookie_token: Option<String> = None;

    if let Some(signer) = &state.cookie_signer {
        let existing = headers
            .get(COOKIE)
            .and_then(|v| v.to_str().ok())
            .and_then(extract_cookie);
        match existing.and_then(|t| signer.verify(t, now)) {
            Some(issued_at) => {
                cookie = CookiePresence::Present(now.saturating_sub(issued_at));
            }
            None => {
                cookie = CookiePresence::Missing;
                new_cookie_token = Some(signer.issue(now));
            }
        }
    }

    // Score the request and pick an escalation tier
    let ctx = SignalContext {
        ip,
        headers: &headers,
        ip_count,
        site_count,
        cookie,
    };
    let score = state.risk.score(&ctx);

    tracing::info!(
        ip = %ip,
        site_key = %params.site_key,
        risk.score = score.total,
        risk.tier = ?score.tier,
        signals.rate = score.breakdown.rate,
        signals.header_anomaly = score.breakdown.header_anomaly,
        signals.ip_reputation = score.breakdown.ip_reputation,
        signals.cookie_age = score.breakdown.cookie_age,
        cookie.presence = ?cookie,
        "Risk scored"
    );

    // Tiers that don't issue a puzzle short-circuit here.
    let Some(difficulty) = difficulty_for(
        score.tier,
        state.config.default_difficulty,
        state.config.max_difficulty,
    ) else {
        // VisualChallenge and Block both reject in Phase 1.
        return Err(CaptchaError::RateLimited);
    };

    let challenge = state.engine.generate(params.site_key, difficulty);

    let response = PuzzleResponse {
        challenge_id: challenge.id,
        algorithm: challenge.algorithm,
        prefix: challenge.prefix.clone(),
        difficulty: challenge.difficulty,
        expires_at: challenge.expires_at.to_rfc3339(),
        tier: score.tier,
    };

    state.store.store_challenge(&challenge).await?;

    let mut response_headers = HeaderMap::new();
    if let Some(token) = new_cookie_token {
        let cookie = set_cookie_header(&token, state.config.cookie_secure);
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            response_headers.insert(SET_COOKIE, value);
        }
    }

    Ok((response_headers, Json(response)).into_response())
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

    // Honeypot: any non-empty value is an instant fail. Bots that scrape the
    // widget DOM and fill every input will populate this. Real users never see it.
    if body.honeypot.as_deref().is_some_and(|s| !s.is_empty()) {
        tracing::info!("Verify rejected: honeypot tripped");
        return Ok(Json(VerifyResponse { success: false }));
    }

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
    let pow_valid = state.engine.verify(&challenge, body.nonce);

    if !pow_valid {
        return Ok(Json(VerifyResponse { success: false }));
    }

    // Mark challenge as used
    state.store.mark_solution_used(&challenge.id).await?;
    state.store.delete_challenge(&challenge.id).await?;

    Ok(Json(VerifyResponse { success: true }))
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
