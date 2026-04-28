use std::net::IpAddr;

use axum::Json;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE, HeaderValue, SET_COOKIE, USER_AGENT};
use axum::response::IntoResponse;

use crate::config::CookieSameSiteCfg;
use crate::dashboard::types::{PuzzleRecord, VerifyRecord};
use crate::error::CaptchaError;
use crate::risk::cookie::{CookieSameSite, extract_cookie, now_secs, set_cookie_header};
use crate::risk::{
    BehaviorPresence, CookiePresence, SignalContext, TlsFingerprint, VerifyContext, VerifyDecision,
    client_ip, difficulty_for,
};
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

    // Resolve the client IP. Behind a reverse proxy in TRUSTED_PROXIES we
    // walk X-Forwarded-For; otherwise the TCP peer is authoritative.
    let peer: IpAddr = addr.ip();
    let ip = client_ip(peer, &headers, &state.trusted_proxies);

    // Get rate counters (feeds the rate signal)
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

    // TLS fingerprint: only honor the header when the immediate peer is in
    // the trusted-proxies CIDR. Direct clients can otherwise spoof the value.
    let tls_fingerprint = match (
        &state.tls_fingerprint_header,
        state.trusted_proxies.contains(peer),
    ) {
        (Some(header_name), true) => match headers.get(header_name).and_then(|v| v.to_str().ok()) {
            Some(value) if !value.is_empty() => TlsFingerprint::Provided(value),
            _ => TlsFingerprint::Skipped,
        },
        _ => TlsFingerprint::Skipped,
    };

    // Score the request and pick an escalation tier
    let ctx = SignalContext {
        ip,
        headers: &headers,
        ip_count,
        site_count,
        cookie,
        tls_fingerprint,
    };
    let score = state.risk.score(&ctx);

    // Tiers that don't issue a puzzle short-circuit here.
    let maybe_difficulty = difficulty_for(
        score.tier,
        state.config.default_difficulty,
        state.config.max_difficulty,
    );
    let outcome = if maybe_difficulty.is_some() {
        "issued"
    } else {
        "rejected"
    };

    tracing::info!(
        event = "puzzle_decision",
        outcome = outcome,
        ip = %ip,
        site_key = %params.site_key,
        ip_count,
        site_count,
        score = score.total,
        tier = ?score.tier,
        difficulty = maybe_difficulty.unwrap_or(0),
        sig_rate = score.breakdown.rate,
        sig_header_anomaly = score.breakdown.header_anomaly,
        sig_ip_reputation = score.breakdown.ip_reputation,
        sig_cookie_age = score.breakdown.cookie_age,
        sig_tls_fingerprint = score.breakdown.tls_fingerprint,
        cookie_presence = ?cookie,
        tls_fingerprint = ?tls_fingerprint,
        "Puzzle decision"
    );

    // Snapshot the User-Agent for the dashboard before we hit any branch
    // that returns. The header may be missing — that's fine, it still scores.
    let ua = headers
        .get(USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let Some(difficulty) = maybe_difficulty else {
        // VisualChallenge and Block both reject in Phase 1.
        if let Some(log) = &state.decision_log {
            log.record_puzzle(PuzzleRecord {
                challenge_id: None,
                site_key: params.site_key,
                ip: ip.to_string(),
                ip_count,
                site_count,
                score: score.total,
                tier: score.tier,
                difficulty: 0,
                outcome: "rejected",
                breakdown: score.breakdown,
                cookie_presence: format!("{cookie:?}"),
                tls_fingerprint: format!("{tls_fingerprint:?}"),
                user_agent: ua,
            });
        }
        return Err(CaptchaError::RateLimited);
    };

    let challenge = state.engine.generate(params.site_key, difficulty);

    if let Some(log) = &state.decision_log {
        log.record_puzzle(PuzzleRecord {
            challenge_id: Some(challenge.id),
            site_key: params.site_key,
            ip: ip.to_string(),
            ip_count,
            site_count,
            score: score.total,
            tier: score.tier,
            difficulty,
            outcome: "issued",
            breakdown: score.breakdown,
            cookie_presence: format!("{cookie:?}"),
            tls_fingerprint: format!("{tls_fingerprint:?}"),
            user_agent: ua,
        });
    }

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
        let same_site = match state.config.cookie_samesite {
            CookieSameSiteCfg::Lax => CookieSameSite::Lax,
            CookieSameSiteCfg::None => CookieSameSite::None,
        };
        let cookie = set_cookie_header(&token, state.config.cookie_secure, same_site);
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
        tracing::info!(
            event = "verify_decision",
            outcome = "pow_invalid",
            challenge_id = %challenge.id,
            success = false,
            "Verify decision"
        );
        if let Some(log) = &state.decision_log {
            log.record_verify(VerifyRecord {
                challenge_id: challenge.id,
                success: false,
                outcome: "pow_invalid",
                score: 0,
                breakdown: Default::default(),
                time_on_page_ms: body.time_on_page_ms,
                cookie_presence: "Unknown".into(),
                webdriver: "n/a",
            });
        }
        return Ok(Json(VerifyResponse { success: false }));
    }

    // Mark challenge as used (PoW solved correctly)
    state.store.mark_solution_used(&challenge.id).await?;
    state.store.delete_challenge(&challenge.id).await?;

    // Verify-time risk scoring: time-on-page, cookie age at verify, honeypot.
    // The decision can promote a PoW-valid request to ShadowFail (success=true,
    // logged) or Block (success=false) based on behavioral signals.
    let now = now_secs();
    let cookie = if let Some(signer) = &state.cookie_signer {
        let token = headers
            .get(axum::http::header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .and_then(extract_cookie);
        match token.and_then(|t| signer.verify(t, now)) {
            Some(issued_at) => CookiePresence::Present(now.saturating_sub(issued_at)),
            None => CookiePresence::Missing,
        }
    } else {
        CookiePresence::Disabled
    };

    let honeypot_tripped = body.honeypot.as_deref().is_some_and(|s| !s.is_empty());
    let behavior = match body.behavior {
        Some(report) => BehaviorPresence::Present(report),
        None => BehaviorPresence::Absent,
    };
    let vctx = VerifyContext {
        honeypot_tripped,
        time_on_page_ms: body.time_on_page_ms,
        cookie,
        behavior,
    };
    let vscore = state.verify_scorer.score(&vctx);

    let (success, outcome) = match vscore.decision {
        VerifyDecision::Pass => (true, "pass"),
        VerifyDecision::ShadowFail => (true, "shadow_fail"),
        VerifyDecision::Block => (false, "block"),
    };

    // Surface the raw webdriver flag for log analysis: the aggregate
    // `sig_behavior` score doesn't tell you which sub-signal contributed,
    // and webdriver is the most operationally-interesting one.
    let webdriver_flag = match body.behavior {
        Some(b) => match b.webdriver {
            Some(true) => "true",
            Some(false) => "false",
            None => "absent",
        },
        None => "no_blob",
    };

    macro_rules! emit_decision {
        ($lvl:expr) => {
            tracing::event!(
                $lvl,
                event = "verify_decision",
                outcome = outcome,
                challenge_id = %challenge.id,
                success = success,
                score = vscore.total,
                sig_honeypot = vscore.breakdown.honeypot,
                sig_time_on_page = vscore.breakdown.time_on_page,
                sig_cookie_age = vscore.breakdown.cookie_age,
                sig_behavior = vscore.breakdown.behavior,
                webdriver = webdriver_flag,
                time_on_page_ms = body.time_on_page_ms.unwrap_or(0),
                cookie_presence = ?cookie,
                "Verify decision"
            )
        };
    }
    match vscore.decision {
        VerifyDecision::ShadowFail => emit_decision!(tracing::Level::WARN),
        _ => emit_decision!(tracing::Level::INFO),
    }

    if let Some(log) = &state.decision_log {
        log.record_verify(VerifyRecord {
            challenge_id: challenge.id,
            success,
            outcome,
            score: vscore.total,
            breakdown: vscore.breakdown,
            time_on_page_ms: body.time_on_page_ms,
            cookie_presence: format!("{cookie:?}"),
            webdriver: webdriver_flag,
        });
    }

    Ok(Json(VerifyResponse { success }))
}

pub async fn create_site(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<CreateSiteRequest>,
) -> Result<Json<CreateSiteResponse>, CaptchaError> {
    require_admin_token(&state, &headers)?;

    let name = body.name.trim();
    if name.is_empty() {
        return Err(CaptchaError::BadRequest("name is required".into()));
    }
    if name.len() > 200 {
        return Err(CaptchaError::BadRequest(
            "name must be 200 characters or fewer".into(),
        ));
    }

    let site_key = uuid::Uuid::new_v4();
    let secret_key = hex::encode(rand::random::<[u8; 32]>());

    let site = Site {
        site_key,
        secret_key: secret_key.clone(),
        name: name.to_string(),
        created_at: chrono::Utc::now(),
    };

    state.store.store_site(&site).await?;

    Ok(Json(CreateSiteResponse {
        site_key,
        secret_key,
    }))
}

/// Validate the `Authorization: Bearer <token>` header against the configured
/// admin token. Returns `NotFound` (not `Unauthorized`) when the admin token
/// isn't set so the endpoint's existence isn't disclosed in unprotected
/// deployments. Token comparison is length-then-constant-time.
fn require_admin_token(state: &SharedState, headers: &HeaderMap) -> Result<(), CaptchaError> {
    // Dev escape hatch: when DEV_DISABLE_ADMIN_AUTH=1 in a debug build, skip
    // the bearer check entirely so e2e and the testsite can call /v1/sites
    // anonymously. main.rs ignores the flag in release builds, but we
    // re-check `cfg!(debug_assertions)` here so this can never bypass auth
    // in a release binary even if the field is somehow true.
    if state.config.dev_disable_admin_auth && cfg!(debug_assertions) {
        return Ok(());
    }
    let Some(expected) = state.admin_token.as_ref() else {
        return Err(CaptchaError::NotFound);
    };
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(CaptchaError::Unauthorized)?;
    let a = token.as_bytes();
    let b = expected.as_bytes();
    if a.len() != b.len() {
        return Err(CaptchaError::Unauthorized);
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    if diff == 0 {
        Ok(())
    } else {
        Err(CaptchaError::Unauthorized)
    }
}
