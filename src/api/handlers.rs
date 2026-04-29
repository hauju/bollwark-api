use std::net::IpAddr;

use axum::Json;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::http::header::{AUTHORIZATION, COOKIE, HeaderValue, SET_COOKIE, USER_AGENT};
use axum::response::IntoResponse;

use crate::config::CookieSameSiteCfg;
use crate::dashboard::types::{PuzzleRecord, VerifyRecord};
use crate::error::CaptchaError;
use crate::puzzle::types::ChallengeKind;
use crate::risk::cookie::{CookieSameSite, extract_cookie, now_secs, set_cookie_header};
use crate::risk::{
    BehaviorPresence, CookiePresence, EscalationTier, SignalContext, TlsFingerprint, VerifyContext,
    VerifyDecision, client_ip, difficulty_for,
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

    // Score the request. The live mode is driven by `full_fingerprint_mode`;
    // the *other* mode is computed only when the dashboard is consuming it,
    // so a baseline production deployment (FULL_FINGERPRINT_MODE unset,
    // ADMIN_DB_PATH unset) never invokes the fingerprint scorers at all
    // (header anomaly, IP reputation, cookie age, TLS fingerprint).
    let ctx = SignalContext {
        ip,
        headers: &headers,
        ip_count,
        site_count,
        cookie,
        tls_fingerprint,
    };
    let log_enabled = state.decision_log.is_some();
    let score = if state.full_fingerprint_mode {
        state.risk.score(&ctx)
    } else {
        state.risk.score_minimal(&ctx)
    };
    let shadow = if log_enabled {
        Some(if state.full_fingerprint_mode {
            state.risk.score_minimal(&ctx)
        } else {
            state.risk.score(&ctx)
        })
    } else {
        None
    };
    // Decompose the live + shadow pair into the (full, minimal) the log
    // record expects. When the dashboard is off, both halves carry the live
    // score — the row is never read anyway.
    let (score_full, score_minimal) = if state.full_fingerprint_mode {
        (score, shadow.unwrap_or(score))
    } else {
        (shadow.unwrap_or(score), score)
    };

    // Tiers that don't issue a PoW puzzle (Block always rejects with 429;
    // VisualChallenge issues an image instead — see below). PoW tiers map
    // to a difficulty here.
    let maybe_difficulty = difficulty_for(
        score.tier,
        state.config.default_difficulty,
        state.config.max_difficulty,
    );
    let outcome = match score.tier {
        EscalationTier::Block => "rejected",
        _ => "issued",
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

    if score.tier == EscalationTier::Block {
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
                score_full: score_full.total,
                tier_full: score_full.tier,
                score_minimal: score_minimal.total,
                tier_minimal: score_minimal.tier,
            });
        }
        // Block-tier still returns a structured JSON body so the widget
        // can surface operator-overridden info URLs even on rejection —
        // this is exactly when the user is most likely to want them.
        let body = BlockedResponse {
            error: CaptchaError::RateLimited.to_string(),
            tier: score.tier,
            info_urls: state.info_urls.clone(),
        };
        return Ok((StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response());
    }

    // Build the challenge. VisualChallenge tier issues an image-text
    // puzzle (no PoW); every other tier issues a PoW at the tier's
    // difficulty.
    let challenge = if score.tier == EscalationTier::VisualChallenge {
        state.engine.generate_visual(params.site_key)
    } else {
        let difficulty = maybe_difficulty.expect("PoW tiers must have a difficulty");
        state.engine.generate(params.site_key, difficulty)
    };

    if let Some(log) = &state.decision_log {
        log.record_puzzle(PuzzleRecord {
            challenge_id: Some(challenge.id),
            site_key: params.site_key,
            ip: ip.to_string(),
            ip_count,
            site_count,
            score: score.total,
            tier: score.tier,
            difficulty: challenge.difficulty,
            outcome: "issued",
            breakdown: score.breakdown,
            cookie_presence: format!("{cookie:?}"),
            tls_fingerprint: format!("{tls_fingerprint:?}"),
            user_agent: ua,
            score_full: score_full.total,
            tier_full: score_full.tier,
            score_minimal: score_minimal.total,
            tier_minimal: score_minimal.tier,
        });
    }

    let response = PuzzleResponse {
        challenge_id: challenge.id,
        kind: challenge.kind,
        algorithm: challenge.algorithm,
        prefix: challenge.prefix.clone(),
        difficulty: challenge.difficulty,
        image: challenge.visual_image.clone(),
        expires_at: challenge.expires_at.to_rfc3339(),
        tier: score.tier,
        info_urls: state.info_urls.clone(),
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

    let site = state
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

    if challenge.site_key != site.site_key {
        return Err(CaptchaError::Unauthorized);
    }

    // Check expiry
    if challenge.expires_at < chrono::Utc::now() {
        state.store.delete_challenge(&challenge.id).await?;
        return Err(CaptchaError::ChallengeExpired);
    }

    // Check replay
    if challenge.solved {
        return Err(CaptchaError::ChallengeAlreadyUsed);
    }

    // Verify the puzzle. PoW challenges check the nonce against the
    // hash target; image challenges compare the typed text to the
    // server-stored expected answer. The "puzzle invalid" outcome is
    // logged with a kind-aware label so the dashboard can distinguish
    // brute-force misses from typos.
    let (puzzle_valid, invalid_outcome) = match challenge.kind {
        ChallengeKind::Pow => (state.engine.verify(&challenge, body.nonce), "pow_invalid"),
        ChallengeKind::Image => {
            let answer = body.text_answer.as_deref().unwrap_or("");
            (
                state.engine.verify_visual(&challenge, answer),
                "visual_invalid",
            )
        }
    };

    if !puzzle_valid {
        tracing::info!(
            event = "verify_decision",
            outcome = invalid_outcome,
            challenge_id = %challenge.id,
            success = false,
            "Verify decision"
        );
        if let Some(log) = &state.decision_log {
            log.record_verify(VerifyRecord {
                challenge_id: challenge.id,
                success: false,
                outcome: invalid_outcome,
                score: 0,
                breakdown: Default::default(),
                time_on_page_ms: body.time_on_page_ms,
                cookie_presence: "Unknown".into(),
                webdriver: "n/a",
                score_full: 0,
                outcome_full: invalid_outcome,
                score_minimal: 0,
                outcome_minimal: invalid_outcome,
            });
        }
        return Ok(Json(VerifyResponse { success: false }));
    }

    // Consume the challenge atomically after a valid PoW. This preserves
    // wrong-nonce retry behavior, while ensuring concurrent correct submits
    // cannot both pass.
    state.store.consume_challenge(&challenge.id).await?;

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
    let v_log_enabled = state.decision_log.is_some();
    let vscore = if state.full_fingerprint_mode {
        state.verify_scorer.score(&vctx)
    } else {
        state.verify_scorer.score_minimal(&vctx)
    };
    let v_shadow = if v_log_enabled {
        Some(if state.full_fingerprint_mode {
            state.verify_scorer.score_minimal(&vctx)
        } else {
            state.verify_scorer.score(&vctx)
        })
    } else {
        None
    };
    let (vscore_full, vscore_minimal) = if state.full_fingerprint_mode {
        (vscore, v_shadow.unwrap_or(vscore))
    } else {
        (v_shadow.unwrap_or(vscore), vscore)
    };

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
        let outcome_full = decision_outcome(vscore_full.decision);
        let outcome_minimal = decision_outcome(vscore_minimal.decision);
        log.record_verify(VerifyRecord {
            challenge_id: challenge.id,
            success,
            outcome,
            score: vscore.total,
            breakdown: vscore.breakdown,
            time_on_page_ms: body.time_on_page_ms,
            cookie_presence: format!("{cookie:?}"),
            webdriver: webdriver_flag,
            score_full: vscore_full.total,
            outcome_full,
            score_minimal: vscore_minimal.total,
            outcome_minimal,
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

fn decision_outcome(decision: VerifyDecision) -> &'static str {
    match decision {
        VerifyDecision::Pass => "pass",
        VerifyDecision::ShadowFail => "shadow_fail",
        VerifyDecision::Block => "block",
    }
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
