use std::net::IpAddr;

use axum::Json;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::http::header::{AUTHORIZATION, USER_AGENT};
use axum::response::IntoResponse;

use crate::dashboard::types::{PuzzleRecord, VerifyRecord};
use crate::error::CaptchaError;
use crate::risk::{
    BehaviorPresence, EscalationTier, SignalContext, TlsFingerprint, VerifyContext, VerifyDecision,
    anonymize_ip, client_ip, difficulty_for,
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

    // Score the request. Every signal self-gates on its own input — header
    // anomaly always computes, IP reputation is 0 without IP_REPUTATION_FILE,
    // and TLS fingerprint is 0 unless a trusted proxy supplied the header — so
    // the privacy-invasive signals only fire when their inputs are configured.
    let ctx = SignalContext {
        ip,
        headers: &headers,
        ip_count,
        site_count,
        tls_fingerprint,
    };
    let score = state.risk.score(&ctx);

    // Aggregate site-load floor: when the whole site is under load, raise PoW
    // difficulty for every visitor regardless of their individual risk score.
    // It composes with the per-request tier via max() and never blocks — Block
    // stays a per-request risk decision, so a load spike (launch, viral link)
    // slows everyone fairly instead of 429-ing real users.
    let load_floor = state.config.load_ladder.floor_for(site_count);

    // Block is the only tier that doesn't issue a PoW puzzle (it rejects
    // with 429 below). Every other tier maps to a difficulty here.
    let maybe_difficulty = difficulty_for(
        score.tier,
        state.config.default_difficulty,
        state.config.max_difficulty,
    )
    .map(|d| d.max(load_floor).min(state.config.max_difficulty));
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
        load_floor,
        sig_rate = score.breakdown.rate,
        sig_header_anomaly = score.breakdown.header_anomaly,
        sig_ip_reputation = score.breakdown.ip_reputation,
        ip_reputation_category = score.ip_category.map(|c| c.as_str()).unwrap_or("none"),
        sig_tls_fingerprint = score.breakdown.tls_fingerprint,
        tls_fingerprint = ?tls_fingerprint,
        "Puzzle decision"
    );

    // Canonical network-type label for the decision log (None → NULL column).
    // Lets the dashboard break traffic down by datacenter/tor/vpn/residential.
    let ip_reputation_category = score.ip_category.map(|c| c.as_str());

    // Snapshot the User-Agent for the dashboard before we hit any branch
    // that returns. The header may be missing — that's fine, it still scores.
    let ua = headers
        .get(USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // IP stored in the decision log. Scoring above already used the full `ip`;
    // here we keep only the network prefix when ANONYMIZE_LOG_IP is on (the
    // default) so the durable dashboard log holds no per-visitor address.
    let logged_ip = if state.config.anonymize_log_ip {
        anonymize_ip(ip)
    } else {
        ip
    }
    .to_string();

    if score.tier == EscalationTier::Block {
        if let Some(log) = &state.decision_log {
            log.record_puzzle(PuzzleRecord {
                challenge_id: None,
                site_key: params.site_key,
                ip: logged_ip,
                ip_count,
                site_count,
                score: score.total,
                tier: score.tier,
                difficulty: 0,
                outcome: "rejected",
                breakdown: score.breakdown,
                ip_reputation_category,
                tls_fingerprint: format!("{tls_fingerprint:?}"),
                user_agent: ua,
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

    // Build the PoW challenge at the tier's difficulty (every non-Block tier
    // issues a PoW; Block already returned above).
    let difficulty = maybe_difficulty.expect("non-Block tiers must have a difficulty");
    let challenge = state.engine.generate(params.site_key, difficulty);

    if let Some(log) = &state.decision_log {
        log.record_puzzle(PuzzleRecord {
            challenge_id: Some(challenge.id),
            site_key: params.site_key,
            ip: logged_ip,
            ip_count,
            site_count,
            score: score.total,
            tier: score.tier,
            difficulty: challenge.difficulty,
            outcome: "issued",
            breakdown: score.breakdown,
            ip_reputation_category,
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
        info_urls: state.info_urls.clone(),
    };

    state.store.store_challenge(&challenge).await?;

    Ok(Json(response).into_response())
}

pub async fn verify(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, CaptchaError> {
    // Normalise the request: decode the opaque widget token, or take the
    // explicit fields for server-to-server callers.
    let req = body.resolve()?;

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
        .get_challenge(&req.challenge_id)
        .await?
        .ok_or(CaptchaError::ChallengeNotFound)?;

    if challenge.site_key != site.site_key {
        return Err(CaptchaError::Unauthorized);
    }

    // Check expiry
    let verify_at = chrono::Utc::now();
    if challenge.expires_at < verify_at {
        state.store.delete_challenge(&challenge.id).await?;
        return Err(CaptchaError::ChallengeExpired);
    }

    // Check replay
    if challenge.solved {
        return Err(CaptchaError::ChallengeAlreadyUsed);
    }

    // Server-authoritative time-on-page: elapsed since the challenge was
    // issued (≈ widget mount, since the widget fetches a puzzle on mount).
    // Derived here rather than trusted from the client, so a bot can't claim
    // a longer dwell than actually elapsed to dodge the fast-submit penalty.
    let time_on_page_ms = (verify_at - challenge.created_at).num_milliseconds().max(0) as u64;

    // Verify the PoW: check the nonce against the hash target.
    let puzzle_valid = state.engine.verify(&challenge, req.nonce);
    let invalid_outcome = "pow_invalid";

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
                time_on_page_ms: Some(time_on_page_ms),
                webdriver: "n/a",
            });
        }
        return Ok(Json(VerifyResponse { success: false }));
    }

    // Consume the challenge atomically after a valid PoW. This preserves
    // wrong-nonce retry behavior, while ensuring concurrent correct submits
    // cannot both pass.
    state.store.consume_challenge(&challenge.id).await?;

    // Verify-time risk scoring: time-on-page, honeypot, behavioral telemetry.
    // The decision can promote a PoW-valid request to ShadowFail (success=true,
    // logged) or Block (success=false) based on these signals.
    let honeypot_tripped = req.honeypot.as_deref().is_some_and(|s| !s.is_empty());
    let behavior = match req.behavior {
        Some(report) => BehaviorPresence::Present(report),
        None => BehaviorPresence::Absent,
    };
    let vctx = VerifyContext {
        honeypot_tripped,
        time_on_page_ms: Some(time_on_page_ms),
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
    let webdriver_flag = match req.behavior {
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
                sig_behavior = vscore.breakdown.behavior,
                webdriver = webdriver_flag,
                time_on_page_ms = time_on_page_ms,
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
            time_on_page_ms: Some(time_on_page_ms),
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
