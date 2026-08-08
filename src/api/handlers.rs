use std::net::IpAddr;

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::http::header::{ORIGIN, USER_AGENT};
use axum::response::IntoResponse;

use crate::dashboard::types::{PuzzleRecord, VerifyRecord};
use crate::error::CaptchaError;
use crate::puzzle::types::Algorithm;
use crate::risk::{
    BehaviorPresence, EscalationTier, SignalContext, TlsFingerprint, VerifyContext, VerifyDecision,
    anonymize_ip, client_ip, difficulty_for, rate_key,
};
use crate::site::types::{EffectivePolicy, Site};
use crate::storage::Store;

use super::extract::{AppJson, AppQuery};
use super::state::SharedState;
use super::types::*;

/// Percentage of `MAX_ACTIVE_CHALLENGES` at which we begin shedding sources
/// that are already over `IP_HARD_LIMIT`. Below this the per-IP cap only
/// throttles difficulty; above it, a flooding source is refused outright so it
/// can't consume the headroom the ceiling is holding in reserve for everyone
/// else. 80% leaves a fifth of the map as slack for organic traffic while the
/// flood drains via TTL.
const SHED_PRESSURE_PERCENT: usize = 80;

pub async fn get_puzzle(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    AppQuery(params): AppQuery<GetPuzzleParams>,
) -> Result<axum::response::Response, CaptchaError> {
    // Validate site key exists
    let site = state
        .store
        .get_site_by_key(&params.site_key)
        .await?
        .ok_or(CaptchaError::InvalidSiteKey)?;

    // Per-site origin allowlist. When the site restricts origins and the
    // request carries an `Origin` header whose lowercased value isn't
    // allow-listed, refuse — *before* touching the rate counters below, so an
    // origin-blocked flood doesn't inflate per-IP/per-site counts. Requests
    // with NO Origin header always pass: same-origin embeds and
    // server-to-server fetches don't send one, and a non-browser client can
    // forge it anyway. This is tenant hygiene (quota/stats protection), not
    // bot defense — the real boundary stays the site secret at /v1/verify.
    if !site.allowed_origins.is_empty()
        && let Some(origin) = headers.get(ORIGIN).and_then(|v| v.to_str().ok())
    {
        let origin = origin.to_ascii_lowercase();
        if !site.allowed_origins.contains(&origin) {
            return Err(CaptchaError::OriginNotAllowed);
        }
    }

    // Overlay this site's policy on the process config. Every knob below —
    // tier bands, base difficulty, the difficulty clamp — reads from here
    // rather than from `state.config`, so a site that overrides nothing is
    // scored exactly as it was before policies existed.
    let policy = site.policy.resolve(&state.config);

    // Resolve the client IP. Behind a reverse proxy in TRUSTED_PROXIES we
    // walk X-Forwarded-For; otherwise the TCP peer is authoritative.
    let peer: IpAddr = addr.ip();
    let ip = client_ip(peer, &headers, &state.trusted_proxies);

    // Get rate counters (feeds the rate signal). The counter key buckets
    // IPv6 to /64 so one host rotating through its delegated block still
    // shares a single counter; scoring and logging keep the full `ip`.
    let ip_count = state.store.increment_ip_count(&rate_key(ip)).await?;
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
    let score = state.risk.score(&ctx, policy.tiers);

    // Hard per-IP issuance cap (IP_HARD_LIMIT): a flood with clean browser
    // headers never reaches TIER_BLOCK_MIN through scoring (the rate signal
    // maxes at +45). Past the cap we escalate to a MAX-difficulty PoW rather
    // than a hard 429: a plain block would also punish shared-IP populations
    // (CGNAT / corporate NAT — hundreds of users behind one address) with no
    // recourse, whereas max PoW throttles an abuser while still letting a
    // legitimate user through (slowly). Unbounded memory growth from the flood
    // is handled separately by the global challenge cap below.
    let hard_capped = state.config.ip_hard_limit > 0 && ip_count > state.config.ip_hard_limit;
    // Global memory backstop: once the in-memory challenge map hits its
    // ceiling, shed new issuance via Block/429 regardless of the per-IP score
    // — bounds a distributed flood (or an IPv6 /64-spread attacker staying
    // under IP_HARD_LIMIT per source) that would otherwise grow the map
    // unbounded between cleanup sweeps. `&&` short-circuits so a disabled cap
    // (0) never takes the challenge-map read lock on the hot path.
    // The ceiling on its own is indiscriminate: at 100% full, every request
    // from every IP for every site is refused, so one flooding source takes the
    // whole service down for all tenants. Start shedding the *sources causing*
    // the pressure before that point instead — past SHED_PRESSURE_PERCENT we
    // refuse IPs already over IP_HARD_LIMIT, which stops them consuming the
    // remaining headroom while everyone under the per-IP cap (i.e. all organic
    // traffic, including CGNAT) keeps being served. A flood from one source
    // therefore plateaus at the shed threshold and drains via TTL instead of
    // reaching the ceiling. The full-map Block stays as the last-resort backstop
    // for a genuinely distributed flood that stays under the per-IP cap.
    let max_active = state.config.max_active_challenges;
    let (over_capacity, under_pressure) = if max_active > 0 {
        let count = state.store.challenge_count();
        (
            count >= max_active,
            count.saturating_mul(100) >= max_active.saturating_mul(SHED_PRESSURE_PERCENT),
        )
    } else {
        (false, false)
    };
    // Both Block paths are a genuine load-shed (429). hard_capped alone stays a
    // throttle: bump to HardPow and floor the difficulty to max below, but keep
    // issuing, so a shared-IP population isn't stranded while there's headroom.
    let shed_flooder = under_pressure && hard_capped;
    let tier = if over_capacity || shed_flooder {
        EscalationTier::Block
    } else if hard_capped {
        EscalationTier::HardPow
    } else {
        score.tier
    };

    // Monitor mode: record the risk verdict, don't act on it. Only a Block
    // that came from *scoring* is downgraded — the two load sheds above are
    // deliberately excluded, because they protect the whole instance rather
    // than judge this visitor, and a monitored tenant that could exhaust the
    // challenge map would take every other site down with it.
    //
    // The downgrade target is HardPow rather than the raw score tier: the
    // visitor still gets through, at the most expensive puzzle we issue. So a
    // monitored site is not unprotected, it just never hands out a hard no.
    //
    // `tier` below stays the *risk verdict* so the dashboard's tier breakdown
    // answers "how many would I have blocked?" — which is the entire reason to
    // run in this mode. The `monitored` flag on the record is what says the
    // verdict wasn't acted on.
    let monitored_block = policy.mode.is_monitor()
        && tier == EscalationTier::Block
        && !over_capacity
        && !shed_flooder;
    let enforced_tier = if monitored_block {
        EscalationTier::HardPow
    } else {
        tier
    };

    // Aggregate site-load floor: when the whole site is under load, raise PoW
    // difficulty for every visitor regardless of their individual risk score.
    // It composes with the per-request tier via max() and never blocks — Block
    // stays a per-request risk decision, so a load spike (launch, viral link)
    // slows everyone fairly instead of 429-ing real users.
    let load_floor = state.config.load_ladder.floor_for(site_count);

    // Block is the only tier that doesn't issue a PoW puzzle (it rejects with
    // 429 below). Every other tier maps to a difficulty here; a hard-capped IP
    // is floored to MAX so the throttle bites without blocking.
    let maybe_difficulty = difficulty_for(
        enforced_tier,
        policy.default_difficulty,
        policy.max_difficulty,
    )
    .map(|d| {
        let floored = d.max(load_floor);
        // A monitored Block gets the same max-difficulty floor as a hard-capped
        // IP: it's the strongest response available that still lets the visitor
        // through, which is what "observe, don't refuse" has to mean here.
        let floored = if hard_capped || monitored_block {
            floored.max(policy.max_difficulty)
        } else {
            floored
        };
        floored.min(policy.max_difficulty)
    });
    let outcome = match enforced_tier {
        EscalationTier::Block => "rejected",
        _ => "issued",
    };

    // IP for logging. Live scoring above used the full `ip`; everything we
    // *emit* — the tracing event here and the durable decision log below —
    // uses the network prefix when ANONYMIZE_LOG_IP is on (the default), so
    // neither a log aggregator nor the dashboard ends up holding a per-visitor
    // address.
    let logged_ip = if state.config.anonymize_log_ip {
        anonymize_ip(ip)
    } else {
        ip
    }
    .to_string();

    tracing::info!(
        event = "puzzle_decision",
        outcome = outcome,
        ip = %logged_ip,
        site_key = %params.site_key,
        ip_count,
        site_count,
        score = score.total,
        tier = ?tier,
        hard_capped,
        over_capacity,
        // Distinguishes the two shed paths: `shed_flooder` means this specific
        // source was refused for flooding while headroom remained, whereas
        // `over_capacity` means the map was genuinely full and everyone was
        // refused. Conflating them would hide a distributed flood behind the
        // per-IP one.
        shed_flooder,
        difficulty = maybe_difficulty.unwrap_or(0),
        load_floor,
        // True when `tier` below says Block but we issued anyway. Without it
        // a monitored site's log reads as a contradiction.
        monitored = monitored_block,
        // Whether this site's own policy (rather than the process config)
        // produced the bands above. Without it, a tier that looks wrong against
        // the documented env defaults is indistinguishable from a bug.
        site_policy = !site.policy.is_empty(),
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

    if enforced_tier == EscalationTier::Block {
        if let Some(log) = &state.decision_log {
            log.record_puzzle(PuzzleRecord {
                challenge_id: None,
                monitored: false,
                site_key: params.site_key,
                ip: logged_ip,
                ip_count,
                site_count,
                score: score.total,
                tier,
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
            tier,
            info_urls: state.info_urls.clone(),
        };
        return Ok((StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response());
    }

    // Build the PoW challenge at the tier's difficulty (every non-Block tier
    // issues a PoW; Block already returned above).
    let difficulty = maybe_difficulty.expect("non-Block tiers must have a difficulty");

    // Carry the dwell anchor across a pre-expiry refresh. The widget cites the
    // challenge it is replacing; we honour it only after confirming the cited
    // challenge exists and belongs to *this* site, so the citation is a proof
    // of possession rather than an assertion. A miss is silently ignored — a
    // stale or consumed id must degrade to a normal issuance, never to an
    // error, since the visitor did nothing wrong.
    //
    // This grants a backdated anchor only to a client that actually held a
    // live challenge for that long, which is the same capability as simply
    // keeping the original challenge to its TTL. It is deliberately not a
    // client-reported dwell or an "I refreshed" flag: those cost a liar
    // nothing, and this must not become a way to skip the fast-submit band.
    // `dwell_since` (not `created_at`) is propagated so a chain of refreshes
    // keeps pointing at the visitor's original arrival.
    let inherited_dwell = match params.refresh_of {
        Some(prior_id) => state
            .store
            .get_challenge(&prior_id)
            .await?
            .filter(|prior| prior.site_key == params.site_key)
            .map(|prior| prior.dwell_since),
        None => None,
    };

    let challenge = state
        .engine
        .generate_with_dwell(params.site_key, difficulty, inherited_dwell);

    if let Some(log) = &state.decision_log {
        log.record_puzzle(PuzzleRecord {
            challenge_id: Some(challenge.id),
            monitored: monitored_block,
            site_key: params.site_key,
            ip: logged_ip,
            ip_count,
            site_count,
            score: score.total,
            tier,
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
        expires_in_secs: state.config.challenge_ttl_secs,
        tier: enforced_tier,
        info_urls: state.info_urls.clone(),
    };

    state.store.store_challenge(&challenge).await?;

    Ok(Json(response).into_response())
}

pub async fn verify(
    State(state): State<SharedState>,
    headers: HeaderMap,
    AppJson(body): AppJson<VerifyRequest>,
) -> Result<Json<VerifyResponse>, CaptchaError> {
    // Normalise the request: decode the opaque widget token, or take the
    // explicit fields for server-to-server callers.
    let req = body.resolve()?;

    // Extract and validate bearer token
    let token = super::extract::bearer_token(&headers).ok_or(CaptchaError::Unauthorized)?;

    let site = state
        .store
        .get_site_by_secret(token)
        .await?
        .ok_or(CaptchaError::Unauthorized)?;

    // Overlay this site's policy on the process config, exactly as the puzzle
    // handler does — the verify-time bands are per-site for the same reason
    // the puzzle-time ones are.
    let policy = site.policy.resolve(&state.config);

    // Fork before any challenge lookup: a failover claim has no challenge by
    // construction, so it takes an entirely separate path with its own
    // (much weaker, explicitly fail-open) acceptance rules.
    let req = match req {
        ResolvedVerify::Solved(s) => s,
        ResolvedVerify::Failover(claim) => {
            return verify_failover(&state, &site, &policy, claim);
        }
    };

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

    // Server-authoritative time-on-page: elapsed since the visitor arrived —
    // `dwell_since`, which equals `created_at` for a first issuance and is
    // inherited across the widget's pre-expiry refreshes. Anchoring on
    // `created_at` instead would restart the clock every refresh, so a
    // five-minute dwell that happened to submit just after one would score
    // (and log) as a 400ms submission.
    //
    // Derived here rather than trusted from the client, so a bot can't claim
    // a longer dwell than actually elapsed to dodge the fast-submit penalty.
    let time_on_page_ms = (verify_at - challenge.dwell_since)
        .num_milliseconds()
        .max(0) as u64;

    // Verify the PoW: check the nonce against the hash target. SHA-256 is a
    // single hash (microseconds), so run it inline. Argon2id is memory-hard
    // (an ~8 MiB alloc + tens of ms of CPU per attempt), so offload it to a
    // blocking thread — running it on an async worker would let a flood of
    // verify attempts starve the runtime and stall every other endpoint.
    let nonce = req.nonce;
    let puzzle_valid = match challenge.algorithm {
        Algorithm::Sha256 => state.engine.verify(&challenge, nonce),
        Algorithm::Argon2id(_) => {
            // Hold a permit for the duration of the hash. Each Argon2id call
            // allocates ARGON2_M_COST KiB, and tokio spawns a fresh blocking
            // thread whenever the existing ones are busy (up to 512) — so
            // unbounded concurrency here turns a burst of cheap POSTs into
            // gigabytes of resident memory. Queueing on the permit (rather than
            // refusing) keeps honest callers working through a burst; the
            // request timeout layer bounds how long anyone waits.
            let permit = state
                .verify_permits
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| CaptchaError::Storage("verify permits closed".to_string()))?;
            let state = state.clone();
            let challenge = challenge.clone();
            tokio::task::spawn_blocking(move || {
                // The permit is moved *into* the closure, not merely held by
                // this request's future. A blocking task cannot be cancelled:
                // if the future is dropped mid-hash — request timeout, or a
                // caller with an impatient HTTP client — tokio detaches the
                // task and the ~8 MiB allocation lives on until the hash
                // returns. Releasing the permit with the future would hand it
                // to the next request against memory that is still in use, so
                // a caller who retries faster than the hash completes could
                // over-commit the bound this semaphore exists to enforce.
                let _permit = permit;
                state.engine.verify(&challenge, nonce)
            })
            .await
            .map_err(|e| CaptchaError::Storage(format!("verify task failed: {e}")))?
        }
    };
    let invalid_outcome = "pow_invalid";

    if !puzzle_valid {
        // A wrong nonce leaves the challenge live for legitimate retry, but
        // bound how many attempts one challenge absorbs so it can't be used as
        // an unlimited (memory-hard) work amplifier.
        let attempts_exhausted = state
            .store
            .register_failed_attempt(&challenge.id, state.config.verify_max_attempts)
            .await?;
        tracing::info!(
            event = "verify_decision",
            outcome = invalid_outcome,
            challenge_id = %challenge.id,
            success = false,
            attempts_exhausted,
            "Verify decision"
        );
        if let Some(log) = &state.decision_log {
            log.record_verify(VerifyRecord {
                challenge_id: challenge.id,
                success: false,
                outcome: invalid_outcome,
                monitored: false,
                score: 0,
                breakdown: Default::default(),
                time_on_page_ms: Some(time_on_page_ms),
                webdriver: "n/a",
            });
        }
        return Ok(Json(VerifyResponse::solved(false)));
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
    let vscore = state.verify_scorer.score(&vctx, policy.verify);

    // Monitor mode turns the refusal off, not the verdict: `outcome` stays
    // "block" so the dashboard keeps counting what would have been blocked,
    // and `success` disagreeing with it is precisely the signal — the pair
    // reads as "this one would have been refused, and wasn't". An invalid
    // proof of work is untouched (handled above and already returned): that's
    // a failed proof, not a judgement about the visitor.
    let monitored = policy.mode.is_monitor() && vscore.decision == VerifyDecision::Block;
    let (success, outcome) = match vscore.decision {
        VerifyDecision::Pass => (true, "pass"),
        VerifyDecision::ShadowFail => (true, "shadow_fail"),
        VerifyDecision::Block => (monitored, "block"),
    };

    // Surface the raw environment probes for log analysis: the aggregate
    // `sig_behavior` score doesn't tell you which sub-signal contributed.
    // `headless` matters most here — it's the noisiest probe, so its observed
    // fire rate on real traffic is what its weighting should be tuned against.
    let flag = |v: Option<bool>| match v {
        Some(true) => "true",
        Some(false) => "false",
        None => "absent",
    };
    let (webdriver_flag, automation_flag, headless_flag) = match req.behavior {
        Some(b) => (flag(b.webdriver), flag(b.automation), flag(b.headless)),
        None => ("no_blob", "no_blob", "no_blob"),
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
                automation = automation_flag,
                headless = headless_flag,
                time_on_page_ms = time_on_page_ms,
                monitored = monitored,
                "Verify decision"
            )
        };
    }
    match vscore.decision {
        VerifyDecision::ShadowFail | VerifyDecision::Block => {
            emit_decision!(tracing::Level::WARN)
        }
        _ => emit_decision!(tracing::Level::INFO),
    }

    if let Some(log) = &state.decision_log {
        log.record_verify(VerifyRecord {
            challenge_id: challenge.id,
            success,
            outcome,
            monitored,
            score: vscore.total,
            breakdown: vscore.breakdown,
            time_on_page_ms: Some(time_on_page_ms),
            webdriver: webdriver_flag,
        });
    }

    Ok(Json(VerifyResponse::solved(success)))
}

/// Decide a failover claim — a client asserting it could not reach us at all.
///
/// Two independent gates, in order:
///
/// 1. **Attestation** ([`crate::failover`]): is there a window where *we* know
///    we were unreachable, still within its grace tail? Without one this is
///    just an unauthenticated request to skip the puzzle, and is refused.
/// 2. **Local evidence**: the honeypot and behaviour blob are collected in the
///    browser and so survive the outage. They're the only real signal left on
///    this path, so an obviously-automated claim is refused *even inside* an
///    attested window. This is why failover isn't a blanket free pass:
///    a headless/driven client that trips the verify scorer still gets nothing.
///
/// Deliberately synchronous and allocation-light — during an outage recovery
/// this path can see the whole site's backlog arrive at once.
fn verify_failover(
    state: &SharedState,
    site: &Site,
    policy: &EffectivePolicy,
    claim: FailoverClaim,
) -> Result<Json<VerifyResponse>, CaptchaError> {
    // The claim names the site it was minted for; it must match the secret the
    // caller authenticated with, or one tenant could spend another's budget.
    if claim.site_key != site.site_key {
        return Err(CaptchaError::Unauthorized);
    }

    let verdict = state.failover.evaluate(&site.site_key, claim.issued_at_ms);

    // Score the browser-local evidence before honoring an accepted claim.
    // There's no challenge, so no server-derived time-on-page — behaviour and
    // the honeypot are all we have.
    let honeypot_tripped = claim.honeypot.as_deref().is_some_and(|s| !s.is_empty());
    let vctx = VerifyContext {
        honeypot_tripped,
        time_on_page_ms: None,
        behavior: match claim.behavior {
            Some(report) => BehaviorPresence::Present(report),
            None => BehaviorPresence::Absent,
        },
    };
    let vscore = state.verify_scorer.score(&vctx, policy.verify);

    let monitored = policy.mode.is_monitor();
    let (success, outcome) = match (verdict.accepted(), vscore.decision) {
        // Not attested, or over the per-site cap. Monitor mode does not reach
        // this arm: refusing an unattested claim is not a risk verdict about
        // the visitor, it's "you asserted an outage that never happened".
        (false, _) => (false, verdict.outcome()),
        // Attested, but the client looks automated. Refuse — an outage is not
        // a reason to stop reading the evidence we still have. This *is* a
        // risk verdict, so a monitored site records it and lets it through.
        (true, VerifyDecision::Block) => (monitored, "failover_behavior_block"),
        (true, _) => (true, verdict.outcome()),
    };

    // Every failover decision is WARN, accepted or not: an operator needs to
    // see both that a fail-open is in progress and that someone is probing for
    // one. This log is the audit trail for the path (same stance as
    // ShadowFail), which is why it carries the full breakdown.
    tracing::warn!(
        event = "verify_decision",
        outcome = outcome,
        failover = true,
        success = success,
        site_key = %site.site_key,
        score = vscore.total,
        sig_honeypot = vscore.breakdown.honeypot,
        sig_behavior = vscore.breakdown.behavior,
        issued_at_ms = claim.issued_at_ms,
        monitored = monitored,
        "Failover claim decision"
    );

    Ok(Json(VerifyResponse {
        success,
        failover: success,
    }))
}

/// Declare an outage window so failover claims are honored for it.
///
/// The escape hatch for outages this process cannot self-observe: the
/// heartbeat only catches gaps where the process itself was gone, so an
/// intact server behind a broken edge (expired/self-signed TLS, DNS, CDN)
/// leaves no trace here — the app was healthy the entire time while no browser
/// could load the widget. `scripts/check-public-endpoint.sh` detects exactly
/// that from outside and is the intended caller.
///
/// `duration_secs` declares a window ending *now* (the common case: something
/// just broke and has been broken for N seconds). `start`/`end` declare an
/// explicit interval, for backfilling after the fact.
pub async fn declare_outage(
    State(state): State<SharedState>,
    headers: HeaderMap,
    AppJson(body): AppJson<DeclareOutageRequest>,
) -> Result<Json<OutagesResponse>, CaptchaError> {
    require_admin_token(&state, &headers)?;

    if !state.failover.enabled() {
        return Err(CaptchaError::BadRequest(
            "client failover is disabled — set FAILOVER_ENABLED=1 and \
             FAILOVER_STATE_PATH to declare outage windows"
                .into(),
        ));
    }

    let now = chrono::Utc::now();
    let (start, end) = match (body.duration_secs, body.start, body.end) {
        (Some(secs), _, _) => {
            if secs == 0 || secs > MAX_DECLARED_OUTAGE_SECS {
                return Err(CaptchaError::BadRequest(format!(
                    "duration_secs must be 1..={MAX_DECLARED_OUTAGE_SECS}"
                )));
            }
            (now - chrono::Duration::seconds(secs as i64), now)
        }
        (None, Some(start), Some(end)) => (start, end),
        _ => {
            return Err(CaptchaError::BadRequest(
                "provide either duration_secs, or both start and end".into(),
            ));
        }
    };

    if end <= start {
        return Err(CaptchaError::BadRequest("end must be after start".into()));
    }
    // An unbounded future `end` would hold the fail-open open indefinitely,
    // which is the one mistake here that can't be noticed from the outside.
    if (end - start).num_seconds() > MAX_DECLARED_OUTAGE_SECS as i64 {
        return Err(CaptchaError::BadRequest(format!(
            "declared window may not exceed {MAX_DECLARED_OUTAGE_SECS}s"
        )));
    }

    state.failover.declare_outage(start, end);
    Ok(Json(outages_payload(&state)))
}

/// Current attested windows plus accept/refuse counters, for operators and
/// the monitor script to confirm a declaration landed.
pub async fn list_outages(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<OutagesResponse>, CaptchaError> {
    require_admin_token(&state, &headers)?;
    Ok(Json(outages_payload(&state)))
}

fn outages_payload(state: &SharedState) -> OutagesResponse {
    let (accepted, refused) = state.failover.counters();
    OutagesResponse {
        enabled: state.failover.enabled(),
        grace_secs: state.config.failover_grace_secs,
        windows: state.failover.active_windows(),
        accepted_total: accepted,
        refused_total: refused,
    }
}

/// Upper bound on a single declared window (24h). Long enough for any real
/// incident, short enough that a fat-fingered declaration expires on its own.
const MAX_DECLARED_OUTAGE_SECS: u64 = 86_400;

pub async fn create_site(
    State(state): State<SharedState>,
    headers: HeaderMap,
    AppJson(body): AppJson<CreateSiteRequest>,
) -> Result<Json<CreateSiteResponse>, CaptchaError> {
    require_admin_token(&state, &headers)?;

    let name =
        crate::site::types::normalize_site_name(&body.name).map_err(CaptchaError::BadRequest)?;

    // Validate + normalize the optional origin allowlist; a bad entry names
    // itself in the 400 so the caller can fix it.
    let allowed_origins = crate::site::types::normalize_origins(&body.allowed_origins)
        .map_err(CaptchaError::BadRequest)?;

    // Validate the policy against *this server's* config, since that's what it
    // will be merged with at request time. Rejecting here means a site can
    // never be stored in a state that silently disables its own protection.
    let policy = body.policy;
    policy
        .validate(&state.config)
        .map_err(CaptchaError::BadRequest)?;

    let site_key = uuid::Uuid::new_v4();
    let secret_key = hex::encode(rand::random::<[u8; 32]>());

    let site = Site {
        site_key,
        secret_key: secret_key.clone(),
        name,
        created_at: chrono::Utc::now(),
        allowed_origins: allowed_origins.clone(),
        policy,
    };

    state.store.store_site(&site).await?;

    Ok(Json(CreateSiteResponse {
        site_key,
        secret_key,
        allowed_origins,
        policy,
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
    let token = super::extract::bearer_token(headers).ok_or(CaptchaError::Unauthorized)?;
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
