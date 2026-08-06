use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::CaptchaError;
use crate::puzzle::types::Algorithm;
use crate::risk::{BehaviorReport, EscalationTier};
use crate::site::types::SitePolicy;

// --- Requests ---

#[derive(Debug, Deserialize)]
pub struct GetPuzzleParams {
    pub site_key: Uuid,
}

/// Verify request. Two shapes are accepted:
///
/// 1. **Opaque token** (the widget path): a single `token` string the widget
///    wrote into the hidden form field. The form host forwards it verbatim —
///    no parsing required. When present it is the sole source of truth and the
///    explicit fields below are ignored.
/// 2. **Explicit fields** (server-to-server path): `challenge_id` plus
///    `nonce` and optional `honeypot`/`behavior`, for callers that build the
///    request themselves.
///
/// Note there is no `time_on_page_ms`: dwell time is derived server-side from
/// the challenge's issuance timestamp, so a client can't claim a longer dwell
/// than actually elapsed.
#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    /// Opaque token produced by the widget (hex-encoded JSON). Takes
    /// precedence over the explicit fields when present.
    #[serde(default)]
    pub token: Option<String>,
    /// Required when `token` is absent (and `failover` is false).
    #[serde(default)]
    pub challenge_id: Option<Uuid>,
    /// PoW nonce.
    #[serde(default)]
    pub nonce: u64,
    #[serde(default)]
    pub honeypot: Option<String>,
    /// Compact behavioural telemetry collected by the widget between mount
    /// and submit. Absent for non-widget integrations.
    #[serde(default)]
    pub behavior: Option<BehaviorReport>,
    /// Marks this as a *failover claim* rather than a solved puzzle: the
    /// widget could not reach `/v1/puzzle` at all, so there is no challenge and
    /// no nonce. See [`crate::failover`] — this flag is client-authored and
    /// proves nothing on its own; the server honors it only against its own
    /// attested outage record.
    #[serde(default)]
    pub failover: bool,
    /// Site the failover claim was minted for. Required when `failover`.
    #[serde(default)]
    pub site_key: Option<Uuid>,
    /// Client-supplied mint time (unix ms). Sanity-checked only — forgeable.
    #[serde(default)]
    pub issued_at: Option<i64>,
}

/// Inner payload carried by the opaque `token`. The widget hex-encodes the
/// JSON form of this so the form host treats it as an opaque blob.
///
/// One shape covers both a solved puzzle and a failover claim, discriminated
/// by `failover`, so the form host forwards a single opaque string either way
/// and needs no branching of its own.
#[derive(Debug, Deserialize)]
struct TokenPayload {
    #[serde(default)]
    challenge_id: Option<Uuid>,
    #[serde(default)]
    nonce: u64,
    #[serde(default)]
    honeypot: Option<String>,
    #[serde(default)]
    behavior: Option<BehaviorReport>,
    #[serde(default)]
    failover: bool,
    #[serde(default)]
    site_key: Option<Uuid>,
    #[serde(default)]
    issued_at: Option<i64>,
}

/// A normally-solved submission: the client held a challenge and produced a
/// nonce for it. `time_on_page_ms` is deliberately absent — it's computed
/// server-side from the challenge's `created_at`.
pub struct SolvedVerify {
    pub challenge_id: Uuid,
    pub nonce: u64,
    pub honeypot: Option<String>,
    pub behavior: Option<BehaviorReport>,
}

/// A claim that the widget could not reach this service at all.
///
/// There is no challenge and no proof of work here — by construction there
/// cannot be, since the outage is precisely that we never issued one. The
/// honeypot and behaviour blob still ride along: the widget collects them
/// locally regardless of connectivity, so they remain the only real evidence
/// available on this path and are scored before the claim is honored.
pub struct FailoverClaim {
    pub site_key: Uuid,
    pub issued_at_ms: i64,
    pub honeypot: Option<String>,
    pub behavior: Option<BehaviorReport>,
}

/// Normalised verify request. The two arms are kept distinct so the handler
/// cannot accidentally treat an unauthenticated failover claim as a solved
/// puzzle — the whole security question on that path is which branch you're in.
pub enum ResolvedVerify {
    Solved(SolvedVerify),
    Failover(FailoverClaim),
}

impl VerifyRequest {
    /// Resolve into the normalised form. Decodes the opaque token when
    /// present, otherwise falls back to the explicit fields.
    pub fn resolve(self) -> Result<ResolvedVerify, CaptchaError> {
        // Treat an empty/whitespace token as absent so a caller that sends
        // `"token": ""` alongside explicit `challenge_id`/`nonce` falls through
        // to those fields instead of failing on an unparsable empty token.
        if let Some(token) = self
            .token
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
        {
            let bytes = hex::decode(token)
                .map_err(|_| CaptchaError::BadRequest("invalid captcha token".into()))?;
            let p: TokenPayload = serde_json::from_slice(&bytes)
                .map_err(|_| CaptchaError::BadRequest("invalid captcha token".into()))?;
            if p.failover {
                return Ok(ResolvedVerify::Failover(FailoverClaim {
                    site_key: p.site_key.ok_or_else(|| {
                        CaptchaError::BadRequest("failover token requires site_key".into())
                    })?,
                    issued_at_ms: p.issued_at.unwrap_or(0),
                    honeypot: p.honeypot,
                    behavior: p.behavior,
                }));
            }
            Ok(ResolvedVerify::Solved(SolvedVerify {
                challenge_id: p
                    .challenge_id
                    .ok_or_else(|| CaptchaError::BadRequest("invalid captcha token".into()))?,
                nonce: p.nonce,
                honeypot: p.honeypot,
                behavior: p.behavior,
            }))
        } else if self.failover {
            Ok(ResolvedVerify::Failover(FailoverClaim {
                site_key: self
                    .site_key
                    .ok_or_else(|| CaptchaError::BadRequest("failover requires site_key".into()))?,
                issued_at_ms: self.issued_at.unwrap_or(0),
                honeypot: self.honeypot,
                behavior: self.behavior,
            }))
        } else {
            let challenge_id = self.challenge_id.ok_or_else(|| {
                CaptchaError::BadRequest("challenge_id or token is required".into())
            })?;
            Ok(ResolvedVerify::Solved(SolvedVerify {
                challenge_id,
                nonce: self.nonce,
                honeypot: self.honeypot,
                behavior: self.behavior,
            }))
        }
    }
}

/// Body for `POST /v1/admin/outages`. Either `duration_secs` (a window ending
/// now) or an explicit `start`/`end` pair.
#[derive(Debug, Deserialize)]
pub struct DeclareOutageRequest {
    #[serde(default)]
    pub duration_secs: Option<u64>,
    #[serde(default)]
    pub start: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub end: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OutagesResponse {
    /// False when `FAILOVER_ENABLED` is off or no state path is configured —
    /// in which case every failover claim is refused regardless of windows.
    pub enabled: bool,
    pub grace_secs: u64,
    /// Windows that can still cover a claim (open, or within their grace tail).
    pub windows: Vec<crate::failover::OutageWindow>,
    pub accepted_total: u64,
    pub refused_total: u64,
}

#[derive(Debug, Deserialize)]
pub struct CreateSiteRequest {
    pub name: String,
    /// Optional browser-origin allowlist (`http(s)://host[:port]` entries).
    /// Empty/omitted = allow any origin. Validated + normalized in the handler.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Optional per-site scoring overrides. Omitted = inherit every env
    /// default. Validated against the running config in the handler.
    #[serde(default)]
    pub policy: SitePolicy,
}

// --- Responses ---

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct InfoUrls {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms: Option<String>,
}

impl InfoUrls {
    pub fn is_empty(&self) -> bool {
        self.about.is_none() && self.privacy.is_none() && self.terms.is_none()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PuzzleResponse {
    pub challenge_id: Uuid,
    pub algorithm: Algorithm,
    pub prefix: String,
    pub difficulty: u32,
    pub expires_at: String,
    /// Challenge lifetime in seconds, measured from issuance. The widget
    /// schedules its pre-expiry refresh from this rather than comparing
    /// `expires_at` against the client clock, which may be skewed.
    pub expires_in_secs: u64,
    pub tier: EscalationTier,
    /// Operator-overridden URLs for the about/privacy/terms pages, when
    /// `INFO_*_URL` env vars are set. Per-field optional — widget falls
    /// back to bundled `/static/*.html` for unset fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub info_urls: Option<InfoUrls>,
}

/// Body returned alongside a 429 in the `Block` tier so the widget can
/// still surface operator-overridden info URLs to a user it just blocked.
#[derive(Debug, Serialize, Deserialize)]
pub struct BlockedResponse {
    pub error: String,
    pub tier: EscalationTier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub info_urls: Option<InfoUrls>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyResponse {
    pub success: bool,
    /// True when `success` was granted on the failover path — i.e. this
    /// visitor never solved a puzzle, because the service was attestably
    /// unreachable when they loaded the form. Integrators who care about the
    /// difference (accept-but-flag, extra review, tighter downstream limits)
    /// should branch on this; those who don't can keep reading `success`
    /// alone and get availability by default.
    #[serde(default)]
    pub failover: bool,
}

impl VerifyResponse {
    /// The ordinary path: `failover` is false for every solved-puzzle verdict.
    pub fn solved(success: bool) -> Self {
        Self {
            success,
            failover: false,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSiteResponse {
    pub site_key: Uuid,
    pub secret_key: String,
    /// Echoes back the normalized origin allowlist (empty = any origin).
    pub allowed_origins: Vec<String>,
    /// Echoes back the accepted policy. Serializes to `{}` when the site
    /// inherits everything, so the caller can see exactly what was stored.
    #[serde(default)]
    pub policy: SitePolicy,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `VerifyRequest` with everything unset, so each test only states the
    /// fields it actually cares about.
    fn req() -> VerifyRequest {
        VerifyRequest {
            token: None,
            challenge_id: None,
            nonce: 0,
            honeypot: None,
            behavior: None,
            failover: false,
            site_key: None,
            issued_at: None,
        }
    }

    fn expect_solved(r: ResolvedVerify) -> SolvedVerify {
        match r {
            ResolvedVerify::Solved(s) => s,
            ResolvedVerify::Failover(_) => panic!("expected a solved verify"),
        }
    }

    fn expect_failover(r: ResolvedVerify) -> FailoverClaim {
        match r {
            ResolvedVerify::Failover(f) => f,
            ResolvedVerify::Solved(_) => panic!("expected a failover claim"),
        }
    }

    #[test]
    fn resolve_empty_token_falls_through_to_explicit_fields() {
        // `"token": ""` must not shadow the explicit challenge_id/nonce.
        let cid = Uuid::new_v4();
        let resolved = VerifyRequest {
            token: Some(String::new()),
            challenge_id: Some(cid),
            nonce: 42,
            ..req()
        }
        .resolve()
        .expect("empty token falls through");
        let solved = expect_solved(resolved);
        assert_eq!(solved.challenge_id, cid);
        assert_eq!(solved.nonce, 42);
    }

    #[test]
    fn resolve_whitespace_token_falls_through() {
        let cid = Uuid::new_v4();
        let resolved = VerifyRequest {
            token: Some("   ".into()),
            challenge_id: Some(cid),
            nonce: 7,
            ..req()
        }
        .resolve()
        .unwrap();
        assert_eq!(expect_solved(resolved).challenge_id, cid);
    }

    #[test]
    fn resolve_missing_token_and_challenge_id_is_bad_request() {
        assert!(matches!(req().resolve(), Err(CaptchaError::BadRequest(_))));
    }

    #[test]
    fn failover_token_resolves_to_a_claim_not_a_solve() {
        let site = Uuid::new_v4();
        let payload = serde_json::json!({
            "failover": true,
            "site_key": site,
            "issued_at": 1_700_000_000_000i64,
        });
        let token = hex::encode(serde_json::to_vec(&payload).unwrap());
        let claim = expect_failover(
            VerifyRequest {
                token: Some(token),
                ..req()
            }
            .resolve()
            .unwrap(),
        );
        assert_eq!(claim.site_key, site);
        assert_eq!(claim.issued_at_ms, 1_700_000_000_000);
    }

    #[test]
    fn failover_token_without_site_key_is_rejected() {
        let payload = serde_json::json!({ "failover": true, "issued_at": 1i64 });
        let token = hex::encode(serde_json::to_vec(&payload).unwrap());
        assert!(matches!(
            VerifyRequest {
                token: Some(token),
                ..req()
            }
            .resolve(),
            Err(CaptchaError::BadRequest(_))
        ));
    }

    #[test]
    fn non_failover_token_without_challenge_id_is_rejected() {
        // `challenge_id` became Option to make room for the failover arm; a
        // solved token that omits it must still be a hard error rather than
        // silently resolving to a nil UUID.
        let payload = serde_json::json!({ "nonce": 5u64 });
        let token = hex::encode(serde_json::to_vec(&payload).unwrap());
        assert!(matches!(
            VerifyRequest {
                token: Some(token),
                ..req()
            }
            .resolve(),
            Err(CaptchaError::BadRequest(_))
        ));
    }

    #[test]
    fn explicit_failover_fields_resolve_to_a_claim() {
        let site = Uuid::new_v4();
        let claim = expect_failover(
            VerifyRequest {
                failover: true,
                site_key: Some(site),
                issued_at: Some(42),
                ..req()
            }
            .resolve()
            .unwrap(),
        );
        assert_eq!(claim.site_key, site);
        assert_eq!(claim.issued_at_ms, 42);
    }
}
