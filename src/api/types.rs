use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::CaptchaError;
use crate::puzzle::types::Algorithm;
use crate::risk::{BehaviorReport, EscalationTier};

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
    /// Required when `token` is absent.
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
}

/// Inner payload carried by the opaque `token`. The widget hex-encodes the
/// JSON form of this so the form host treats it as an opaque blob.
#[derive(Debug, Deserialize)]
struct TokenPayload {
    challenge_id: Uuid,
    #[serde(default)]
    nonce: u64,
    #[serde(default)]
    honeypot: Option<String>,
    #[serde(default)]
    behavior: Option<BehaviorReport>,
}

/// Normalised verify fields after resolving either the opaque token or the
/// explicit body. `time_on_page_ms` is deliberately not here — it's computed
/// server-side from the challenge's `created_at`.
pub struct ResolvedVerify {
    pub challenge_id: Uuid,
    pub nonce: u64,
    pub honeypot: Option<String>,
    pub behavior: Option<BehaviorReport>,
}

impl VerifyRequest {
    /// Resolve into the normalised fields. Decodes the opaque token when
    /// present, otherwise falls back to the explicit fields.
    pub fn resolve(self) -> Result<ResolvedVerify, CaptchaError> {
        if let Some(token) = self.token.as_deref() {
            let bytes = hex::decode(token.trim())
                .map_err(|_| CaptchaError::BadRequest("invalid captcha token".into()))?;
            let p: TokenPayload = serde_json::from_slice(&bytes)
                .map_err(|_| CaptchaError::BadRequest("invalid captcha token".into()))?;
            Ok(ResolvedVerify {
                challenge_id: p.challenge_id,
                nonce: p.nonce,
                honeypot: p.honeypot,
                behavior: p.behavior,
            })
        } else {
            let challenge_id = self.challenge_id.ok_or_else(|| {
                CaptchaError::BadRequest("challenge_id or token is required".into())
            })?;
            Ok(ResolvedVerify {
                challenge_id,
                nonce: self.nonce,
                honeypot: self.honeypot,
                behavior: self.behavior,
            })
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateSiteRequest {
    pub name: String,
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
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSiteResponse {
    pub site_key: Uuid,
    pub secret_key: String,
}
