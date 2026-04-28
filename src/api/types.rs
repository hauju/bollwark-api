use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::puzzle::types::{Algorithm, ChallengeKind};
use crate::risk::{BehaviorReport, EscalationTier};

// --- Requests ---

#[derive(Debug, Deserialize)]
pub struct GetPuzzleParams {
    pub site_key: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub challenge_id: Uuid,
    /// PoW nonce. Required for `kind=pow` challenges; ignored for
    /// `kind=image` (defaults to 0 so visual-only clients don't need to
    /// send a placeholder).
    #[serde(default)]
    pub nonce: u64,
    /// User-typed answer for visual (image-text) challenges. Required when
    /// the challenge is `kind=image`; ignored for `kind=pow`.
    #[serde(default)]
    pub text_answer: Option<String>,
    #[serde(default)]
    pub honeypot: Option<String>,
    /// Milliseconds elapsed between widget mount and form submit. Optional —
    /// callers that don't use the bundled widget may not send this.
    #[serde(default)]
    pub time_on_page_ms: Option<u64>,
    /// Compact behavioural telemetry collected by the widget between mount
    /// and submit. Absent for non-widget integrations.
    #[serde(default)]
    pub behavior: Option<BehaviorReport>,
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
    /// Discriminator for the puzzle type. `pow` (default for backward-compat)
    /// uses `algorithm`/`prefix`/`difficulty` and is solved by the worker;
    /// `image` uses `image` (a base64 PNG data URL) and is solved by the
    /// user reading and typing the characters.
    #[serde(default)]
    pub kind: ChallengeKind,
    pub algorithm: Algorithm,
    pub prefix: String,
    pub difficulty: u32,
    /// Base64 PNG data URL of a visual challenge. Present only when
    /// `kind == image`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
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
