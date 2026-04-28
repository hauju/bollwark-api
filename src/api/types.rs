use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::puzzle::types::Algorithm;
use crate::risk::{BehaviorReport, EscalationTier};

// --- Requests ---

#[derive(Debug, Deserialize)]
pub struct GetPuzzleParams {
    pub site_key: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub challenge_id: Uuid,
    pub nonce: u64,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct PuzzleResponse {
    pub challenge_id: Uuid,
    pub algorithm: Algorithm,
    pub prefix: String,
    pub difficulty: u32,
    pub expires_at: String,
    pub tier: EscalationTier,
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
