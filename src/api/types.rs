use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::puzzle::types::Algorithm;

// --- Requests ---

#[derive(Debug, Deserialize)]
pub struct GetPuzzleParams {
    pub site_key: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub challenge_id: Uuid,
    pub nonce: u64,
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
