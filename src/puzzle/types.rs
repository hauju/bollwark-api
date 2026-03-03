use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Algorithm {
    Sha256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub id: Uuid,
    pub site_key: Uuid,
    pub algorithm: Algorithm,
    pub prefix: String,
    pub difficulty: u32,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub solved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Solution {
    pub challenge_id: Uuid,
    pub nonce: u64,
}

#[derive(Debug, Clone)]
pub struct PuzzleConfig {
    pub default_difficulty: u32,
    pub min_difficulty: u32,
    pub max_difficulty: u32,
    pub ttl_secs: u64,
}

impl Default for PuzzleConfig {
    fn default() -> Self {
        Self {
            default_difficulty: 20,
            min_difficulty: 16,
            max_difficulty: 28,
            ttl_secs: 300,
        }
    }
}
