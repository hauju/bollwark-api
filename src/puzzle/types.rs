use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Argon2id parameters for memory-hard PoW. Matches the upstream
/// `argon2::Params` shape; values are stamped on each challenge so the
/// client knows exactly which hash to compute and the server can tune
/// without redeploying clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2idParams {
    /// Memory cost in KiB. Default 8192 (8 MiB) — small enough to fit on
    /// mobile, large enough to defeat trivial GPU parallelisation.
    pub m_cost: u32,
    /// Iteration count. Default 2.
    pub t_cost: u32,
    /// Parallelism / lanes. Default 1 (single-thread worker).
    pub p_cost: u32,
}

impl Default for Argon2idParams {
    fn default() -> Self {
        Self {
            m_cost: 8_192,
            t_cost: 2,
            p_cost: 1,
        }
    }
}

/// PoW algorithm. Chosen per server (via `PUZZLE_ALGORITHM`) and stamped on
/// each challenge so the client picks the right hash function.
///
/// Wire format is backward-compatible: `Sha256` serialises as the bare
/// string `"sha256"` (matching the original API), while
/// `Argon2id(params)` serialises as `{"argon2id": {...}}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Algorithm {
    Sha256,
    Argon2id(Argon2idParams),
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
    /// Failed PoW verify attempts against this challenge. A wrong nonce
    /// deliberately leaves the challenge live for retry, so without a cap one
    /// challenge could absorb unlimited (potentially memory-hard) verify
    /// attempts. The store evicts the challenge once this reaches
    /// `VERIFY_MAX_ATTEMPTS`.
    #[serde(default)]
    pub attempts: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Solution {
    pub challenge_id: Uuid,
    pub nonce: u64,
}

#[derive(Debug, Clone)]
pub struct PuzzleConfig {
    pub algorithm: Algorithm,
    pub default_difficulty: u32,
    pub ttl_secs: u64,
}

impl Default for PuzzleConfig {
    fn default() -> Self {
        Self {
            algorithm: Algorithm::Sha256,
            default_difficulty: 20,
            ttl_secs: 300,
        }
    }
}
