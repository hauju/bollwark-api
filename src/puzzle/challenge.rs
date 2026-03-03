use chrono::{Duration, Utc};
use rand::RngExt;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::types::{Algorithm, Challenge, PuzzleConfig};

pub struct PuzzleEngine {
    config: PuzzleConfig,
}

impl PuzzleEngine {
    pub fn new(config: PuzzleConfig) -> Self {
        Self { config }
    }

    pub fn generate(&self, site_key: Uuid, difficulty: u32) -> Challenge {
        let mut rng = rand::rng();
        let mut prefix_bytes = [0u8; 16];
        rng.fill(&mut prefix_bytes);
        let prefix = hex::encode(prefix_bytes);

        let now = Utc::now();
        let expires_at = now + Duration::seconds(self.config.ttl_secs as i64);

        Challenge {
            id: Uuid::new_v4(),
            site_key,
            algorithm: Algorithm::Sha256,
            prefix,
            difficulty,
            created_at: now,
            expires_at,
            solved: false,
        }
    }

    pub fn verify(&self, challenge: &Challenge, nonce: u64) -> bool {
        let hash = compute_hash(&challenge.prefix, nonce);
        has_leading_zero_bits(&hash, challenge.difficulty)
    }

    pub fn default_difficulty(&self) -> u32 {
        self.config.default_difficulty
    }
}

pub fn compute_hash(prefix: &str, nonce: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(nonce.to_le_bytes());
    hasher.finalize().into()
}

pub fn has_leading_zero_bits(hash: &[u8; 32], difficulty: u32) -> bool {
    let mut remaining = difficulty;

    for &byte in hash {
        if remaining == 0 {
            return true;
        }
        if remaining >= 8 {
            if byte != 0 {
                return false;
            }
            remaining -= 8;
        } else {
            let mask = 0xFF << (8 - remaining);
            return (byte & mask) == 0;
        }
    }

    remaining == 0
}

/// Brute-force solve a challenge (used in tests).
pub fn solve_challenge(prefix: &str, difficulty: u32) -> u64 {
    for nonce in 0u64.. {
        let hash = compute_hash(prefix, nonce);
        if has_leading_zero_bits(&hash, difficulty) {
            return nonce;
        }
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_leading_zero_bits_zero() {
        let hash = [0u8; 32];
        assert!(has_leading_zero_bits(&hash, 0));
        assert!(has_leading_zero_bits(&hash, 8));
        assert!(has_leading_zero_bits(&hash, 256));
    }

    #[test]
    fn test_has_leading_zero_bits_one_bit() {
        // 0x7F = 0111_1111 → 1 leading zero
        let mut hash = [0xFFu8; 32];
        hash[0] = 0x7F;
        assert!(has_leading_zero_bits(&hash, 1));
        assert!(!has_leading_zero_bits(&hash, 2));
    }

    #[test]
    fn test_has_leading_zero_bits_exact_byte_boundary() {
        let mut hash = [0xFFu8; 32];
        hash[0] = 0x00;
        assert!(has_leading_zero_bits(&hash, 8));
        assert!(!has_leading_zero_bits(&hash, 9));
    }

    #[test]
    fn test_has_leading_zero_bits_cross_byte() {
        let mut hash = [0xFFu8; 32];
        hash[0] = 0x00;
        hash[1] = 0x0F; // 0000_1111 → 4 more leading zeros
        assert!(has_leading_zero_bits(&hash, 12));
        assert!(!has_leading_zero_bits(&hash, 13));
    }

    #[test]
    fn test_generate_and_verify() {
        let config = PuzzleConfig {
            default_difficulty: 8,
            min_difficulty: 4,
            max_difficulty: 16,
            ttl_secs: 300,
        };
        let engine = PuzzleEngine::new(config);
        let challenge = engine.generate(Uuid::new_v4(), 8);

        let nonce = solve_challenge(&challenge.prefix, challenge.difficulty);
        assert!(engine.verify(&challenge, nonce));
    }

    #[test]
    fn test_verify_rejects_wrong_nonce() {
        let config = PuzzleConfig {
            default_difficulty: 16,
            min_difficulty: 4,
            max_difficulty: 28,
            ttl_secs: 300,
        };
        let engine = PuzzleEngine::new(config);
        let challenge = engine.generate(Uuid::new_v4(), 16);

        // Nonce u64::MAX is extremely unlikely to be valid
        assert!(!engine.verify(&challenge, u64::MAX));
    }

    #[test]
    fn test_solve_low_difficulty() {
        let config = PuzzleConfig {
            default_difficulty: 4,
            min_difficulty: 4,
            max_difficulty: 16,
            ttl_secs: 300,
        };
        let engine = PuzzleEngine::new(config);
        let challenge = engine.generate(Uuid::new_v4(), 4);

        let nonce = solve_challenge(&challenge.prefix, challenge.difficulty);
        assert!(engine.verify(&challenge, nonce));
    }
}
