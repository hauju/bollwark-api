use argon2::{Algorithm as Argon2Algorithm, Argon2, Params, Version};
use chrono::{Duration, Utc};
use rand::RngExt;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::types::{Algorithm, Argon2idParams, Challenge, PuzzleConfig};

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
            algorithm: self.config.algorithm,
            prefix,
            difficulty,
            created_at: now,
            expires_at,
            solved: false,
        }
    }

    pub fn verify(&self, challenge: &Challenge, nonce: u64) -> bool {
        match challenge.algorithm {
            Algorithm::Sha256 => {
                let hash = compute_sha256(&challenge.prefix, nonce);
                has_leading_zero_bits(&hash, challenge.difficulty)
            }
            Algorithm::Argon2id(params) => match compute_argon2id(&challenge.prefix, nonce, params)
            {
                Some(hash) => has_leading_zero_bits(&hash, challenge.difficulty),
                None => false,
            },
        }
    }

    pub fn default_difficulty(&self) -> u32 {
        self.config.default_difficulty
    }
}

pub fn compute_sha256(prefix: &str, nonce: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(nonce.to_le_bytes());
    hasher.finalize().into()
}

/// Argon2id PoW hash. Returns `None` if the upstream params are invalid
/// (e.g. `m_cost`/`t_cost` zero) — the verifier treats that as a failed
/// solution rather than a server error so a bad client can't crash us.
///
/// The salt is the challenge prefix bytes (16 bytes of hex → 32 bytes of
/// salt material). The "password" is the little-endian nonce. We take the
/// first 32 bytes of output to match the SHA-256 path so
/// `has_leading_zero_bits` works unchanged.
pub fn compute_argon2id(prefix: &str, nonce: u64, params: Argon2idParams) -> Option<[u8; 32]> {
    let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32)).ok()?;
    let argon = Argon2::new(Argon2Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(&nonce.to_le_bytes(), prefix.as_bytes(), &mut out)
        .ok()?;
    Some(out)
}

/// Back-compat alias retained for existing callers / tests.
pub fn compute_hash(prefix: &str, nonce: u64) -> [u8; 32] {
    compute_sha256(prefix, nonce)
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

/// Brute-force solve a SHA-256 challenge (used in tests).
pub fn solve_challenge(prefix: &str, difficulty: u32) -> u64 {
    for nonce in 0u64.. {
        let hash = compute_sha256(prefix, nonce);
        if has_leading_zero_bits(&hash, difficulty) {
            return nonce;
        }
    }
    unreachable!()
}

/// Brute-force solve an Argon2id challenge (used in tests).
pub fn solve_argon2id_challenge(prefix: &str, difficulty: u32, params: Argon2idParams) -> u64 {
    for nonce in 0u64.. {
        if let Some(hash) = compute_argon2id(prefix, nonce, params)
            && has_leading_zero_bits(&hash, difficulty)
        {
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
            algorithm: Algorithm::Sha256,
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
            algorithm: Algorithm::Sha256,
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
            algorithm: Algorithm::Sha256,
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

    // --- Argon2id ---

    fn argon_test_params() -> Argon2idParams {
        // Minimum-cost params keep the test fast: 8 KiB memory, 1 iteration,
        // 1 lane. Real-world server config would use the defaults (8 MiB / 2 / 1).
        Argon2idParams {
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn test_argon2id_generate_and_verify() {
        let config = PuzzleConfig {
            algorithm: Algorithm::Argon2id(argon_test_params()),
            default_difficulty: 4,
            min_difficulty: 1,
            max_difficulty: 8,
            ttl_secs: 300,
        };
        let engine = PuzzleEngine::new(config);
        let challenge = engine.generate(Uuid::new_v4(), 4);
        assert!(matches!(challenge.algorithm, Algorithm::Argon2id(_)));

        let nonce =
            solve_argon2id_challenge(&challenge.prefix, challenge.difficulty, argon_test_params());
        assert!(engine.verify(&challenge, nonce));
    }

    #[test]
    fn test_argon2id_rejects_wrong_nonce() {
        let config = PuzzleConfig {
            algorithm: Algorithm::Argon2id(argon_test_params()),
            default_difficulty: 4,
            min_difficulty: 1,
            max_difficulty: 8,
            ttl_secs: 300,
        };
        let engine = PuzzleEngine::new(config);
        let challenge = engine.generate(Uuid::new_v4(), 4);
        assert!(!engine.verify(&challenge, u64::MAX));
    }

    #[test]
    fn test_argon2id_invalid_params_dont_crash() {
        // m_cost = 0 is invalid for Argon2id. compute_argon2id should return
        // None and verify() should treat that as a failed solution rather
        // than panic.
        let bad = Argon2idParams {
            m_cost: 0,
            t_cost: 1,
            p_cost: 1,
        };
        assert!(compute_argon2id("deadbeef", 0, bad).is_none());
    }
}
