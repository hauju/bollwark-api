use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationTier {
    InvisiblePass,
    Checkbox,
    HardPow,
    Block,
}

#[derive(Debug, Clone, Copy)]
pub struct TierThresholds {
    pub checkbox: u32,
    pub hard_pow: u32,
    pub block: u32,
}

impl Default for TierThresholds {
    fn default() -> Self {
        Self {
            checkbox: 20,
            hard_pow: 40,
            block: 85,
        }
    }
}

impl TierThresholds {
    pub fn classify(&self, score: u32) -> EscalationTier {
        if score >= self.block {
            EscalationTier::Block
        } else if score >= self.hard_pow {
            EscalationTier::HardPow
        } else if score >= self.checkbox {
            EscalationTier::Checkbox
        } else {
            EscalationTier::InvisiblePass
        }
    }
}

/// Map a chosen tier to a PoW difficulty adjustment relative to the base.
/// Returns `None` for `Block` (rejected with 429, no puzzle issued).
pub fn difficulty_for(
    tier: EscalationTier,
    default_difficulty: u32,
    max_difficulty: u32,
) -> Option<u32> {
    let bump = match tier {
        EscalationTier::InvisiblePass => 0,
        EscalationTier::Checkbox => 2,
        EscalationTier::HardPow => 4,
        EscalationTier::Block => return None,
    };
    Some(default_difficulty.saturating_add(bump).min(max_difficulty))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_invisible_below_checkbox_threshold() {
        let t = TierThresholds::default();
        assert_eq!(t.classify(0), EscalationTier::InvisiblePass);
        assert_eq!(t.classify(19), EscalationTier::InvisiblePass);
    }

    #[test]
    fn classify_boundary_values() {
        let t = TierThresholds::default();
        assert_eq!(t.classify(20), EscalationTier::Checkbox);
        assert_eq!(t.classify(39), EscalationTier::Checkbox);
        assert_eq!(t.classify(40), EscalationTier::HardPow);
        // The old VisualChallenge band (65–84) now folds into HardPow.
        assert_eq!(t.classify(64), EscalationTier::HardPow);
        assert_eq!(t.classify(65), EscalationTier::HardPow);
        assert_eq!(t.classify(84), EscalationTier::HardPow);
        assert_eq!(t.classify(85), EscalationTier::Block);
        assert_eq!(t.classify(200), EscalationTier::Block);
    }

    #[test]
    fn difficulty_mapping_clamps_to_max() {
        assert_eq!(difficulty_for(EscalationTier::HardPow, 26, 28), Some(28));
        assert_eq!(difficulty_for(EscalationTier::Checkbox, 26, 28), Some(28));
    }

    #[test]
    fn difficulty_mapping_invisible_is_base() {
        assert_eq!(
            difficulty_for(EscalationTier::InvisiblePass, 20, 28),
            Some(20)
        );
    }

    #[test]
    fn difficulty_mapping_block_is_none() {
        assert_eq!(difficulty_for(EscalationTier::Block, 20, 28), None);
    }

    #[test]
    fn serializes_as_snake_case() {
        assert_eq!(
            serde_json::to_string(&EscalationTier::InvisiblePass).unwrap(),
            "\"invisible_pass\""
        );
        assert_eq!(
            serde_json::to_string(&EscalationTier::HardPow).unwrap(),
            "\"hard_pow\""
        );
        assert_eq!(
            serde_json::to_string(&EscalationTier::Block).unwrap(),
            "\"block\""
        );
    }
}
