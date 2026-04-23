use std::sync::Arc;

use crate::config::AppConfig;
use crate::puzzle::challenge::PuzzleEngine;
use crate::puzzle::difficulty::DifficultyCalculator;
use crate::risk::{CookieSigner, RiskScorer, TierThresholds};
use crate::storage::memory::InMemoryStore;

pub type SharedState = Arc<AppState>;

pub struct AppState {
    pub store: Arc<InMemoryStore>,
    pub engine: PuzzleEngine,
    pub difficulty: DifficultyCalculator,
    pub risk: RiskScorer,
    pub cookie_signer: Option<CookieSigner>,
    pub config: AppConfig,
}

pub fn tier_thresholds_from_config(config: &AppConfig) -> TierThresholds {
    TierThresholds {
        checkbox: config.tier_checkbox_min,
        hard_pow: config.tier_hard_pow_min,
        visual: config.tier_visual_min,
        block: config.tier_block_min,
    }
}
