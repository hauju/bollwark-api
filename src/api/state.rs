use std::sync::Arc;

use crate::config::AppConfig;
use crate::puzzle::challenge::PuzzleEngine;
use crate::puzzle::difficulty::DifficultyCalculator;
use crate::storage::memory::InMemoryStore;

pub type SharedState = Arc<AppState>;

pub struct AppState {
    pub store: Arc<InMemoryStore>,
    pub engine: PuzzleEngine,
    pub difficulty: DifficultyCalculator,
    pub config: AppConfig,
}
