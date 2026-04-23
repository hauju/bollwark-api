pub mod cookie;
pub mod reputation;
pub mod score;
pub mod signals;
pub mod tier;

pub use cookie::CookieSigner;
pub use reputation::{CidrListReputation, IpCategory};
pub use score::{RiskScore, RiskScorer, SignalBreakdown, SignalContext};
pub use signals::CookiePresence;
pub use tier::{EscalationTier, TierThresholds, difficulty_for};
