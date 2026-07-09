pub mod behavior;
pub mod client_ip;
pub mod load;
pub mod reputation;
pub mod score;
pub mod signals;
pub mod tier;
pub mod tls_fingerprint;
pub mod verify;

pub use behavior::{BehaviorPresence, BehaviorReport};
pub use client_ip::{anonymize_ip, client_ip, rate_key};
pub use load::LoadLadder;
pub use reputation::{CidrListReputation, IpCategory, ReputationStore};
pub use score::{RiskScore, RiskScorer, SignalBreakdown, SignalContext};
pub use tier::{EscalationTier, TierThresholds, difficulty_for};
pub use tls_fingerprint::{FingerprintBlocklist, TlsFingerprint, TrustedProxies};
pub use verify::{
    VerifyBreakdown, VerifyContext, VerifyDecision, VerifyScore, VerifyScorer, VerifyThresholds,
};
