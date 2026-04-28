pub mod behavior;
pub mod client_ip;
pub mod cookie;
pub mod reputation;
pub mod score;
pub mod signals;
pub mod tier;
pub mod tls_fingerprint;
pub mod verify;

pub use behavior::{BehaviorPresence, BehaviorReport};
pub use client_ip::client_ip;
pub use cookie::{CookieSameSite, CookieSigner};
pub use reputation::{CidrListReputation, IpCategory};
pub use score::{RiskScore, RiskScorer, SignalBreakdown, SignalContext};
pub use signals::CookiePresence;
pub use tier::{EscalationTier, TierThresholds, difficulty_for};
pub use tls_fingerprint::{FingerprintBlocklist, TlsFingerprint, TrustedProxies};
pub use verify::{VerifyContext, VerifyDecision, VerifyScorer, VerifyThresholds};
