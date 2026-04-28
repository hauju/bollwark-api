use serde::Serialize;
use uuid::Uuid;

use crate::risk::verify::VerifyBreakdown;
use crate::risk::{EscalationTier, SignalBreakdown};

/// Per-decision record emitted from the puzzle handler. Mirrors the fields
/// in the existing `puzzle_decision` tracing event so the dashboard table
/// matches what an operator already sees in the JSONL stream.
#[derive(Debug, Clone)]
pub struct PuzzleRecord {
    pub challenge_id: Option<Uuid>,
    pub site_key: Uuid,
    pub ip: String,
    pub ip_count: u32,
    pub site_count: u32,
    pub score: u32,
    pub tier: EscalationTier,
    pub difficulty: u32,
    pub outcome: &'static str,
    pub breakdown: SignalBreakdown,
    pub cookie_presence: String,
    pub tls_fingerprint: String,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VerifyRecord {
    pub challenge_id: Uuid,
    pub success: bool,
    pub outcome: &'static str,
    pub score: u32,
    pub breakdown: VerifyBreakdown,
    pub time_on_page_ms: Option<u64>,
    pub cookie_presence: String,
    pub webdriver: &'static str,
}

/// Wire format returned by the admin API. One row per puzzle decision; verify
/// fields are populated when the matching `/v1/verify` call has occurred.
#[derive(Debug, Clone, Serialize)]
pub struct Session {
    pub id: i64,
    pub ts: String,
    pub challenge_id: Option<String>,
    pub site_key: String,
    pub ip: String,
    pub user_agent: Option<String>,
    pub puzzle_outcome: String,
    pub puzzle_score: u32,
    pub tier: String,
    pub difficulty: u32,
    pub ip_count: u32,
    pub site_count: u32,
    pub cookie_presence: String,
    pub tls_fingerprint: String,
    pub puzzle_breakdown: PuzzleBreakdownDto,
    pub verify: Option<VerifySection>,
    /// Combined bot-likelihood score, 0–100. Max of puzzle and verify scores
    /// (clamped). When verify hasn't happened yet, it's just the puzzle score.
    pub bot_probability: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct PuzzleBreakdownDto {
    pub rate: u32,
    pub header_anomaly: u32,
    pub ip_reputation: u32,
    pub cookie_age: u32,
    pub tls_fingerprint: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifySection {
    pub ts: String,
    pub outcome: String,
    pub success: bool,
    pub score: u32,
    pub time_on_page_ms: Option<u64>,
    pub cookie_presence: String,
    pub webdriver: String,
    pub breakdown: VerifyBreakdownDto,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyBreakdownDto {
    pub honeypot: u32,
    pub time_on_page: u32,
    pub cookie_age: u32,
    pub behavior: u32,
}

/// Aggregate stats across every recorded session. Computed via a single
/// SQL aggregation pass — much cheaper than streaming back every row and
/// summing on the client.
#[derive(Debug, Clone, Serialize)]
pub struct Stats {
    pub total_sessions: u64,
    pub verified_sessions: u64,
    pub avg_puzzle_score: f64,
    pub avg_verify_score: f64,
    pub avg_bot_probability: f64,
    pub puzzle_signals: PuzzleSignalSums,
    pub verify_signals: VerifySignalSums,
    pub outcomes: OutcomeCounts,
    pub tiers: TierCounts,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PuzzleSignalSums {
    pub rate: u64,
    pub header_anomaly: u64,
    pub ip_reputation: u64,
    pub cookie_age: u64,
    pub tls_fingerprint: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct VerifySignalSums {
    pub honeypot: u64,
    pub time_on_page: u64,
    pub cookie_age: u64,
    pub behavior: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct OutcomeCounts {
    pub puzzle_issued: u64,
    pub puzzle_rejected: u64,
    pub verify_pass: u64,
    pub verify_shadow_fail: u64,
    pub verify_block: u64,
    pub verify_pow_invalid: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TierCounts {
    pub invisible_pass: u64,
    pub checkbox: u64,
    pub hard_pow: u64,
    pub visual_challenge: u64,
    pub block: u64,
}

/// Aggregate counts for a single site, drawn from the decision log.
/// Keyed by `site_key` (string-formatted UUID) so the route handler can
/// merge it with the in-memory site registry by lookup.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SiteActivity {
    pub puzzle_count: u64,
    pub verify_count: u64,
    pub last_seen: Option<String>,
    pub avg_bot_probability: f64,
}

/// Wire format for `GET /v1/admin/sites`. Combines the registered site
/// (from `InMemoryStore`) with activity aggregates from the decision log.
/// `secret_key` is intentionally omitted — secrets are revealed once at
/// registration time and the dashboard has no need to display them.
#[derive(Debug, Clone, Serialize)]
pub struct SiteSummary {
    pub site_key: String,
    pub name: String,
    pub created_at: String,
    pub puzzle_count: u64,
    pub verify_count: u64,
    pub last_seen: Option<String>,
    pub avg_bot_probability: f64,
}
