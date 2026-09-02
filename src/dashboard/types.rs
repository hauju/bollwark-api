use serde::Serialize;
use uuid::Uuid;

use crate::risk::verify::VerifyBreakdown;
use crate::risk::{EscalationTier, SignalBreakdown};

/// Per-decision record emitted from the puzzle handler. Mirrors the fields
/// in the `puzzle_decision` tracing event so the dashboard table matches what
/// an operator already sees in the JSONL stream.
#[derive(Debug, Clone)]
pub struct PuzzleRecord {
    /// The site is in [`crate::site::types::SiteMode::Monitor`] and this row's
    /// `tier` is a Block that was *not* enforced — a puzzle was issued anyway.
    /// Recorded rather than folded into `outcome` so the dashboard's existing
    /// tier/outcome aggregates keep answering "what would I block?" unchanged.
    pub monitored: bool,
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
    /// Canonical IP-reputation category (`tor`/`datacenter`/`vpn`/
    /// `residential`), or `None` when no reputation list matched the IP.
    /// Stored alongside the numeric `breakdown.ip_reputation`.
    pub ip_reputation_category: Option<&'static str>,
    pub tls_fingerprint: String,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VerifyRecord {
    /// The site is monitoring and this row's `outcome` is a Block that was not
    /// enforced, so `success` is true despite it. See [`PuzzleRecord`].
    pub monitored: bool,
    pub challenge_id: Uuid,
    pub success: bool,
    pub outcome: &'static str,
    pub score: u32,
    pub breakdown: VerifyBreakdown,
    pub time_on_page_ms: Option<u64>,
    pub webdriver: &'static str,
}

/// Wire format returned by the admin API. One row per puzzle decision; verify
/// fields are populated when the matching `/v1/verify` call has occurred.
#[derive(Debug, Clone, Serialize)]
pub struct Session {
    /// The puzzle-side risk verdict in `tier` was recorded but not enforced —
    /// the site is in monitor mode and a puzzle was issued anyway.
    #[serde(default)]
    pub monitored: bool,
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
    pub tls_fingerprint: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifySection {
    /// `outcome` is a Block that was not enforced, so `success` is true.
    #[serde(default)]
    pub monitored: bool,
    pub ts: String,
    pub outcome: String,
    pub success: bool,
    pub score: u32,
    pub time_on_page_ms: Option<u64>,
    pub webdriver: String,
    pub breakdown: VerifyBreakdownDto,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyBreakdownDto {
    pub honeypot: u32,
    pub time_on_page: u32,
    pub behavior: u32,
    pub remote_ip: u32,
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
    /// Decision-log records dropped because the writer queue was full since
    /// this process started. Non-zero means SQLite can't keep up with the
    /// request rate — the durable log is undercounting. Sourced from the
    /// in-memory drop counter, not the database.
    pub dropped_records: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PuzzleSignalSums {
    pub rate: u64,
    pub header_anomaly: u64,
    pub ip_reputation: u64,
    pub tls_fingerprint: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct VerifySignalSums {
    pub honeypot: u64,
    pub time_on_page: u64,
    pub behavior: u64,
    pub remote_ip: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct OutcomeCounts {
    pub puzzle_issued: u64,
    pub puzzle_rejected: u64,
    pub verify_pass: u64,
    pub verify_shadow_fail: u64,
    pub verify_block: u64,
    pub verify_pow_invalid: u64,
    /// Of the counts above, how many were *observed rather than enforced*
    /// because the site is in monitor mode. Split out rather than excluded so
    /// the block counts keep answering "what would I block?" — subtract these
    /// to get what was actually refused.
    #[serde(default)]
    pub puzzle_monitored: u64,
    #[serde(default)]
    pub verify_monitored: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TierCounts {
    pub invisible_pass: u64,
    pub checkbox: u64,
    pub hard_pow: u64,
    pub block: u64,
}

/// Windowed analytics for the dashboard's Analytics tab: time-bucketed
/// traffic/outcome/tier series plus distribution breakdowns, all computed
/// over the last `window_hours` (optionally filtered to one site).
#[derive(Debug, Clone, Serialize)]
pub struct Analytics {
    pub window_hours: u32,
    pub bucket_secs: u32,
    /// Dense series — every bucket in the window is present, zero-filled,
    /// so the chart renderer never has to interpolate gaps.
    pub buckets: Vec<TimeBucket>,
    /// Combined bot-probability distribution, 10 bins (0–9 … 90–100).
    pub bot_histogram: Vec<u64>,
    /// Browser-family counts parsed from the logged User-Agent, sorted
    /// descending.
    pub browsers: Vec<BrowserCount>,
    /// Bot-family counts for the automated slice of traffic, sorted
    /// descending — a finer split of the single "bot/script" browser family.
    /// Sessions with a non-automated UA don't appear here.
    pub bots: Vec<BotCount>,
    /// IP-reputation network-type counts (datacenter/tor/vpn/residential),
    /// sorted descending. Only sessions whose IP matched the reputation list
    /// appear here, so the panel is empty when no `IP_REPUTATION_FILE` is set.
    pub network_types: Vec<NetworkTypeCount>,
    /// ISO country-code counts from the offline GeoIP lookup stamped at
    /// log-write time, sorted descending. Empty when `GEOIP_DB_PATH` is unset
    /// (every row's `country` column is NULL).
    pub countries: Vec<CountryCount>,
    /// Per-signal fire counts: number of sessions in the window where the
    /// signal contributed a non-zero score.
    pub signal_fires: SignalFires,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TimeBucket {
    /// Bucket start, RFC3339 UTC.
    pub t: String,
    pub puzzles: u64,
    pub verifies: u64,
    pub issued: u64,
    pub rejected: u64,
    pub pass: u64,
    pub shadow_fail: u64,
    pub block: u64,
    pub pow_invalid: u64,
    pub tier_invisible_pass: u64,
    pub tier_checkbox: u64,
    pub tier_hard_pow: u64,
    pub tier_block: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BrowserCount {
    pub name: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BotCount {
    pub name: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkTypeCount {
    pub name: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CountryCount {
    pub name: String,
    pub count: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SignalFires {
    pub rate: u64,
    pub header_anomaly: u64,
    pub ip_reputation: u64,
    pub tls_fingerprint: u64,
    pub honeypot: u64,
    pub time_on_page: u64,
    pub behavior: u64,
    pub remote_ip: u64,
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
    /// Browser-origin allowlist (empty = any origin allowed).
    pub allowed_origins: Vec<String>,
    /// Per-site scoring overrides. `{}` means the site inherits every
    /// process default.
    pub policy: crate::site::types::SitePolicy,
    pub puzzle_count: u64,
    pub verify_count: u64,
    pub last_seen: Option<String>,
    pub avg_bot_probability: f64,
}
