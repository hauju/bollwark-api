//! Read API for the dashboard. Each query opens a fresh read-only SQLite
//! connection in a `spawn_blocking` task — the database is in WAL mode so
//! readers do not contend with the writer. Volume here is operator-driven
//! (a handful of polls per second at most) so connection overhead is fine.

use std::collections::HashMap;
use std::path::PathBuf;

use rusqlite::{Connection, OpenFlags, OptionalExtension, Row};

use super::types::{
    OutcomeCounts, PrivacyCompare, PuzzleBreakdownDto, PuzzleSignalSums, Session, SiteActivity,
    Stats, TierCounts, VerifyBreakdownDto, VerifySection, VerifySignalSums,
};

#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("join: {0}")]
    Join(#[from] tokio::task::JoinError),
}

#[derive(Clone)]
pub struct Sessions {
    db_path: PathBuf,
}

impl Sessions {
    pub fn new(db_path: impl Into<PathBuf>) -> Self {
        Self {
            db_path: db_path.into(),
        }
    }

    pub async fn list(&self, limit: u32) -> Result<Vec<Session>, QueryError> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<Session>, rusqlite::Error> {
            let conn = open_ro(&path)?;
            list_blocking(&conn, limit)
        })
        .await?
        .map_err(QueryError::Sqlite)
    }

    pub async fn get(&self, id: i64) -> Result<Option<Session>, QueryError> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || -> Result<Option<Session>, rusqlite::Error> {
            let conn = open_ro(&path)?;
            get_blocking(&conn, id)
        })
        .await?
        .map_err(QueryError::Sqlite)
    }

    pub async fn stats(&self) -> Result<Stats, QueryError> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(move || -> Result<Stats, rusqlite::Error> {
            let conn = open_ro(&path)?;
            stats_blocking(&conn)
        })
        .await?
        .map_err(QueryError::Sqlite)
    }

    /// Aggregate counts grouped by site_key. Returns a map keyed by the
    /// site_key string so the caller can merge it with the in-memory site
    /// registry without re-scanning. Sites with zero recorded sessions are
    /// simply absent from the map.
    pub async fn site_activity(&self) -> Result<HashMap<String, SiteActivity>, QueryError> {
        let path = self.db_path.clone();
        tokio::task::spawn_blocking(
            move || -> Result<HashMap<String, SiteActivity>, rusqlite::Error> {
                let conn = open_ro(&path)?;
                site_activity_blocking(&conn)
            },
        )
        .await?
        .map_err(QueryError::Sqlite)
    }
}

fn open_ro(path: &PathBuf) -> rusqlite::Result<Connection> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
}

fn list_blocking(conn: &Connection, limit: u32) -> rusqlite::Result<Vec<Session>> {
    let mut stmt = conn.prepare(LIST_SQL)?;
    let rows = stmt.query_map([limit], row_to_session)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn get_blocking(conn: &Connection, id: i64) -> rusqlite::Result<Option<Session>> {
    let mut stmt = conn.prepare(GET_SQL)?;
    stmt.query_row([id], row_to_session).optional()
}

// Column order is shared between LIST_SQL and GET_SQL; row_to_session
// indexes by position so the two SELECTs MUST stay in sync.
const LIST_SQL: &str = "SELECT
    p.id, p.ts, p.challenge_id, p.site_key, p.ip, p.user_agent,
    p.outcome, p.score, p.tier, p.difficulty, p.ip_count, p.site_count,
    p.cookie_presence, p.tls_fingerprint,
    p.sig_rate, p.sig_header_anomaly, p.sig_ip_reputation, p.sig_cookie_age, p.sig_tls_fingerprint,
    v.ts, v.outcome, v.success, v.score,
    v.sig_honeypot, v.sig_time_on_page, v.sig_cookie_age, v.sig_behavior,
    v.time_on_page_ms, v.cookie_presence, v.webdriver,
    p.score_full, p.tier_full, p.score_minimal, p.tier_minimal,
    v.score_full, v.outcome_full, v.score_minimal, v.outcome_minimal
FROM puzzle_decisions p
LEFT JOIN verify_decisions v ON v.challenge_id = p.challenge_id
ORDER BY p.id DESC
LIMIT ?1";

const GET_SQL: &str = "SELECT
    p.id, p.ts, p.challenge_id, p.site_key, p.ip, p.user_agent,
    p.outcome, p.score, p.tier, p.difficulty, p.ip_count, p.site_count,
    p.cookie_presence, p.tls_fingerprint,
    p.sig_rate, p.sig_header_anomaly, p.sig_ip_reputation, p.sig_cookie_age, p.sig_tls_fingerprint,
    v.ts, v.outcome, v.success, v.score,
    v.sig_honeypot, v.sig_time_on_page, v.sig_cookie_age, v.sig_behavior,
    v.time_on_page_ms, v.cookie_presence, v.webdriver,
    p.score_full, p.tier_full, p.score_minimal, p.tier_minimal,
    v.score_full, v.outcome_full, v.score_minimal, v.outcome_minimal
FROM puzzle_decisions p
LEFT JOIN verify_decisions v ON v.challenge_id = p.challenge_id
WHERE p.id = ?1";

#[allow(clippy::cast_sign_loss)]
fn row_to_session(row: &Row<'_>) -> rusqlite::Result<Session> {
    let id: i64 = row.get(0)?;
    let ts: String = row.get(1)?;
    let challenge_id: Option<String> = row.get(2)?;
    let site_key: String = row.get(3)?;
    let ip: String = row.get(4)?;
    let user_agent: Option<String> = row.get(5)?;
    let puzzle_outcome: String = row.get(6)?;
    let puzzle_score: u32 = row.get::<_, i64>(7)? as u32;
    let tier: String = row.get(8)?;
    let difficulty: u32 = row.get::<_, i64>(9)? as u32;
    let ip_count: u32 = row.get::<_, i64>(10)? as u32;
    let site_count: u32 = row.get::<_, i64>(11)? as u32;
    let cookie_presence: String = row.get(12)?;
    let tls_fingerprint: String = row.get(13)?;
    let breakdown = PuzzleBreakdownDto {
        rate: row.get::<_, i64>(14)? as u32,
        header_anomaly: row.get::<_, i64>(15)? as u32,
        ip_reputation: row.get::<_, i64>(16)? as u32,
        cookie_age: row.get::<_, i64>(17)? as u32,
        tls_fingerprint: row.get::<_, i64>(18)? as u32,
    };

    let v_ts: Option<String> = row.get(19)?;
    let verify = if let Some(ts) = v_ts {
        let outcome: String = row.get(20)?;
        let success: i64 = row.get(21)?;
        let score: u32 = row.get::<_, i64>(22)? as u32;
        let v_breakdown = VerifyBreakdownDto {
            honeypot: row.get::<_, i64>(23)? as u32,
            time_on_page: row.get::<_, i64>(24)? as u32,
            cookie_age: row.get::<_, i64>(25)? as u32,
            behavior: row.get::<_, i64>(26)? as u32,
        };
        let time_on_page_ms: Option<i64> = row.get(27)?;
        let v_cookie_presence: String = row.get(28)?;
        let webdriver: String = row.get(29)?;
        let v_score_full: u32 = row.get::<_, i64>(34)? as u32;
        let v_outcome_full: String = row.get(35)?;
        let v_score_minimal: u32 = row.get::<_, i64>(36)? as u32;
        let v_outcome_minimal: String = row.get(37)?;
        Some(VerifySection {
            ts,
            outcome,
            success: success != 0,
            score,
            time_on_page_ms: time_on_page_ms.map(|v| v as u64),
            cookie_presence: v_cookie_presence,
            webdriver,
            breakdown: v_breakdown,
            score_full: v_score_full,
            outcome_full: v_outcome_full,
            score_minimal: v_score_minimal,
            outcome_minimal: v_outcome_minimal,
        })
    } else {
        None
    };

    let puzzle_score_full: u32 = row.get::<_, i64>(30)? as u32;
    let puzzle_tier_full: String = row.get(31)?;
    let puzzle_score_minimal: u32 = row.get::<_, i64>(32)? as u32;
    let puzzle_tier_minimal: String = row.get(33)?;

    let bot_probability = bot_probability(puzzle_score, verify.as_ref().map(|v| v.score));

    Ok(Session {
        id,
        ts,
        challenge_id,
        site_key,
        ip,
        user_agent,
        puzzle_outcome,
        puzzle_score,
        tier,
        difficulty,
        ip_count,
        site_count,
        cookie_presence,
        tls_fingerprint,
        puzzle_breakdown: breakdown,
        verify,
        bot_probability,
        puzzle_score_full,
        puzzle_tier_full,
        puzzle_score_minimal,
        puzzle_tier_minimal,
    })
}

/// Combine puzzle and verify scores into a single 0-100 likelihood. We take
/// the max because either pass is independently sufficient: a clean puzzle
/// score with a tripped honeypot is still clearly a bot. Capping at 100
/// keeps the dashboard label sane even though scores can exceed 100 when
/// multiple signals stack.
fn bot_probability(puzzle: u32, verify: Option<u32>) -> u32 {
    let combined = match verify {
        Some(v) => puzzle.max(v),
        None => puzzle,
    };
    combined.min(100)
}

#[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
fn stats_blocking(conn: &Connection) -> rusqlite::Result<Stats> {
    // Single pass over puzzle_decisions left-joined with verify_decisions.
    // Aggregations only — at most one row returned, so this stays cheap
    // even with millions of rows.
    let row = conn.query_row(
        "SELECT
            COUNT(*),
            COUNT(v.id),
            COALESCE(AVG(p.score), 0.0),
            COALESCE(AVG(v.score), 0.0),
            COALESCE(AVG(MIN(MAX(p.score, COALESCE(v.score, 0)), 100)), 0.0),
            COALESCE(SUM(p.sig_rate), 0),
            COALESCE(SUM(p.sig_header_anomaly), 0),
            COALESCE(SUM(p.sig_ip_reputation), 0),
            COALESCE(SUM(p.sig_cookie_age), 0),
            COALESCE(SUM(p.sig_tls_fingerprint), 0),
            COALESCE(SUM(v.sig_honeypot), 0),
            COALESCE(SUM(v.sig_time_on_page), 0),
            COALESCE(SUM(v.sig_cookie_age), 0),
            COALESCE(SUM(v.sig_behavior), 0),
            SUM(CASE WHEN p.outcome = 'issued'   THEN 1 ELSE 0 END),
            SUM(CASE WHEN p.outcome = 'rejected' THEN 1 ELSE 0 END),
            SUM(CASE WHEN v.outcome = 'pass'         THEN 1 ELSE 0 END),
            SUM(CASE WHEN v.outcome = 'shadow_fail'  THEN 1 ELSE 0 END),
            SUM(CASE WHEN v.outcome = 'block'        THEN 1 ELSE 0 END),
            SUM(CASE WHEN v.outcome = 'pow_invalid'  THEN 1 ELSE 0 END),
            SUM(CASE WHEN p.tier = 'InvisiblePass'    THEN 1 ELSE 0 END),
            SUM(CASE WHEN p.tier = 'Checkbox'         THEN 1 ELSE 0 END),
            SUM(CASE WHEN p.tier = 'HardPow'          THEN 1 ELSE 0 END),
            SUM(CASE WHEN p.tier = 'VisualChallenge'  THEN 1 ELSE 0 END),
            SUM(CASE WHEN p.tier = 'Block'            THEN 1 ELSE 0 END),
            SUM(CASE WHEN p.tier_full <> '' AND p.tier_minimal <> '' AND p.tier_full <> p.tier_minimal THEN 1 ELSE 0 END),
            SUM(CASE WHEN p.tier_full <> '' AND p.tier_minimal <> '' THEN 1 ELSE 0 END),
            SUM(CASE WHEN v.outcome_full <> '' AND v.outcome_minimal <> '' AND v.outcome_full <> v.outcome_minimal THEN 1 ELSE 0 END),
            SUM(CASE WHEN v.outcome_full <> '' AND v.outcome_minimal <> '' THEN 1 ELSE 0 END)
         FROM puzzle_decisions p
         LEFT JOIN verify_decisions v ON v.challenge_id = p.challenge_id",
        [],
        |r| {
            Ok(Stats {
                total_sessions: r.get::<_, i64>(0)? as u64,
                verified_sessions: r.get::<_, i64>(1)? as u64,
                avg_puzzle_score: r.get::<_, f64>(2)?,
                avg_verify_score: r.get::<_, f64>(3)?,
                avg_bot_probability: r.get::<_, f64>(4)?,
                puzzle_signals: PuzzleSignalSums {
                    rate: r.get::<_, i64>(5)? as u64,
                    header_anomaly: r.get::<_, i64>(6)? as u64,
                    ip_reputation: r.get::<_, i64>(7)? as u64,
                    cookie_age: r.get::<_, i64>(8)? as u64,
                    tls_fingerprint: r.get::<_, i64>(9)? as u64,
                },
                verify_signals: VerifySignalSums {
                    honeypot: r.get::<_, i64>(10)? as u64,
                    time_on_page: r.get::<_, i64>(11)? as u64,
                    cookie_age: r.get::<_, i64>(12)? as u64,
                    behavior: r.get::<_, i64>(13)? as u64,
                },
                outcomes: OutcomeCounts {
                    puzzle_issued: opt_i64(r, 14)? as u64,
                    puzzle_rejected: opt_i64(r, 15)? as u64,
                    verify_pass: opt_i64(r, 16)? as u64,
                    verify_shadow_fail: opt_i64(r, 17)? as u64,
                    verify_block: opt_i64(r, 18)? as u64,
                    verify_pow_invalid: opt_i64(r, 19)? as u64,
                },
                tiers: TierCounts {
                    invisible_pass: opt_i64(r, 20)? as u64,
                    checkbox: opt_i64(r, 21)? as u64,
                    hard_pow: opt_i64(r, 22)? as u64,
                    visual_challenge: opt_i64(r, 23)? as u64,
                    block: opt_i64(r, 24)? as u64,
                },
                privacy_compare: PrivacyCompare {
                    puzzle_diverged: opt_i64(r, 25)? as u64,
                    puzzle_total: opt_i64(r, 26)? as u64,
                    verify_diverged: opt_i64(r, 27)? as u64,
                    verify_total: opt_i64(r, 28)? as u64,
                },
            })
        },
    )?;
    Ok(row)
}

// SUM() over zero rows yields NULL in SQLite, which rusqlite surfaces as a
// type error when the target is `i64`. Read as Option and default to 0.
fn opt_i64(row: &Row<'_>, idx: usize) -> rusqlite::Result<i64> {
    Ok(row.get::<_, Option<i64>>(idx)?.unwrap_or(0))
}

#[allow(clippy::cast_sign_loss)]
fn site_activity_blocking(conn: &Connection) -> rusqlite::Result<HashMap<String, SiteActivity>> {
    // Group puzzle decisions by site_key, then left-join verify decisions
    // through challenge_id so we get verify_count and a combined bot
    // probability per site in one pass.
    let mut stmt = conn.prepare(
        "SELECT
            p.site_key,
            COUNT(*),
            COUNT(v.id),
            MAX(p.ts),
            COALESCE(AVG(MIN(MAX(p.score, COALESCE(v.score, 0)), 100)), 0.0)
         FROM puzzle_decisions p
         LEFT JOIN verify_decisions v ON v.challenge_id = p.challenge_id
         GROUP BY p.site_key",
    )?;
    let rows = stmt.query_map([], |row| {
        let site_key: String = row.get(0)?;
        let puzzle_count: i64 = row.get(1)?;
        let verify_count: i64 = row.get(2)?;
        let last_seen: Option<String> = row.get(3)?;
        let avg_bot_probability: f64 = row.get(4)?;
        Ok((
            site_key,
            SiteActivity {
                puzzle_count: puzzle_count as u64,
                verify_count: verify_count as u64,
                last_seen,
                avg_bot_probability,
            },
        ))
    })?;
    let mut out = HashMap::new();
    for row in rows {
        let (k, v) = row?;
        out.insert(k, v);
    }
    Ok(out)
}
