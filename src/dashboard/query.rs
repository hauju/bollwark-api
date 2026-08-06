//! Read API for the dashboard. Each query opens a fresh read-only SQLite
//! connection in a `spawn_blocking` task — the database is in WAL mode so
//! readers do not contend with the writer. Volume here is operator-driven
//! (a handful of polls per second at most) so connection overhead is fine.

use std::collections::HashMap;
use std::path::PathBuf;

use rusqlite::{Connection, OpenFlags, OptionalExtension, Row};

use super::types::{
    Analytics, BotCount, BrowserCount, CountryCount, NetworkTypeCount, OutcomeCounts,
    PuzzleBreakdownDto, PuzzleSignalSums, Session, SignalFires, SiteActivity, Stats, TierCounts,
    TimeBucket, VerifyBreakdownDto, VerifySection, VerifySignalSums,
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

    /// Windowed analytics over the last `hours`, optionally filtered to one
    /// site. Bucket size is derived from the window so the chart always has
    /// a readable number of points.
    pub async fn analytics(
        &self,
        hours: u32,
        site_key: Option<String>,
    ) -> Result<Analytics, QueryError> {
        let path = self.db_path.clone();
        let now_epoch = chrono::Utc::now().timestamp();
        tokio::task::spawn_blocking(move || -> Result<Analytics, rusqlite::Error> {
            let conn = open_ro(&path)?;
            analytics_blocking(&conn, hours, now_epoch, site_key.as_deref())
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
    p.tls_fingerprint,
    p.sig_rate, p.sig_header_anomaly, p.sig_ip_reputation, p.sig_tls_fingerprint,
    v.ts, v.outcome, v.success, v.score,
    v.sig_honeypot, v.sig_time_on_page, v.sig_behavior,
    v.time_on_page_ms, v.webdriver,
    p.monitored, v.monitored
FROM puzzle_decisions p
LEFT JOIN verify_decisions v ON v.challenge_id = p.challenge_id
ORDER BY p.id DESC
LIMIT ?1";

const GET_SQL: &str = "SELECT
    p.id, p.ts, p.challenge_id, p.site_key, p.ip, p.user_agent,
    p.outcome, p.score, p.tier, p.difficulty, p.ip_count, p.site_count,
    p.tls_fingerprint,
    p.sig_rate, p.sig_header_anomaly, p.sig_ip_reputation, p.sig_tls_fingerprint,
    v.ts, v.outcome, v.success, v.score,
    v.sig_honeypot, v.sig_time_on_page, v.sig_behavior,
    v.time_on_page_ms, v.webdriver,
    p.monitored, v.monitored
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
    let tls_fingerprint: String = row.get(12)?;
    let breakdown = PuzzleBreakdownDto {
        rate: row.get::<_, i64>(13)? as u32,
        header_anomaly: row.get::<_, i64>(14)? as u32,
        ip_reputation: row.get::<_, i64>(15)? as u32,
        tls_fingerprint: row.get::<_, i64>(16)? as u32,
    };

    let v_ts: Option<String> = row.get(17)?;
    let verify = if let Some(ts) = v_ts {
        let outcome: String = row.get(18)?;
        let success: i64 = row.get(19)?;
        let score: u32 = row.get::<_, i64>(20)? as u32;
        let v_breakdown = VerifyBreakdownDto {
            honeypot: row.get::<_, i64>(21)? as u32,
            time_on_page: row.get::<_, i64>(22)? as u32,
            behavior: row.get::<_, i64>(23)? as u32,
        };
        let time_on_page_ms: Option<i64> = row.get(24)?;
        let webdriver: String = row.get(25)?;
        let v_monitored: i64 = row.get(27).unwrap_or(0);
        Some(VerifySection {
            ts,
            outcome,
            success: success != 0,
            monitored: v_monitored != 0,
            score,
            time_on_page_ms: time_on_page_ms.map(|v| v as u64),
            webdriver,
            breakdown: v_breakdown,
        })
    } else {
        None
    };

    let monitored: i64 = row.get(26)?;
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
        tls_fingerprint,
        monitored: monitored != 0,
        puzzle_breakdown: breakdown,
        verify,
        bot_probability,
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
            COALESCE(SUM(p.sig_tls_fingerprint), 0),
            COALESCE(SUM(v.sig_honeypot), 0),
            COALESCE(SUM(v.sig_time_on_page), 0),
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
            SUM(CASE WHEN p.tier = 'Block'            THEN 1 ELSE 0 END),
            SUM(CASE WHEN p.monitored = 1 THEN 1 ELSE 0 END),
            SUM(CASE WHEN v.monitored = 1 THEN 1 ELSE 0 END)
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
                    tls_fingerprint: r.get::<_, i64>(8)? as u64,
                },
                verify_signals: VerifySignalSums {
                    honeypot: r.get::<_, i64>(9)? as u64,
                    time_on_page: r.get::<_, i64>(10)? as u64,
                    behavior: r.get::<_, i64>(11)? as u64,
                },
                outcomes: OutcomeCounts {
                    puzzle_issued: opt_i64(r, 12)? as u64,
                    puzzle_rejected: opt_i64(r, 13)? as u64,
                    verify_pass: opt_i64(r, 14)? as u64,
                    verify_shadow_fail: opt_i64(r, 15)? as u64,
                    verify_block: opt_i64(r, 16)? as u64,
                    verify_pow_invalid: opt_i64(r, 17)? as u64,
                    puzzle_monitored: opt_i64(r, 22)? as u64,
                    verify_monitored: opt_i64(r, 23)? as u64,
                },
                tiers: TierCounts {
                    invisible_pass: opt_i64(r, 18)? as u64,
                    checkbox: opt_i64(r, 19)? as u64,
                    hard_pow: opt_i64(r, 20)? as u64,
                    block: opt_i64(r, 21)? as u64,
                },
                // Filled in by the handler from the in-memory drop counter;
                // the DB has no record of dropped rows (that's the point).
                dropped_records: 0,
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

/// Bucket width for a given window. Tuned so a window never renders more
/// than ~50 points.
fn bucket_secs_for(hours: u32) -> i64 {
    match hours {
        0..=2 => 300,      // 5 min  → ≤ 24 buckets
        3..=12 => 1800,    // 30 min → ≤ 24
        13..=48 => 3600,   // 1 h    → ≤ 48
        49..=240 => 21600, // 6 h    → ≤ 40
        _ => 86400,        // 1 d    → ≤ 30
    }
}

/// Classify a User-Agent into a coarse browser family. Order matters:
/// Chromium-family browsers all contain "chrome/", so the more specific
/// tokens are checked first.
fn browser_family(ua: Option<&str>) -> &'static str {
    let Some(ua) = ua else { return "(none)" };
    let l = ua.to_ascii_lowercase();
    const SCRIPTED: &[&str] = &[
        "bot", "crawler", "spider", "curl", "wget", "python", "go-http", "headless",
    ];
    if SCRIPTED.iter().any(|m| l.contains(m)) {
        "bot/script"
    } else if l.contains("edg/") {
        "Edge"
    } else if l.contains("opr/") || l.contains("opera") {
        "Opera"
    } else if l.contains("firefox/") || l.contains("fxios/") {
        "Firefox"
    } else if l.contains("chrome/") || l.contains("crios/") {
        "Chrome"
    } else if l.contains("safari/") {
        "Safari"
    } else {
        "Other"
    }
}

/// Classify an automated User-Agent into a bot family — the finer split of
/// `browser_family`'s single "bot/script" bucket. `None` means the UA looks
/// like a real browser (or is absent) and belongs in no bot bucket.
///
/// The crawler families say "claims": a Googlebot or GPTBot UA arriving at
/// `/v1/puzzle` is almost certainly a spoofer, because real crawlers fetch
/// raw HTML and never execute the widget. Order matters — the crawler tokens
/// all contain "bot", so they are checked before the generic catch-all.
fn bot_family(ua: Option<&str>) -> Option<&'static str> {
    let l = ua?.to_ascii_lowercase();
    if l.contains("headless") {
        Some("Headless browser")
    } else if l.contains("gptbot")
        || l.contains("claudebot")
        || l.contains("perplexitybot")
        || l.contains("ccbot")
        || l.contains("bytespider")
    {
        Some("Claims AI crawler")
    } else if l.contains("googlebot") || l.contains("bingbot") || l.contains("duckduckbot") {
        Some("Claims search crawler")
    } else if l.contains("curl") || l.contains("wget") {
        Some("curl/wget")
    } else if l.contains("python") {
        Some("Python")
    } else if l.contains("go-http") {
        Some("Go")
    } else if l.contains("bot") || l.contains("crawler") || l.contains("spider") {
        Some("Other scripted")
    } else {
        None
    }
}

#[allow(clippy::cast_sign_loss)]
fn analytics_blocking(
    conn: &Connection,
    hours: u32,
    now_epoch: i64,
    site_key: Option<&str>,
) -> rusqlite::Result<Analytics> {
    let bucket_secs = bucket_secs_for(hours);
    // Align the window start down to a bucket boundary so the first bucket
    // isn't a partial sliver.
    let since_epoch = (now_epoch - i64::from(hours) * 3600) / bucket_secs * bucket_secs;
    // RFC3339 form of the window start, used for the WHERE filter. `p.ts` is
    // fixed-layout UTC with a trailing `+00:00` (written by `to_rfc3339()`),
    // so a lexicographic `p.ts >= ?` comparison sorts chronologically *and*
    // uses `idx_puzzle_ts` — the same trick `DecisionLog::prune` relies on.
    // The integer `since_epoch` is still used for bucket alignment and the
    // dense fill loop below.
    let since_rfc = chrono::DateTime::from_timestamp(since_epoch, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_default();

    // All queries share the same window + site filter. The `p.ts >= ?1` range
    // is index-friendly via `idx_puzzle_ts`; the per-row `strftime` that
    // remains below is only the bucket projection, computed on the rows the
    // filter already narrowed.
    const FILTER: &str = "p.ts >= ?1
         AND (?2 IS NULL OR p.site_key = ?2)";

    // 1. Time-bucketed counts.
    let mut by_bucket: std::collections::HashMap<i64, TimeBucket> =
        std::collections::HashMap::new();
    let mut stmt = conn.prepare(&format!(
        "SELECT
            CAST(strftime('%s', p.ts) AS INTEGER) / ?3 * ?3 AS bucket,
            COUNT(*),
            COUNT(v.id),
            SUM(CASE WHEN p.outcome = 'issued'   THEN 1 ELSE 0 END),
            SUM(CASE WHEN p.outcome = 'rejected' THEN 1 ELSE 0 END),
            SUM(CASE WHEN v.outcome = 'pass'        THEN 1 ELSE 0 END),
            SUM(CASE WHEN v.outcome = 'shadow_fail' THEN 1 ELSE 0 END),
            SUM(CASE WHEN v.outcome = 'block'       THEN 1 ELSE 0 END),
            SUM(CASE WHEN v.outcome = 'pow_invalid' THEN 1 ELSE 0 END),
            SUM(CASE WHEN p.tier = 'InvisiblePass' THEN 1 ELSE 0 END),
            SUM(CASE WHEN p.tier = 'Checkbox'      THEN 1 ELSE 0 END),
            SUM(CASE WHEN p.tier = 'HardPow'       THEN 1 ELSE 0 END),
            SUM(CASE WHEN p.tier = 'Block'         THEN 1 ELSE 0 END)
         FROM puzzle_decisions p
         LEFT JOIN verify_decisions v ON v.challenge_id = p.challenge_id
         WHERE {FILTER}
         GROUP BY bucket"
    ))?;
    let rows = stmt.query_map(rusqlite::params![&since_rfc, site_key, bucket_secs], |r| {
        let epoch: i64 = r.get(0)?;
        Ok((
            epoch,
            TimeBucket {
                t: String::new(), // filled in the dense pass below
                puzzles: r.get::<_, i64>(1)? as u64,
                verifies: r.get::<_, i64>(2)? as u64,
                issued: opt_i64(r, 3)? as u64,
                rejected: opt_i64(r, 4)? as u64,
                pass: opt_i64(r, 5)? as u64,
                shadow_fail: opt_i64(r, 6)? as u64,
                block: opt_i64(r, 7)? as u64,
                pow_invalid: opt_i64(r, 8)? as u64,
                tier_invisible_pass: opt_i64(r, 9)? as u64,
                tier_checkbox: opt_i64(r, 10)? as u64,
                tier_hard_pow: opt_i64(r, 11)? as u64,
                tier_block: opt_i64(r, 12)? as u64,
            },
        ))
    })?;
    for row in rows {
        let (epoch, bucket) = row?;
        by_bucket.insert(epoch, bucket);
    }

    // Dense, zero-filled series from window start to now.
    let mut buckets = Vec::new();
    let mut epoch = since_epoch;
    while epoch <= now_epoch {
        let mut b = by_bucket.remove(&epoch).unwrap_or_default();
        b.t = chrono::DateTime::from_timestamp(epoch, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default();
        buckets.push(b);
        epoch += bucket_secs;
    }

    // 2. Bot-probability histogram (combined score, same formula as
    // `bot_probability`) + signal fire counts, one pass.
    let mut bot_histogram = vec![0u64; 10];
    let mut stmt = conn.prepare(&format!(
        "SELECT
            MIN(MIN(MAX(p.score, COALESCE(v.score, 0)), 100) / 10, 9) AS bin,
            COUNT(*)
         FROM puzzle_decisions p
         LEFT JOIN verify_decisions v ON v.challenge_id = p.challenge_id
         WHERE {FILTER}
         GROUP BY bin"
    ))?;
    let rows = stmt.query_map(rusqlite::params![&since_rfc, site_key], |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
    })?;
    for row in rows {
        let (bin, count) = row?;
        bot_histogram[bin.clamp(0, 9) as usize] = count as u64;
    }

    let signal_fires = conn.query_row(
        &format!(
            "SELECT
                SUM(CASE WHEN p.sig_rate            > 0 THEN 1 ELSE 0 END),
                SUM(CASE WHEN p.sig_header_anomaly  > 0 THEN 1 ELSE 0 END),
                SUM(CASE WHEN p.sig_ip_reputation   > 0 THEN 1 ELSE 0 END),
                SUM(CASE WHEN p.sig_tls_fingerprint > 0 THEN 1 ELSE 0 END),
                SUM(CASE WHEN COALESCE(v.sig_honeypot, 0)     > 0 THEN 1 ELSE 0 END),
                SUM(CASE WHEN COALESCE(v.sig_time_on_page, 0) > 0 THEN 1 ELSE 0 END),
                SUM(CASE WHEN COALESCE(v.sig_behavior, 0)     > 0 THEN 1 ELSE 0 END)
             FROM puzzle_decisions p
             LEFT JOIN verify_decisions v ON v.challenge_id = p.challenge_id
             WHERE {FILTER}"
        ),
        rusqlite::params![&since_rfc, site_key],
        |r| {
            Ok(SignalFires {
                rate: opt_i64(r, 0)? as u64,
                header_anomaly: opt_i64(r, 1)? as u64,
                ip_reputation: opt_i64(r, 2)? as u64,
                tls_fingerprint: opt_i64(r, 3)? as u64,
                honeypot: opt_i64(r, 4)? as u64,
                time_on_page: opt_i64(r, 5)? as u64,
                behavior: opt_i64(r, 6)? as u64,
            })
        },
    )?;

    // 3. Browser + bot families. Group raw UA strings in SQL (cheap dedup),
    // then classify and merge the families in Rust — one pass feeds both
    // breakdowns.
    let mut families: HashMap<&'static str, u64> = HashMap::new();
    let mut bot_families: HashMap<&'static str, u64> = HashMap::new();
    let mut stmt = conn.prepare(&format!(
        "SELECT p.user_agent, COUNT(*)
         FROM puzzle_decisions p
         WHERE {FILTER}
         GROUP BY p.user_agent"
    ))?;
    let rows = stmt.query_map(rusqlite::params![&since_rfc, site_key], |r| {
        Ok((r.get::<_, Option<String>>(0)?, r.get::<_, i64>(1)?))
    })?;
    for row in rows {
        let (ua, count) = row?;
        *families.entry(browser_family(ua.as_deref())).or_default() += count as u64;
        if let Some(family) = bot_family(ua.as_deref()) {
            *bot_families.entry(family).or_default() += count as u64;
        }
    }
    let mut browsers: Vec<BrowserCount> = families
        .into_iter()
        .map(|(name, count)| BrowserCount {
            name: name.to_string(),
            count,
        })
        .collect();
    browsers.sort_by(|a, b| b.count.cmp(&a.count).then(a.name.cmp(&b.name)));
    let mut bots: Vec<BotCount> = bot_families
        .into_iter()
        .map(|(name, count)| BotCount {
            name: name.to_string(),
            count,
        })
        .collect();
    bots.sort_by(|a, b| b.count.cmp(&a.count).then(a.name.cmp(&b.name)));

    // 4. Network types. The category is already a canonical label, so SQL can
    // group and order directly. NULL rows (no reputation match) are excluded —
    // the panel shows the network-type mix of *matched* traffic only.
    let mut network_types = Vec::new();
    let mut stmt = conn.prepare(&format!(
        "SELECT p.ip_reputation_category, COUNT(*)
         FROM puzzle_decisions p
         WHERE {FILTER} AND p.ip_reputation_category IS NOT NULL
         GROUP BY p.ip_reputation_category
         ORDER BY COUNT(*) DESC, p.ip_reputation_category ASC"
    ))?;
    let rows = stmt.query_map(rusqlite::params![&since_rfc, site_key], |r| {
        Ok(NetworkTypeCount {
            name: r.get::<_, String>(0)?,
            count: r.get::<_, i64>(1)? as u64,
        })
    })?;
    for row in rows {
        network_types.push(row?);
    }

    // 5. Country distribution. The `country` column is stamped at log-write
    // time by the offline GeoIP lookup; NULL rows (geo disabled or no match)
    // are excluded, so the panel is empty when `GEOIP_DB_PATH` is unset.
    let mut countries = Vec::new();
    let mut stmt = conn.prepare(&format!(
        "SELECT p.country, COUNT(*)
         FROM puzzle_decisions p
         WHERE {FILTER} AND p.country IS NOT NULL
         GROUP BY p.country
         ORDER BY COUNT(*) DESC, p.country ASC"
    ))?;
    let rows = stmt.query_map(rusqlite::params![&since_rfc, site_key], |r| {
        Ok(CountryCount {
            name: r.get::<_, String>(0)?,
            count: r.get::<_, i64>(1)? as u64,
        })
    })?;
    for row in rows {
        countries.push(row?);
    }

    Ok(Analytics {
        window_hours: hours,
        bucket_secs: bucket_secs as u32,
        buckets,
        bot_histogram,
        browsers,
        bots,
        network_types,
        countries,
        signal_fires,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Guards the positional column→field mapping in `stats_blocking`. The
    /// SELECT list and the `Stats` construction are aligned only by index, so
    /// an off-by-one (e.g. when a tier column is added/removed) would silently
    /// return wrong numbers. Insert known rows and assert the aggregates —
    /// especially the tier counts, which sit at the tail of the SELECT and
    /// shift when a column changes.
    #[test]
    fn stats_mapping_is_aligned() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(crate::dashboard::log::SCHEMA).unwrap();

        // Two puzzle rows (one HardPow, one Block); c1 also gets a verify row.
        conn.execute_batch(
            "INSERT INTO puzzle_decisions
               (ts, challenge_id, site_key, ip, ip_count, site_count, score, tier, difficulty,
                outcome, sig_rate, sig_header_anomaly, sig_ip_reputation,
                sig_tls_fingerprint, tls_fingerprint, user_agent)
             VALUES
               ('2026-01-01T00:00:00Z','c1','s','1.2.3.4',1,1,45,'HardPow',12,'issued',
                30,15,0,0,'Skipped',NULL),
               ('2026-01-01T00:00:01Z','c2','s','1.2.3.4',2,2,90,'Block',0,'rejected',
                30,30,30,0,'Skipped',NULL);
             INSERT INTO verify_decisions
               (ts, challenge_id, success, outcome, score, sig_honeypot, sig_time_on_page,
                sig_behavior, time_on_page_ms, webdriver)
             VALUES
               ('2026-01-01T00:00:02Z','c1',1,'pass',0,0,0,0,5000,'false');",
        )
        .unwrap();

        let stats = stats_blocking(&conn).unwrap();

        assert_eq!(stats.total_sessions, 2);
        assert_eq!(stats.verified_sessions, 1);

        // Tier counts (indices 18–21) — the tail that shifts when a column is
        // added/removed.
        assert_eq!(stats.tiers.invisible_pass, 0);
        assert_eq!(stats.tiers.checkbox, 0);
        assert_eq!(stats.tiers.hard_pow, 1);
        assert_eq!(stats.tiers.block, 1);

        // Nothing above was monitored, so both counters read zero — this also
        // pins indices 22–23, the new tail of the SELECT.
        assert_eq!(stats.outcomes.puzzle_monitored, 0);
        assert_eq!(stats.outcomes.verify_monitored, 0);

        // Outcomes.
        assert_eq!(stats.outcomes.puzzle_issued, 1);
        assert_eq!(stats.outcomes.puzzle_rejected, 1);
        assert_eq!(stats.outcomes.verify_pass, 1);
    }

    /// Same positional-alignment guard for `analytics_blocking`: known rows
    /// in, exact bucket counts / histogram / browser families / fire counts
    /// out. Uses a fixed `now_epoch` so bucket boundaries are deterministic.
    #[test]
    fn analytics_mapping_is_aligned() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(crate::dashboard::log::SCHEMA).unwrap();

        // now = 2026-01-02T00:00:00Z. Window: 24h → 3600s buckets.
        let now_epoch = 1_767_312_000;
        let ts_in = "2026-01-01T12:30:00+00:00"; // in window
        let ts_in2 = "2026-01-01T12:45:00+00:00"; // same bucket as ts_in
        let ts_out = "2025-12-30T00:00:00+00:00"; // outside window

        conn.execute_batch(&format!(
            "INSERT INTO puzzle_decisions
               (ts, challenge_id, site_key, ip, ip_count, site_count, score, tier, difficulty,
                outcome, sig_rate, sig_header_anomaly, sig_ip_reputation,
                sig_tls_fingerprint, ip_reputation_category, tls_fingerprint, user_agent, country)
             VALUES
               ('{ts_in}','c1','s1','1.2.3.0',1,1,10,'InvisiblePass',18,'issued',
                10,0,0,0,NULL,'Skipped','Mozilla/5.0 Chrome/120.0 Safari/537.36','US'),
               ('{ts_in2}','c2','s1','1.2.3.0',2,2,95,'Block',0,'rejected',
                30,35,30,0,'datacenter','Skipped','curl/8.4.0','US'),
               ('{ts_in2}','c3','s2','5.6.7.0',1,1,5,'InvisiblePass',18,'issued',
                0,5,0,0,NULL,'Skipped',NULL,'DE'),
               ('{ts_out}','c4','s1','1.2.3.0',1,1,50,'HardPow',24,'issued',
                50,0,0,0,'tor','Skipped','Mozilla/5.0 Firefox/121.0','FR');
             INSERT INTO verify_decisions
               (ts, challenge_id, success, outcome, score, sig_honeypot, sig_time_on_page,
                sig_behavior, time_on_page_ms, webdriver)
             VALUES
               ('{ts_in}','c1',1,'pass',0,0,0,0,5000,'false');"
        ))
        .unwrap();

        let a = analytics_blocking(&conn, 24, now_epoch, None).unwrap();

        assert_eq!(a.window_hours, 24);
        assert_eq!(a.bucket_secs, 3600);

        // Dense series: 24h window aligned to the hour + the current bucket.
        assert_eq!(a.buckets.len(), 25);
        assert!(a.buckets.iter().all(|b| !b.t.is_empty()));

        // All three in-window rows share the 12:00 bucket.
        let busy = a
            .buckets
            .iter()
            .find(|b| b.t.starts_with("2026-01-01T12:00:00"))
            .unwrap();
        assert_eq!(busy.puzzles, 3);
        assert_eq!(busy.verifies, 1);
        assert_eq!(busy.issued, 2);
        assert_eq!(busy.rejected, 1);
        assert_eq!(busy.pass, 1);
        assert_eq!(busy.tier_invisible_pass, 2);
        assert_eq!(busy.tier_block, 1);
        // The out-of-window row contributes nowhere.
        assert_eq!(a.buckets.iter().map(|b| b.puzzles).sum::<u64>(), 3);

        // Histogram: scores 10 (bin 1), 95 (bin 9), 5 (bin 0).
        assert_eq!(a.bot_histogram[0], 1);
        assert_eq!(a.bot_histogram[1], 1);
        assert_eq!(a.bot_histogram[9], 1);
        assert_eq!(a.bot_histogram.iter().sum::<u64>(), 3);

        // Browsers: Chrome, bot/script (curl), (none) — Firefox is outside
        // the window.
        let by_name: HashMap<_, _> = a
            .browsers
            .iter()
            .map(|b| (b.name.as_str(), b.count))
            .collect();
        assert_eq!(by_name.get("Chrome"), Some(&1));
        assert_eq!(by_name.get("bot/script"), Some(&1));
        assert_eq!(by_name.get("(none)"), Some(&1));
        assert_eq!(by_name.get("Firefox"), None);

        // Bots: only the curl row is automated; Chrome and NULL contribute
        // nothing.
        assert_eq!(a.bots.len(), 1);
        assert_eq!(a.bots[0].name, "curl/wget");
        assert_eq!(a.bots[0].count, 1);

        // Signal fires (in-window only).
        assert_eq!(a.signal_fires.rate, 2);
        assert_eq!(a.signal_fires.header_anomaly, 2);
        assert_eq!(a.signal_fires.ip_reputation, 1);
        assert_eq!(a.signal_fires.honeypot, 0);

        // Network types: only the in-window datacenter row (c2) counts; c1/c3
        // have no category and c4's 'tor' is outside the window.
        assert_eq!(a.network_types.len(), 1);
        assert_eq!(a.network_types[0].name, "datacenter");
        assert_eq!(a.network_types[0].count, 1);

        // Countries: in-window US (c1, c2) and DE (c3), sorted by count desc;
        // c4's FR is outside the window.
        assert_eq!(a.countries.len(), 2);
        assert_eq!(a.countries[0].name, "US");
        assert_eq!(a.countries[0].count, 2);
        assert_eq!(a.countries[1].name, "DE");
        assert_eq!(a.countries[1].count, 1);

        // Site filter narrows to s2's single clean request.
        let s2 = analytics_blocking(&conn, 24, now_epoch, Some("s2")).unwrap();
        assert_eq!(s2.buckets.iter().map(|b| b.puzzles).sum::<u64>(), 1);
        assert_eq!(s2.bot_histogram[0], 1);
        assert_eq!(s2.bot_histogram.iter().sum::<u64>(), 1);
        // s2 has no reputation-matched traffic.
        assert!(s2.network_types.is_empty());
        // s2's only request is the DE one.
        assert_eq!(s2.countries.len(), 1);
        assert_eq!(s2.countries[0].name, "DE");
        assert_eq!(s2.countries[0].count, 1);
    }

    /// The crawler tokens all contain "bot", so ordering bugs would silently
    /// fold every crawler into "Other scripted"; real-browser UAs must map to
    /// no family at all.
    #[test]
    fn bot_family_classifies_by_specificity() {
        let f = |ua: &str| bot_family(Some(ua));

        assert_eq!(
            f("Mozilla/5.0 HeadlessChrome/120.0"),
            Some("Headless browser")
        );
        assert_eq!(
            f("Mozilla/5.0 (compatible; GPTBot/1.0)"),
            Some("Claims AI crawler")
        );
        assert_eq!(
            f("Mozilla/5.0 (compatible; ClaudeBot/1.0)"),
            Some("Claims AI crawler")
        );
        assert_eq!(
            f("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
            Some("Claims search crawler")
        );
        assert_eq!(f("curl/8.4.0"), Some("curl/wget"));
        assert_eq!(f("Wget/1.21"), Some("curl/wget"));
        assert_eq!(f("python-requests/2.31.0"), Some("Python"));
        assert_eq!(f("Go-http-client/2.0"), Some("Go"));
        assert_eq!(f("SomeRandomBot/0.1"), Some("Other scripted"));

        assert_eq!(f("Mozilla/5.0 Chrome/120.0 Safari/537.36"), None);
        assert_eq!(bot_family(None), None);
    }

    /// A monitored block must stay counted as a block *and* be identifiable as
    /// unenforced. Excluding it from the block counts would make monitor mode
    /// report nothing, which is the only thing it exists to do.
    #[test]
    fn monitored_rows_are_counted_as_blocks_and_flagged() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(crate::dashboard::log::SCHEMA).unwrap();

        conn.execute_batch(
            "INSERT INTO puzzle_decisions
               (ts, challenge_id, site_key, ip, ip_count, site_count, score, tier, difficulty,
                outcome, monitored, sig_rate, sig_header_anomaly, sig_ip_reputation,
                sig_tls_fingerprint, tls_fingerprint, user_agent)
             VALUES
               ('2026-01-01T00:00:00Z','c1','s','1.2.3.4',1,1,90,'Block',16,'issued',1,
                30,30,30,0,'Skipped',NULL);
             INSERT INTO verify_decisions
               (ts, challenge_id, success, outcome, score, sig_honeypot, sig_time_on_page,
                sig_behavior, time_on_page_ms, webdriver, monitored)
             VALUES
               ('2026-01-01T00:00:02Z','c1',1,'block',100,100,0,0,5000,'false',1);",
        )
        .unwrap();

        let stats = stats_blocking(&conn).unwrap();
        // The verdict is still visible as a block...
        assert_eq!(stats.outcomes.verify_block, 1);
        assert_eq!(stats.tiers.block, 1);
        // ...and distinguishable from an enforced one.
        assert_eq!(stats.outcomes.puzzle_monitored, 1);
        assert_eq!(stats.outcomes.verify_monitored, 1);
        // The puzzle was issued despite the Block tier — that pairing is the
        // on-disk signature of a monitored request.
        assert_eq!(stats.outcomes.puzzle_issued, 1);
        assert_eq!(stats.outcomes.puzzle_rejected, 0);

        // The session view surfaces both flags for the detail panel.
        let session = get_blocking(&conn, 1).unwrap().expect("session row");
        assert!(session.monitored);
        let verify = session.verify.expect("verify section");
        assert!(verify.monitored);
        assert!(verify.success);
    }
}
