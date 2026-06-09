//! Decision writer. Owns a single SQLite connection on a dedicated thread
//! and consumes decisions from a bounded channel. Handlers never block on
//! disk: `record_*` is a non-blocking `try_send` — when the writer is
//! falling behind and the queue is full, decisions are dropped (with a
//! rate-limited WARN) rather than allowed to push back on the request
//! handler or grow RAM unbounded.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

use rusqlite::{Connection, params};
use tokio::sync::mpsc::{Sender, channel, error::TrySendError};
use tokio::sync::oneshot;

use super::types::{PuzzleRecord, VerifyRecord};

/// Bounded channel capacity. At ~200 bytes per record this is ~1.6 MB of
/// queued state, which absorbs short bursts (10k decisions in a few seconds)
/// without OOMing the process. Steady-state throughput is determined by
/// SQLite write speed, not the channel.
const CHANNEL_CAPACITY: usize = 8192;

pub(crate) const SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS puzzle_decisions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT    NOT NULL,
    challenge_id    TEXT,
    site_key        TEXT    NOT NULL,
    ip              TEXT    NOT NULL,
    ip_count        INTEGER NOT NULL,
    site_count      INTEGER NOT NULL,
    score           INTEGER NOT NULL,
    tier            TEXT    NOT NULL,
    difficulty      INTEGER NOT NULL,
    outcome         TEXT    NOT NULL,
    sig_rate              INTEGER NOT NULL,
    sig_header_anomaly    INTEGER NOT NULL,
    sig_ip_reputation     INTEGER NOT NULL,
    sig_tls_fingerprint   INTEGER NOT NULL,
    tls_fingerprint TEXT    NOT NULL,
    user_agent      TEXT
);
CREATE INDEX IF NOT EXISTS idx_puzzle_ts ON puzzle_decisions(ts DESC);
CREATE INDEX IF NOT EXISTS idx_puzzle_challenge ON puzzle_decisions(challenge_id);

CREATE TABLE IF NOT EXISTS verify_decisions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT    NOT NULL,
    challenge_id    TEXT    NOT NULL,
    success         INTEGER NOT NULL,
    outcome         TEXT    NOT NULL,
    score           INTEGER NOT NULL,
    sig_honeypot       INTEGER NOT NULL,
    sig_time_on_page   INTEGER NOT NULL,
    sig_behavior       INTEGER NOT NULL,
    time_on_page_ms INTEGER,
    webdriver       TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_verify_challenge ON verify_decisions(challenge_id);
CREATE INDEX IF NOT EXISTS idx_verify_ts ON verify_decisions(ts DESC);
";

// Drop columns left over from the cookie-age signal and the full/minimal
// shadow-scoring comparison, both removed when the service went cookie-free
// and dropped FULL_FINGERPRINT_MODE. SQLite has no `DROP COLUMN IF EXISTS`,
// so we run each once and treat the "no such column" error (fresh databases,
// or a second run) as a no-op. DROP COLUMN requires SQLite 3.35+ (2021).
const MIGRATIONS: &[&str] = &[
    "ALTER TABLE puzzle_decisions DROP COLUMN sig_cookie_age",
    "ALTER TABLE puzzle_decisions DROP COLUMN cookie_presence",
    "ALTER TABLE puzzle_decisions DROP COLUMN score_full",
    "ALTER TABLE puzzle_decisions DROP COLUMN tier_full",
    "ALTER TABLE puzzle_decisions DROP COLUMN score_minimal",
    "ALTER TABLE puzzle_decisions DROP COLUMN tier_minimal",
    "ALTER TABLE verify_decisions DROP COLUMN sig_cookie_age",
    "ALTER TABLE verify_decisions DROP COLUMN cookie_presence",
    "ALTER TABLE verify_decisions DROP COLUMN score_full",
    "ALTER TABLE verify_decisions DROP COLUMN outcome_full",
    "ALTER TABLE verify_decisions DROP COLUMN score_minimal",
    "ALTER TABLE verify_decisions DROP COLUMN outcome_minimal",
];

enum Msg {
    Puzzle(PuzzleRecord),
    Verify(VerifyRecord),
    /// Truncate both tables. Routed through the writer thread so it's
    /// serialised with any in-flight inserts. The caller awaits the ack
    /// to know the operation finished before issuing a follow-up read.
    Clear(oneshot::Sender<rusqlite::Result<()>>),
}

#[derive(Clone)]
pub struct DecisionLog {
    sender: Sender<Msg>,
    db_path: String,
    /// Monotonic count of records dropped because the channel was full.
    /// Exposed for `/v1/admin/stats` and inspection from operators.
    dropped: Arc<AtomicU64>,
}

impl DecisionLog {
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        let path_str = path.as_ref().to_string_lossy().into_owned();

        // Writer connection. Run schema, enable WAL so readers don't block.
        let writer = Connection::open(&path_str)?;
        writer.execute_batch(SCHEMA)?;
        for stmt in MIGRATIONS {
            // SQLite reports "no such column" when the column is already gone —
            // i.e. a fresh database (created from the current SCHEMA without it)
            // or a second run of these migrations. Treat that as a no-op.
            if let Err(e) = writer.execute(stmt, []) {
                let msg = e.to_string();
                if !msg.contains("no such column") {
                    return Err(e);
                }
            }
        }
        writer.pragma_update(None, "journal_mode", "WAL")?;
        writer.pragma_update(None, "synchronous", "NORMAL")?;

        let (tx, mut rx) = channel::<Msg>(CHANNEL_CAPACITY);

        // Dedicated OS thread; rusqlite::Connection is not Send across awaits
        // and we want a long-lived owner for the writer.
        thread::Builder::new()
            .name("decision-log".into())
            .spawn(move || {
                while let Some(msg) = rx.blocking_recv() {
                    match msg {
                        Msg::Puzzle(rec) => {
                            if let Err(e) = insert_puzzle(&writer, &rec) {
                                tracing::warn!(error = %e, "decision-log: insert failed");
                            }
                        }
                        Msg::Verify(rec) => {
                            if let Err(e) = insert_verify(&writer, &rec) {
                                tracing::warn!(error = %e, "decision-log: insert failed");
                            }
                        }
                        Msg::Clear(ack) => {
                            let result = clear_all(&writer);
                            if let Err(e) = &result {
                                tracing::warn!(error = %e, "decision-log: clear failed");
                            }
                            let _ = ack.send(result);
                        }
                    }
                }
                tracing::info!("decision-log writer thread exiting");
            })
            .expect("spawn decision-log thread");

        Ok(Self {
            sender: tx,
            db_path: path_str,
            dropped: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn db_path(&self) -> &str {
        &self.db_path
    }

    /// Number of records dropped because the writer queue was full.
    /// Useful for capacity planning — a non-zero value means SQLite
    /// can't keep up with the request rate.
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn record_puzzle(&self, record: PuzzleRecord) {
        self.try_send(Msg::Puzzle(record), "puzzle");
    }

    pub fn record_verify(&self, record: VerifyRecord) {
        self.try_send(Msg::Verify(record), "verify");
    }

    /// Non-blocking send. The hot path can't await — we'd hold up the
    /// request handler waiting on disk. On `Full`, increment the drop
    /// counter and emit a WARN at every power-of-two threshold so the
    /// log doesn't drown in repeats during a sustained backlog.
    fn try_send(&self, msg: Msg, kind: &'static str) {
        match self.sender.try_send(msg) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                let n = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                if n.is_power_of_two() {
                    tracing::warn!(
                        kind,
                        dropped_total = n,
                        capacity = CHANNEL_CAPACITY,
                        "decision-log: queue full, dropping record"
                    );
                }
            }
            Err(TrySendError::Closed(_)) => {
                // Writer thread has exited — service is shutting down.
                // Silent drop: nothing useful to log.
            }
        }
    }

    /// Wipe all puzzle/verify rows. Resolves once the writer thread has
    /// finished the truncate, so the next list query is guaranteed to see
    /// an empty table. Uses an awaiting `send` (not `try_send`) because
    /// `clear` is operator-initiated and we'd rather block briefly than
    /// silently fail under burst.
    pub async fn clear(&self) -> rusqlite::Result<()> {
        let (tx, rx) = oneshot::channel();
        if self.sender.send(Msg::Clear(tx)).await.is_err() {
            return Err(rusqlite::Error::InvalidQuery);
        }
        rx.await.unwrap_or(Err(rusqlite::Error::InvalidQuery))
    }
}

fn clear_all(conn: &Connection) -> rusqlite::Result<()> {
    let tx = conn.unchecked_transaction()?;
    tx.execute("DELETE FROM verify_decisions", [])?;
    tx.execute("DELETE FROM puzzle_decisions", [])?;
    // Reset the AUTOINCREMENT counters so the next session is #1 again.
    // sqlite_sequence may not exist if no AUTOINCREMENT row has ever been
    // inserted, so ignore "no such table" here.
    let _ = tx.execute(
        "DELETE FROM sqlite_sequence WHERE name IN ('puzzle_decisions','verify_decisions')",
        [],
    );
    tx.commit()?;
    Ok(())
}

fn insert_puzzle(conn: &Connection, r: &PuzzleRecord) -> rusqlite::Result<()> {
    let ts = chrono::Utc::now().to_rfc3339();
    let tier = format!("{:?}", r.tier);
    conn.execute(
        "INSERT INTO puzzle_decisions (
            ts, challenge_id, site_key, ip, ip_count, site_count,
            score, tier, difficulty, outcome,
            sig_rate, sig_header_anomaly, sig_ip_reputation, sig_tls_fingerprint,
            tls_fingerprint, user_agent
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6,
            ?7, ?8, ?9, ?10,
            ?11, ?12, ?13, ?14,
            ?15, ?16
         )",
        params![
            ts,
            r.challenge_id.map(|u| u.to_string()),
            r.site_key.to_string(),
            r.ip,
            r.ip_count,
            r.site_count,
            r.score,
            tier,
            r.difficulty,
            r.outcome,
            r.breakdown.rate,
            r.breakdown.header_anomaly,
            r.breakdown.ip_reputation,
            r.breakdown.tls_fingerprint,
            r.tls_fingerprint,
            r.user_agent,
        ],
    )?;
    Ok(())
}

fn insert_verify(conn: &Connection, r: &VerifyRecord) -> rusqlite::Result<()> {
    let ts = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO verify_decisions (
            ts, challenge_id, success, outcome, score,
            sig_honeypot, sig_time_on_page, sig_behavior,
            time_on_page_ms, webdriver
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5,
            ?6, ?7, ?8,
            ?9, ?10
         )",
        params![
            ts,
            r.challenge_id.to_string(),
            r.success as i64,
            r.outcome,
            r.score,
            r.breakdown.honeypot,
            r.breakdown.time_on_page,
            r.breakdown.behavior,
            r.time_on_page_ms.map(|v| v as i64),
            r.webdriver,
        ],
    )?;
    Ok(())
}
