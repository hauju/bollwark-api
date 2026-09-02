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

use super::geo::GeoIp;
use super::types::{PuzzleRecord, VerifyRecord};

/// Bounded channel capacity. At ~200 bytes per record this is ~1.6 MB of
/// queued state, which absorbs short bursts (10k decisions in a few seconds)
/// without OOMing the process. Steady-state throughput is determined by
/// SQLite write speed, not the channel.
const CHANNEL_CAPACITY: usize = 8192;

/// Max records folded into a single insert transaction. The writer greedily
/// drains queued inserts up to this many and commits them together, so a burst
/// that filled the channel costs a handful of fsyncs instead of thousands —
/// the difference between the writer keeping up and the channel dropping under
/// load. Capped (rather than draining the whole queue) to bound per-commit
/// latency and the batch buffer.
const MAX_INSERT_BATCH: usize = 256;

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
    monitored       INTEGER NOT NULL DEFAULT 0,
    sig_rate              INTEGER NOT NULL,
    sig_header_anomaly    INTEGER NOT NULL,
    sig_ip_reputation     INTEGER NOT NULL,
    sig_tls_fingerprint   INTEGER NOT NULL,
    ip_reputation_category TEXT,
    tls_fingerprint TEXT    NOT NULL,
    user_agent      TEXT,
    country         TEXT
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
    sig_remote_ip      INTEGER NOT NULL DEFAULT 0,
    time_on_page_ms INTEGER,
    webdriver       TEXT    NOT NULL,
    monitored       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_verify_challenge ON verify_decisions(challenge_id);
CREATE INDEX IF NOT EXISTS idx_verify_ts ON verify_decisions(ts DESC);
";

// In-place schema migrations for databases created by an older binary.
//
// DROPs: columns left over from the cookie-age signal and the full/minimal
// shadow-scoring comparison, both removed when the service went cookie-free
// and dropped FULL_FINGERPRINT_MODE.
//
// ADDs: columns added to SCHEMA after the table first shipped. A fresh
// database already has them (created from the current SCHEMA), so the ADD is
// a no-op there; an upgraded database picks them up here.
//
// SQLite has no `... IF [NOT] EXISTS` for columns, so we run each once and
// treat the benign "no such column" (DROP, already gone) and "duplicate
// column name" (ADD, already present) errors as no-ops. DROP COLUMN requires
// SQLite 3.35+ (2021).
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
    "ALTER TABLE puzzle_decisions ADD COLUMN ip_reputation_category TEXT",
    "ALTER TABLE puzzle_decisions ADD COLUMN country TEXT",
    // Monitor mode: the row's verdict was recorded but not enforced. Defaults
    // to 0 so every pre-existing row reads as enforced, which it was.
    "ALTER TABLE puzzle_decisions ADD COLUMN monitored INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE verify_decisions ADD COLUMN monitored INTEGER NOT NULL DEFAULT 0",
    // Remote-IP mismatch signal. 0 for every pre-existing row: the check
    // did not exist, so it never fired.
    "ALTER TABLE verify_decisions ADD COLUMN sig_remote_ip INTEGER NOT NULL DEFAULT 0",
];

enum Msg {
    Puzzle(PuzzleRecord),
    Verify(VerifyRecord),
    /// Truncate both tables. Routed through the writer thread so it's
    /// serialised with any in-flight inserts. The caller awaits the ack
    /// to know the operation finished before issuing a follow-up read.
    Clear(oneshot::Sender<rusqlite::Result<()>>),
    /// Delete rows whose `ts` is older than the RFC3339 cutoff. Same
    /// rationale as `Clear` for going through the writer thread; the ack
    /// carries the number of rows removed so the sweeper can log it.
    Prune {
        cutoff: String,
        ack: oneshot::Sender<rusqlite::Result<usize>>,
    },
    /// Drain barrier: the writer acks only after every record queued *before*
    /// this message has been committed (FIFO channel + single consumer). Used
    /// on graceful shutdown to flush the queue without joining the writer
    /// thread (which can't be joined cleanly — the detached retention sweeper
    /// keeps a sender alive).
    Flush(oneshot::Sender<()>),
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
    /// Open (or create) the decision-log database. `geoip` is an optional
    /// MaxMind country reader: when `Some`, the writer thread stamps each
    /// puzzle row with the visitor's ISO country code (looked up offline on the
    /// logged IP). `None` leaves the `country` column NULL.
    pub fn open(path: impl AsRef<Path>, geoip: Option<GeoIp>) -> rusqlite::Result<Self> {
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
                if !msg.contains("no such column") && !msg.contains("duplicate column name") {
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
                        // Control messages run alone, in order, in their own tx.
                        Msg::Clear(_) | Msg::Prune { .. } | Msg::Flush(_) => {
                            handle_control(&writer, msg)
                        }
                        // Inserts are batched: start with this record, then
                        // greedily drain whatever inserts are already queued and
                        // commit them in one transaction. A control message that
                        // interrupts the drain is handled right after the flush
                        // so ordering (e.g. a Clear wiping prior inserts) holds.
                        first => {
                            let mut batch = vec![first];
                            let mut deferred = None;
                            while batch.len() < MAX_INSERT_BATCH {
                                match rx.try_recv() {
                                    Ok(m @ (Msg::Clear(_) | Msg::Prune { .. } | Msg::Flush(_))) => {
                                        deferred = Some(m);
                                        break;
                                    }
                                    Ok(insert) => batch.push(insert),
                                    Err(_) => break,
                                }
                            }
                            if let Err(e) = flush_batch(&writer, &batch, geoip.as_ref()) {
                                tracing::warn!(
                                    error = %e,
                                    count = batch.len(),
                                    "decision-log: batch insert failed"
                                );
                            }
                            if let Some(control) = deferred {
                                handle_control(&writer, control);
                            }
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

    /// Delete rows older than `retention_hours`. Returns the number of rows
    /// removed across both tables. Like `clear`, this awaits an ack from the
    /// writer thread so the delete is serialised with in-flight inserts.
    /// Called by the periodic retention sweeper in `main.rs`.
    pub async fn prune(&self, retention_hours: u64) -> rusqlite::Result<usize> {
        // `Duration::hours` panics out of range, and the previous
        // `unwrap_or(i64::MAX)` fallback was itself guaranteed to panic — so an
        // oversized retention window killed this task on its first tick and the
        // log silently stopped being pruned. `AppConfig` now rejects such values
        // at boot; fall back to an error here too so a direct caller can't take
        // the sweeper down.
        let Some(window) = i64::try_from(retention_hours)
            .ok()
            .and_then(chrono::Duration::try_hours)
        else {
            return Err(rusqlite::Error::InvalidQuery);
        };
        let cutoff = (chrono::Utc::now() - window).to_rfc3339();
        let (tx, rx) = oneshot::channel();
        if self
            .sender
            .send(Msg::Prune { cutoff, ack: tx })
            .await
            .is_err()
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        rx.await.unwrap_or(Err(rusqlite::Error::InvalidQuery))
    }

    /// Block until every record queued so far has been written to disk.
    /// Called on graceful shutdown so decisions from requests that drained
    /// during shutdown aren't lost with the process. Returns `Err(())` if the
    /// writer thread is already gone.
    pub async fn flush(&self) -> Result<(), ()> {
        let (tx, rx) = oneshot::channel();
        if self.sender.send(Msg::Flush(tx)).await.is_err() {
            return Err(());
        }
        rx.await.map_err(|_| ())
    }
}

/// Insert a batch of Puzzle/Verify records in a single transaction — one fsync
/// per batch instead of per record. A single failing insert rolls back the
/// whole batch, but the only realistic failures here are connection-level
/// (disk full, I/O error) that would sink any approach.
fn flush_batch(conn: &Connection, batch: &[Msg], geoip: Option<&GeoIp>) -> rusqlite::Result<()> {
    let tx = conn.unchecked_transaction()?;
    for msg in batch {
        match msg {
            Msg::Puzzle(rec) => insert_puzzle(&tx, rec, geoip)?,
            Msg::Verify(rec) => insert_verify(&tx, rec)?,
            // Control messages are never placed in an insert batch.
            Msg::Clear(_) | Msg::Prune { .. } | Msg::Flush(_) => {}
        }
    }
    tx.commit()
}

/// Run a control message (Clear/Prune) in its own transaction and ack the
/// caller. Serialised with inserts by the single writer thread.
fn handle_control(conn: &Connection, msg: Msg) {
    match msg {
        Msg::Clear(ack) => {
            let result = clear_all(conn);
            if let Err(e) = &result {
                tracing::warn!(error = %e, "decision-log: clear failed");
            }
            let _ = ack.send(result);
        }
        Msg::Prune { cutoff, ack } => {
            let result = prune_before(conn, &cutoff);
            if let Err(e) = &result {
                tracing::warn!(error = %e, "decision-log: prune failed");
            }
            let _ = ack.send(result);
        }
        // A Flush is reached only after every earlier record has been
        // committed (FIFO), so acking here signals the drain is complete.
        Msg::Flush(ack) => {
            let _ = ack.send(());
        }
        // Inserts are handled by flush_batch, never here.
        Msg::Puzzle(_) | Msg::Verify(_) => {}
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

/// Delete rows older than `cutoff` from both tables. `cutoff` is an RFC3339
/// UTC string in the same format the inserts write (`to_rfc3339()`), so a
/// plain string `<` comparison is both correct — fixed-width fields with a
/// trailing `+00:00` sort lexicographically in chronological order — and
/// index-friendly via `idx_puzzle_ts` / `idx_verify_ts`, unlike a
/// `strftime('%s', ts)` comparison which would scan every row.
fn prune_before(conn: &Connection, cutoff: &str) -> rusqlite::Result<usize> {
    let tx = conn.unchecked_transaction()?;
    // Verify rows first: a verify always shares its puzzle's window, so
    // pruning by each table's own `ts` keeps the join consistent — a puzzle
    // row only survives if it's newer than the cutoff, and the queries drive
    // the join from the puzzle side anyway.
    let verifies = tx.execute("DELETE FROM verify_decisions WHERE ts < ?1", [cutoff])?;
    let puzzles = tx.execute("DELETE FROM puzzle_decisions WHERE ts < ?1", [cutoff])?;
    tx.commit()?;
    Ok(verifies + puzzles)
}

fn insert_puzzle(
    conn: &Connection,
    r: &PuzzleRecord,
    geoip: Option<&GeoIp>,
) -> rusqlite::Result<()> {
    let ts = chrono::Utc::now().to_rfc3339();
    let tier = format!("{:?}", r.tier);
    // Offline country lookup at write time. `r.ip` is the logged IP — already
    // truncated to /24 (or /48) when ANONYMIZE_LOG_IP is on, which still
    // resolves country-level. NULL when geo is disabled or the address isn't
    // in the database.
    let country = geoip.and_then(|g| {
        r.ip.parse::<std::net::IpAddr>()
            .ok()
            .and_then(|ip| g.country(ip))
    });
    conn.execute(
        "INSERT INTO puzzle_decisions (
            ts, challenge_id, site_key, ip, ip_count, site_count,
            score, tier, difficulty, outcome, monitored,
            sig_rate, sig_header_anomaly, sig_ip_reputation, sig_tls_fingerprint,
            ip_reputation_category, tls_fingerprint, user_agent, country
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6,
            ?7, ?8, ?9, ?10, ?11,
            ?12, ?13, ?14, ?15,
            ?16, ?17, ?18, ?19
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
            r.monitored as i64,
            r.breakdown.rate,
            r.breakdown.header_anomaly,
            r.breakdown.ip_reputation,
            r.breakdown.tls_fingerprint,
            r.ip_reputation_category,
            r.tls_fingerprint,
            r.user_agent,
            country,
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
            time_on_page_ms, webdriver, monitored, sig_remote_ip
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5,
            ?6, ?7, ?8,
            ?9, ?10, ?11, ?12
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
            r.monitored as i64,
            r.breakdown.remote_ip,
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `prune_before` removes rows older than the cutoff from both tables and
    /// leaves newer rows untouched. Uses fixed RFC3339 timestamps so the
    /// lexicographic comparison the function relies on is exercised directly.
    #[test]
    fn prune_before_drops_only_old_rows() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();

        // Two puzzle rows (one old, one fresh), each with a verify row whose
        // ts tracks its puzzle. Cutoff sits between the two days.
        conn.execute_batch(
            "INSERT INTO puzzle_decisions
               (ts, challenge_id, site_key, ip, ip_count, site_count, score, tier, difficulty,
                outcome, sig_rate, sig_header_anomaly, sig_ip_reputation,
                sig_tls_fingerprint, tls_fingerprint, user_agent)
             VALUES
               ('2026-01-01T00:00:00+00:00','old','s','1.2.3.4',1,1,10,'Checkbox',12,'issued',
                10,0,0,0,'Skipped',NULL),
               ('2026-01-05T00:00:00+00:00','new','s','1.2.3.4',1,1,10,'Checkbox',12,'issued',
                10,0,0,0,'Skipped',NULL);
             INSERT INTO verify_decisions
               (ts, challenge_id, success, outcome, score, sig_honeypot, sig_time_on_page,
                sig_behavior, time_on_page_ms, webdriver)
             VALUES
               ('2026-01-01T00:00:02+00:00','old',1,'pass',0,0,0,0,5000,'false'),
               ('2026-01-05T00:00:02+00:00','new',1,'pass',0,0,0,0,5000,'false');",
        )
        .unwrap();

        let removed = prune_before(&conn, "2026-01-03T00:00:00+00:00").unwrap();
        assert_eq!(removed, 2, "one puzzle + one verify from the old day");

        let puzzles: i64 = conn
            .query_row("SELECT COUNT(*) FROM puzzle_decisions", [], |r| r.get(0))
            .unwrap();
        let verifies: i64 = conn
            .query_row("SELECT COUNT(*) FROM verify_decisions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(puzzles, 1);
        assert_eq!(verifies, 1);

        let survivor: String = conn
            .query_row("SELECT challenge_id FROM puzzle_decisions", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(survivor, "new");

        // A cutoff before everything is a no-op.
        assert_eq!(prune_before(&conn, "2025-01-01T00:00:00+00:00").unwrap(), 0);
    }

    /// `flush` resolves only after the writer thread has committed everything
    /// queued before it — the guarantee graceful shutdown relies on.
    #[tokio::test]
    async fn flush_commits_queued_records() {
        let path =
            std::env::temp_dir().join(format!("bollwark-flush-test-{}.db", uuid::Uuid::new_v4()));
        let log = DecisionLog::open(&path, None).unwrap();
        log.record_puzzle(PuzzleRecord {
            challenge_id: Some(uuid::Uuid::new_v4()),
            monitored: false,
            site_key: uuid::Uuid::new_v4(),
            ip: "1.2.3.0".into(),
            ip_count: 1,
            site_count: 1,
            score: 0,
            tier: crate::risk::EscalationTier::InvisiblePass,
            difficulty: 5,
            outcome: "issued",
            breakdown: Default::default(),
            ip_reputation_category: None,
            tls_fingerprint: "Skipped".into(),
            user_agent: None,
        });

        // Returns only once the writer has committed the record above.
        log.flush().await.unwrap();

        let conn = Connection::open(&path).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM puzzle_decisions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
    }
}
