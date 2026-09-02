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

use rusqlite::{Connection, OptionalExtension, params};
use tokio::sync::mpsc::{Sender, channel, error::TrySendError};
use tokio::sync::oneshot;
use uuid::Uuid;

use super::geo::GeoIp;
use super::query::browser_family;
use super::types::{FeedbackVerdict, PuzzleRecord, VerifyRecord};

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
    monitored       INTEGER NOT NULL DEFAULT 0,
    automation      TEXT,
    headless        TEXT,
    mouse_moves     INTEGER,
    touches         INTEGER,
    interactions    INTEGER,
    first_interaction_ms INTEGER,
    impossible_timing INTEGER NOT NULL DEFAULT 0,
    duplicate_blob  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_verify_challenge ON verify_decisions(challenge_id);
CREATE INDEX IF NOT EXISTS idx_verify_ts ON verify_decisions(ts DESC);

-- An integrator's verdict on a live decision row (POST /v1/feedback). Lives
-- only as long as the row it annotates: the prune folds it into the sample.
CREATE TABLE IF NOT EXISTS labels (
    challenge_id    TEXT PRIMARY KEY,
    site_key        TEXT NOT NULL,
    verdict         TEXT NOT NULL,
    ts              TEXT NOT NULL
);

-- Anonymised decisions, written by the retention prune and never deleted.
-- Deliberately no ip, no user_agent, no minute-level timestamp: what is here
-- identifies nobody, which is what lets it live without a retention window.
CREATE TABLE IF NOT EXISTS training_samples (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_id    TEXT UNIQUE,
    site_key        TEXT NOT NULL,
    hour            TEXT NOT NULL,
    score           INTEGER NOT NULL,
    tier            TEXT    NOT NULL,
    difficulty      INTEGER NOT NULL,
    outcome         TEXT    NOT NULL,
    monitored       INTEGER NOT NULL,
    sig_rate              INTEGER NOT NULL,
    sig_header_anomaly    INTEGER NOT NULL,
    sig_ip_reputation     INTEGER NOT NULL,
    sig_tls_fingerprint   INTEGER NOT NULL,
    ip_reputation_category TEXT,
    country         TEXT,
    browser_family  TEXT,
    v_score         INTEGER,
    v_outcome       TEXT,
    v_success       INTEGER,
    v_monitored     INTEGER,
    sig_honeypot    INTEGER,
    sig_time_on_page INTEGER,
    sig_behavior    INTEGER,
    sig_remote_ip   INTEGER,
    time_on_page_ms INTEGER,
    webdriver       TEXT,
    automation      TEXT,
    headless        TEXT,
    mouse_moves     INTEGER,
    touches         INTEGER,
    interactions    INTEGER,
    first_interaction_ms INTEGER,
    impossible_timing INTEGER,
    duplicate_blob  INTEGER,
    label           TEXT,
    labeled_at      TEXT
);
CREATE INDEX IF NOT EXISTS idx_training_site ON training_samples(site_key);
";

/// Everything the training copy takes from a decision that is about to be
/// pruned. Column order is what `copy_to_training` indexes by; `ts` and
/// `user_agent` are transformed on the way across, the rest passes through.
const SELECT_FOR_TRAINING: &str = "SELECT
    p.ts, p.challenge_id, p.site_key, p.score, p.tier, p.difficulty, p.outcome, p.monitored,
    p.sig_rate, p.sig_header_anomaly, p.sig_ip_reputation, p.sig_tls_fingerprint,
    p.ip_reputation_category, p.country, p.user_agent,
    v.score, v.outcome, v.success, v.monitored,
    v.sig_honeypot, v.sig_time_on_page, v.sig_behavior, v.sig_remote_ip,
    v.time_on_page_ms, v.webdriver, v.automation, v.headless,
    v.mouse_moves, v.touches, v.interactions, v.first_interaction_ms,
    v.impossible_timing, v.duplicate_blob,
    l.verdict, l.ts
FROM puzzle_decisions p
LEFT JOIN verify_decisions v ON v.challenge_id = p.challenge_id
LEFT JOIN labels l ON l.challenge_id = p.challenge_id
WHERE p.ts < ?1
ORDER BY p.id";

const INSERT_TRAINING: &str = "INSERT OR IGNORE INTO training_samples (
    challenge_id, site_key, hour, score, tier, difficulty, outcome, monitored,
    sig_rate, sig_header_anomaly, sig_ip_reputation, sig_tls_fingerprint,
    ip_reputation_category, country, browser_family,
    v_score, v_outcome, v_success, v_monitored,
    sig_honeypot, sig_time_on_page, sig_behavior, sig_remote_ip,
    time_on_page_ms, webdriver, automation, headless,
    mouse_moves, touches, interactions, first_interaction_ms,
    impossible_timing, duplicate_blob,
    label, labeled_at
) VALUES (
    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8,
    ?9, ?10, ?11, ?12,
    ?13, ?14, ?15,
    ?16, ?17, ?18, ?19,
    ?20, ?21, ?22, ?23,
    ?24, ?25, ?26, ?27,
    ?28, ?29, ?30, ?31,
    ?32, ?33,
    ?34, ?35
)";

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
    // Raw behaviour counters and probe flags, kept for the training copy.
    // NULL on pre-existing rows: they were never recorded.
    "ALTER TABLE verify_decisions ADD COLUMN automation TEXT",
    "ALTER TABLE verify_decisions ADD COLUMN headless TEXT",
    "ALTER TABLE verify_decisions ADD COLUMN mouse_moves INTEGER",
    "ALTER TABLE verify_decisions ADD COLUMN touches INTEGER",
    "ALTER TABLE verify_decisions ADD COLUMN interactions INTEGER",
    "ALTER TABLE verify_decisions ADD COLUMN first_interaction_ms INTEGER",
    "ALTER TABLE verify_decisions ADD COLUMN impossible_timing INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE verify_decisions ADD COLUMN duplicate_blob INTEGER NOT NULL DEFAULT 0",
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
    /// Attach an integrator's verdict to a decision. Routed through the writer
    /// so it cannot race the prune that folds labels into training samples;
    /// the ack says whether a decision for that challenge exists for that site.
    Label {
        challenge_id: String,
        site_key: String,
        verdict: &'static str,
        ack: oneshot::Sender<rusqlite::Result<bool>>,
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
                        Msg::Clear(_) | Msg::Prune { .. } | Msg::Label { .. } | Msg::Flush(_) => {
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
                                    Ok(
                                        m @ (Msg::Clear(_)
                                        | Msg::Prune { .. }
                                        | Msg::Label { .. }
                                        | Msg::Flush(_)),
                                    ) => {
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

    /// Attach an integrator's `spam`/`legit` verdict to a challenge. Lands on
    /// the live decision row, or — once the sweeper has folded that row into
    /// `training_samples` — on the sample directly, so feedback that arrives
    /// days later still reaches the dataset. `Ok(false)` means no decision for
    /// that challenge exists for that site.
    pub async fn label(
        &self,
        challenge_id: Uuid,
        site_key: Uuid,
        verdict: FeedbackVerdict,
    ) -> rusqlite::Result<bool> {
        let (tx, rx) = oneshot::channel();
        let msg = Msg::Label {
            challenge_id: challenge_id.to_string(),
            site_key: site_key.to_string(),
            verdict: verdict.as_str(),
            ack: tx,
        };
        if self.sender.send(msg).await.is_err() {
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
            Msg::Clear(_) | Msg::Prune { .. } | Msg::Label { .. } | Msg::Flush(_) => {}
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
        Msg::Label {
            challenge_id,
            site_key,
            verdict,
            ack,
        } => {
            let result = apply_label(conn, &challenge_id, &site_key, verdict);
            if let Err(e) = &result {
                tracing::warn!(error = %e, "decision-log: label failed");
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
    // Labels annotate live rows; training samples are the long-term set and
    // deliberately survive a dashboard reset.
    tx.execute("DELETE FROM labels", [])?;
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
    // Fold the rows about to go into the anonymised training set first, in
    // the same transaction: a crash between the two loses nothing and
    // duplicates nothing.
    copy_to_training(&tx, cutoff)?;
    // Verify rows first: a verify always shares its puzzle's window, so
    // pruning by each table's own `ts` keeps the join consistent — a puzzle
    // row only survives if it's newer than the cutoff, and the queries drive
    // the join from the puzzle side anyway.
    let verifies = tx.execute("DELETE FROM verify_decisions WHERE ts < ?1", [cutoff])?;
    let puzzles = tx.execute("DELETE FROM puzzle_decisions WHERE ts < ?1", [cutoff])?;
    // A label lives only as long as the row it annotates; the ones that
    // mattered were just folded into their samples.
    tx.execute(
        "DELETE FROM labels WHERE challenge_id NOT IN
            (SELECT challenge_id FROM puzzle_decisions WHERE challenge_id IS NOT NULL)",
        [],
    )?;
    tx.commit()?;
    Ok(verifies + puzzles)
}

/// Copy every decision older than `cutoff` into `training_samples`, minus
/// everything that could identify a visitor: the IP is dropped, the
/// user-agent string is reduced to its browser family, the timestamp to the
/// hour. What remains is a row of scores, counters and categories that
/// identifies nobody — anonymous within the meaning of Recital 26 GDPR, which
/// is what lets it live without a retention limit. The integrator's label, if
/// one arrived while the row was live, rides along. Rows that never saw a
/// verify are copied too: an issued-but-never-solved puzzle is a signal.
fn copy_to_training(conn: &Connection, cutoff: &str) -> rusqlite::Result<usize> {
    use rusqlite::types::Value;

    let mut select = conn.prepare(SELECT_FOR_TRAINING)?;
    let mut insert = conn.prepare(INSERT_TRAINING)?;
    let mut rows = select.query([cutoff])?;
    let mut copied = 0;
    while let Some(row) = rows.next()? {
        let ts: String = row.get(0)?;
        let user_agent: Option<String> = row.get(14)?;
        let family = user_agent
            .as_deref()
            .map(|ua| Value::Text(browser_family(Some(ua)).to_string()))
            .unwrap_or(Value::Null);

        let mut values: Vec<Value> = Vec::with_capacity(35);
        values.push(row.get::<_, Value>(1)?); // challenge_id
        values.push(row.get::<_, Value>(2)?); // site_key
        values.push(Value::Text(hour_bucket(&ts)));
        for i in 3..=13 {
            values.push(row.get::<_, Value>(i)?); // score .. country
        }
        values.push(family);
        for i in 15..=34 {
            values.push(row.get::<_, Value>(i)?); // verify columns, label
        }
        copied += insert.execute(rusqlite::params_from_iter(values))?;
    }
    Ok(copied)
}

/// Truncate an RFC3339 timestamp to its UTC hour. Coarse on purpose: a
/// minute-level time on a low-traffic site can single a visitor out.
fn hour_bucket(ts: &str) -> String {
    match chrono::DateTime::parse_from_rfc3339(ts) {
        Ok(t) => t
            .with_timezone(&chrono::Utc)
            .format("%Y-%m-%dT%H:00:00Z")
            .to_string(),
        // Not RFC3339: keep the date+hour prefix rather than lose the row.
        Err(_) => format!("{}:00:00Z", &ts[..ts.len().min(13)]),
    }
}

/// Route an integrator's verdict to wherever the decision currently lives.
/// The site check is what keeps one tenant from labelling another's traffic.
fn apply_label(
    conn: &Connection,
    challenge_id: &str,
    site_key: &str,
    verdict: &str,
) -> rusqlite::Result<bool> {
    let ts = chrono::Utc::now().to_rfc3339();
    // Already anonymised into a sample: label the sample directly.
    let updated = conn.execute(
        "UPDATE training_samples SET label = ?1, labeled_at = ?2
         WHERE challenge_id = ?3 AND site_key = ?4",
        params![verdict, ts, challenge_id, site_key],
    )?;
    if updated > 0 {
        return Ok(true);
    }
    let live: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM puzzle_decisions WHERE challenge_id = ?1 AND site_key = ?2 LIMIT 1",
            params![challenge_id, site_key],
            |r| r.get(0),
        )
        .optional()?;
    if live.is_none() {
        return Ok(false);
    }
    conn.execute(
        "INSERT INTO labels (challenge_id, site_key, verdict, ts) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(challenge_id) DO UPDATE SET verdict = excluded.verdict, ts = excluded.ts",
        params![challenge_id, site_key, verdict, ts],
    )?;
    Ok(true)
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
            time_on_page_ms, webdriver, monitored, sig_remote_ip,
            automation, headless, mouse_moves, touches, interactions,
            first_interaction_ms, impossible_timing, duplicate_blob
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5,
            ?6, ?7, ?8,
            ?9, ?10, ?11, ?12,
            ?13, ?14, ?15, ?16, ?17,
            ?18, ?19, ?20
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
            r.automation,
            r.headless,
            r.behavior.map(|b| b.mouse_moves),
            r.behavior.map(|b| b.touches),
            r.behavior.map(|b| b.interactions),
            // Client-asserted: a lying blob can carry any u64, and a value past
            // i64::MAX would wrap negative here and then fail to parse as an
            // integer downstream (the training export, dx's puller). Clamp;
            // the impossible-timing check has already scored the lie.
            r.behavior
                .and_then(|b| b.first_interaction_ms)
                .map(|v| i64::try_from(v).unwrap_or(i64::MAX)),
            r.impossible_timing as i64,
            r.duplicate_blob as i64,
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

    /// A client-asserted `first_interaction_ms` past `i64::MAX` is clamped
    /// rather than wrapped, so the row — and every export that reads it —
    /// stays a valid integer.
    #[test]
    fn insert_verify_clamps_a_hostile_first_interaction() {
        use crate::risk::BehaviorReport;
        use crate::risk::verify::VerifyBreakdown;

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        let record = VerifyRecord {
            monitored: false,
            challenge_id: Uuid::new_v4(),
            success: true,
            outcome: "pass",
            score: 0,
            breakdown: VerifyBreakdown::default(),
            time_on_page_ms: Some(5_000),
            webdriver: "false",
            automation: "false",
            headless: "false",
            behavior: Some(BehaviorReport {
                first_interaction_ms: Some(u64::MAX),
                ..Default::default()
            }),
            impossible_timing: true,
            duplicate_blob: false,
        };
        insert_verify(&conn, &record).unwrap();
        let stored: i64 = conn
            .query_row(
                "SELECT first_interaction_ms FROM verify_decisions",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stored, i64::MAX);
    }

    /// The prune folds each row it is about to delete into `training_samples`
    /// first — without the IP, with the user-agent reduced to a family and the
    /// timestamp to the hour — and carries the integrator's label across.
    #[test]
    fn prune_copies_rows_into_anonymised_training_samples() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        conn.execute_batch(
            "INSERT INTO puzzle_decisions
               (ts, challenge_id, site_key, ip, ip_count, site_count, score, tier, difficulty,
                outcome, sig_rate, sig_header_anomaly, sig_ip_reputation,
                sig_tls_fingerprint, tls_fingerprint, user_agent, country)
             VALUES
               ('2026-01-01T13:07:09+00:00','old','s','1.2.3.0',1,1,10,'Checkbox',12,'issued',
                10,0,0,0,'Skipped','Mozilla/5.0 (X11) Chrome/120.0 Safari/537.36','DE'),
               ('2026-01-05T00:00:00+00:00','new','s','1.2.3.0',1,1,10,'Checkbox',12,'issued',
                10,0,0,0,'Skipped',NULL,NULL);
             INSERT INTO verify_decisions
               (ts, challenge_id, success, outcome, score, sig_honeypot, sig_time_on_page,
                sig_behavior, time_on_page_ms, webdriver, mouse_moves, interactions)
             VALUES
               ('2026-01-01T13:07:12+00:00','old',1,'shadow_fail',30,0,0,30,5000,'false',20,2);
             INSERT INTO labels (challenge_id, site_key, verdict, ts)
             VALUES ('old','s','spam','2026-01-02T00:00:00+00:00');",
        )
        .unwrap();

        prune_before(&conn, "2026-01-03T00:00:00+00:00").unwrap();

        let (cid, hour, family, country, v_score, mouse_moves, label): (
            String,
            String,
            String,
            String,
            i64,
            i64,
            String,
        ) = conn
            .query_row(
                "SELECT challenge_id, hour, browser_family, country, v_score, mouse_moves, label
                 FROM training_samples",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(cid, "old", "only the pruned row is copied");
        assert_eq!(hour, "2026-01-01T13:00:00Z", "minute and second are gone");
        assert_eq!(family, "Chrome", "the UA string is reduced to a family");
        assert_eq!(country, "DE");
        assert_eq!(v_score, 30);
        assert_eq!(mouse_moves, 20);
        assert_eq!(label, "spam", "the label rode along");

        // The table cannot hold what it must not: no ip, no user_agent column.
        let columns: Vec<String> = conn
            .prepare("PRAGMA table_info(training_samples)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(!columns.iter().any(|c| c == "ip" || c == "user_agent"));

        // The folded label is gone with its row; the fresh row is untouched.
        let labels: i64 = conn
            .query_row("SELECT COUNT(*) FROM labels", [], |r| r.get(0))
            .unwrap();
        assert_eq!(labels, 0);

        // A late label lands on the sample; the wrong site cannot touch it.
        assert!(!apply_label(&conn, "old", "other-site", "legit").unwrap());
        assert!(apply_label(&conn, "old", "s", "legit").unwrap());
        let label: String = conn
            .query_row("SELECT label FROM training_samples", [], |r| r.get(0))
            .unwrap();
        assert_eq!(label, "legit");
        // A label for a live row goes to `labels`; an unknown one is refused.
        assert!(apply_label(&conn, "new", "s", "spam").unwrap());
        assert!(!apply_label(&conn, "nope", "s", "spam").unwrap());
        let pending: String = conn
            .query_row(
                "SELECT verdict FROM labels WHERE challenge_id = 'new'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pending, "spam");
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
