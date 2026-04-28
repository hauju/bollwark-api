//! Validation dashboard: SQLite-backed log of every puzzle and verify
//! decision, plus the read API + static HTML the operator inspects them with.
//!
//! Decisions are written from the hot path through an unbounded channel so
//! the request handler never blocks on disk. A dedicated writer thread owns
//! the only mutating connection. Reads use a separate read-only connection
//! pool (one connection per query, opened on demand by `spawn_blocking`),
//! safe to run concurrently with the writer because the database is in WAL
//! mode.

pub mod log;
pub mod query;
pub mod routes;
pub mod types;

pub use log::DecisionLog;
pub use query::Sessions;
