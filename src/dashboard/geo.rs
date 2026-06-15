//! Offline IP → country enrichment for the decision log. Wraps a MaxMind
//! GeoLite2 / GeoIP2 *Country* database, opened once at boot and queried by the
//! writer thread at log-write time. Entirely local — no network calls, nothing
//! leaves the box — and the lookup runs on the already-anonymized network
//! prefix (`risk::anonymize_ip` truncates to /24 or /48), which still resolves
//! to the right country. So the durable log gains a country breakdown without
//! storing anything more identifying than it already did.

use std::net::IpAddr;
use std::path::Path;

use maxminddb::{Reader, path};

/// A loaded MaxMind country database. Lookups are an in-memory mmdb tree walk,
/// so the writer thread can stamp every row without measurable overhead.
pub struct GeoIp {
    reader: Reader<Vec<u8>>,
}

impl GeoIp {
    /// Open a `.mmdb` file (GeoLite2-Country or GeoIP2-Country). Surfaces the
    /// MaxMind error on a missing/corrupt file so the caller can decide whether
    /// to fail loud or fall back to no enrichment.
    pub fn open(db_path: impl AsRef<Path>) -> Result<Self, maxminddb::MaxMindDbError> {
        Ok(Self {
            reader: Reader::open_readfile(db_path)?,
        })
    }

    /// ISO 3166-1 alpha-2 country code for `ip` (e.g. `"US"`), or `None` when
    /// the address isn't in the database. Any lookup/decode error is treated as
    /// "unknown" — geo enrichment is best-effort and must never fail a log write.
    pub fn country(&self, ip: IpAddr) -> Option<String> {
        self.reader
            .lookup(ip)
            .ok()?
            .decode_path::<String>(&path!["country", "iso_code"])
            .ok()?
    }
}
