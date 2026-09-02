//! TLS fingerprint signal.
//!
//! TLS fingerprints (JA3, JA4, etc.) are stable hashes of a client's TLS
//! ClientHello. They cluster strongly by stack — every Chrome on every site
//! produces the same JA4, while curl, Go's `net/http`, headless browsers, and
//! known bot frameworks each produce distinctive fingerprints.
//!
//! Native TLS inspection is intrusive (requires a custom hyper/rustls
//! acceptor) and brittle across rustls upgrades. This module instead reads the
//! fingerprint from a header set by a trusted reverse proxy (Cloudflare,
//! Envoy with `tls_inspector`, nginx with the JA4 module, etc.). The header
//! is only honored when the immediate peer IP is in a configured trusted-proxy
//! CIDR allowlist — otherwise any client could spoof it.

use super::weights::{SignalWeights, current};
use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

use ipnet::IpNet;

/// CIDR allowlist of upstream proxies whose TLS-fingerprint header we trust.
pub struct TrustedProxies {
    nets: Vec<IpNet>,
}

impl TrustedProxies {
    pub fn empty() -> Self {
        Self { nets: Vec::new() }
    }

    /// Parse a comma- or whitespace-separated list of CIDRs.
    /// Returns an error on the first malformed entry.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut nets = Vec::new();
        for raw in spec.split(|c: char| c == ',' || c.is_whitespace()) {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            let net: IpNet = trimmed
                .parse()
                .map_err(|e| format!("bad cidr {trimmed:?}: {e}"))?;
            nets.push(net);
        }
        Ok(Self { nets })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.nets.iter().any(|n| n.contains(&ip))
    }

    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    pub fn len(&self) -> usize {
        self.nets.len()
    }
}

/// Set of known-bad TLS fingerprints. Lookup is exact-match.
pub struct FingerprintBlocklist {
    set: HashSet<String>,
}

impl FingerprintBlocklist {
    pub fn empty() -> Self {
        Self {
            set: HashSet::new(),
        }
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        let content =
            fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        Self::parse(&content)
    }

    pub fn parse(content: &str) -> Result<Self, String> {
        let mut set = HashSet::new();
        for raw in content.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            // Each line is a single fingerprint value (whitespace-trimmed).
            // Rest of the line, if any, is treated as a comment.
            let fp = line.split_whitespace().next().unwrap_or("");
            if !fp.is_empty() {
                set.insert(fp.to_string());
            }
        }
        Ok(Self { set })
    }

    pub fn contains(&self, fp: &str) -> bool {
        self.set.contains(fp)
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum TlsFingerprint<'a> {
    /// Feature disabled, peer isn't trusted, or header wasn't sent. No score.
    Skipped,
    /// Handler read the header from a trusted peer; scorer should look it up.
    Provided(&'a str),
}

pub const FINGERPRINT_BAD_SCORE: u32 = 35;

pub fn score_tls_fingerprint(fp: TlsFingerprint<'_>, list: &FingerprintBlocklist) -> u32 {
    score_tls_fingerprint_with(current(), fp, list)
}

/// [`score_tls_fingerprint`] against explicit weights; the plain form reads the
/// process-wide table from [`super::weights::current`].
pub fn score_tls_fingerprint_with(
    w: &SignalWeights,
    fp: TlsFingerprint<'_>,
    list: &FingerprintBlocklist,
) -> u32 {
    match fp {
        TlsFingerprint::Skipped => 0,
        TlsFingerprint::Provided(value) if list.contains(value) => w.tls_fingerprint_bad,
        TlsFingerprint::Provided(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn trusted_proxies_parses_comma_list() {
        let p = TrustedProxies::parse("10.0.0.0/8, 192.168.0.0/16").unwrap();
        assert_eq!(p.len(), 2);
        assert!(p.contains(ip("10.5.6.7")));
        assert!(p.contains(ip("192.168.1.1")));
        assert!(!p.contains(ip("8.8.8.8")));
    }

    #[test]
    fn trusted_proxies_parses_whitespace_list() {
        let p = TrustedProxies::parse("10.0.0.0/8\n192.168.0.0/16").unwrap();
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn trusted_proxies_empty_input_is_empty() {
        let p = TrustedProxies::parse("").unwrap();
        assert!(p.is_empty());
    }

    #[test]
    fn trusted_proxies_rejects_bad_cidr() {
        assert!(TrustedProxies::parse("nope").is_err());
    }

    #[test]
    fn blocklist_parses_lines() {
        let content = "\
            # known-bad fingerprints\n\
            t13d1715h2_5b57614c22b0_5c2c66f702b6\n\
            \n\
            t13d301100_286b2c61aa14_e74b73c89e6c # python-requests\n\
        ";
        let bl = FingerprintBlocklist::parse(content).unwrap();
        assert_eq!(bl.len(), 2);
        assert!(bl.contains("t13d1715h2_5b57614c22b0_5c2c66f702b6"));
        assert!(bl.contains("t13d301100_286b2c61aa14_e74b73c89e6c"));
        assert!(!bl.contains("unknown"));
    }

    #[test]
    fn skipped_scores_zero() {
        let bl = FingerprintBlocklist::empty();
        assert_eq!(score_tls_fingerprint(TlsFingerprint::Skipped, &bl), 0);
    }

    #[test]
    fn unmatched_scores_zero() {
        let bl = FingerprintBlocklist::parse("known\n").unwrap();
        assert_eq!(
            score_tls_fingerprint(TlsFingerprint::Provided("benign-chrome"), &bl),
            0
        );
    }

    #[test]
    fn matched_scores_bad() {
        let bl = FingerprintBlocklist::parse("badfp\n").unwrap();
        assert_eq!(
            score_tls_fingerprint(TlsFingerprint::Provided("badfp"), &bl),
            FINGERPRINT_BAD_SCORE
        );
    }
}
