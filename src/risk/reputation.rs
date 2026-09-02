use super::weights::{SignalWeights, current};
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use ipnet::IpNet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpCategory {
    Datacenter,
    Tor,
    Vpn,
    Residential,
}

impl IpCategory {
    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "datacenter" | "dc" | "hosting" => Some(Self::Datacenter),
            "tor" => Some(Self::Tor),
            "vpn" | "proxy" => Some(Self::Vpn),
            "residential" | "isp" => Some(Self::Residential),
            _ => None,
        }
    }

    /// Canonical lowercase name, stable across config aliases (`dc`/`hosting`
    /// both normalise to `datacenter`). Used as the at-rest label in the
    /// decision log so the dashboard can break traffic down by network type.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Datacenter => "datacenter",
            Self::Tor => "tor",
            Self::Vpn => "vpn",
            Self::Residential => "residential",
        }
    }
}

/// File-backed CIDR list. One entry per line: `<cidr> <category>` (whitespace-separated).
/// Lines starting with `#` and blank lines are ignored. Unknown categories on otherwise
/// well-formed lines are skipped with a warning.
pub struct CidrListReputation {
    entries: Vec<(IpNet, IpCategory)>,
}

impl CidrListReputation {
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        let content =
            fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        Self::parse(&content)
    }

    pub fn parse(content: &str) -> Result<Self, String> {
        let mut entries = Vec::new();
        for (lineno, raw) in content.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let cidr_str = parts
                .next()
                .ok_or_else(|| format!("line {}: missing cidr", lineno + 1))?;
            let category_str = parts
                .next()
                .ok_or_else(|| format!("line {}: missing category", lineno + 1))?;
            let cidr: IpNet = cidr_str
                .parse()
                .map_err(|e| format!("line {}: bad cidr {cidr_str:?}: {e}", lineno + 1))?;
            let Some(category) = IpCategory::parse(category_str) else {
                tracing::warn!(
                    "ip reputation: unknown category {category_str:?} on line {}, skipping",
                    lineno + 1
                );
                continue;
            };
            entries.push((cidr, category));
        }
        Ok(Self { entries })
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<IpCategory> {
        // First match wins. For small lists this is fine; replace with a trie if it grows.
        self.entries
            .iter()
            .find(|(net, _)| net.contains(&ip))
            .map(|(_, cat)| *cat)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Hot-swappable reputation list. Reads use `ArcSwap::load` (a single
/// atomic load — no locking on the request path) and reloads atomically
/// publish a freshly-parsed list. Held by `RiskScorer` and by the
/// fs-watcher in `main.rs`.
pub struct ReputationStore {
    inner: ArcSwap<CidrListReputation>,
}

impl ReputationStore {
    pub fn new(initial: CidrListReputation) -> Self {
        Self {
            inner: ArcSwap::from_pointee(initial),
        }
    }

    pub fn empty() -> Self {
        Self::new(CidrListReputation::empty())
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<IpCategory> {
        self.inner.load().lookup(ip)
    }

    pub fn replace(&self, next: CidrListReputation) {
        self.inner.store(Arc::new(next));
    }
}

// Score contributions per category. Tor is the strongest signal because the
// IP set is small and well-defined; datacenter / vpn are noisier (some legit
// traffic) so they're moderate; residential is a faint trust nudge but kept
// at zero for v1 to avoid over-weighting a noisy positive signal.
pub const SCORE_TOR: u32 = 40;
pub const SCORE_DATACENTER: u32 = 30;
pub const SCORE_VPN: u32 = 20;
pub const SCORE_RESIDENTIAL: u32 = 0;

pub fn score_ip_reputation(category: Option<IpCategory>) -> u32 {
    score_ip_reputation_with(current(), category)
}

/// [`score_ip_reputation`] against explicit weights; the plain form reads the
/// process-wide table from [`super::weights::current`].
pub fn score_ip_reputation_with(w: &SignalWeights, category: Option<IpCategory>) -> u32 {
    match category {
        Some(IpCategory::Tor) => w.ip_tor,
        Some(IpCategory::Datacenter) => w.ip_datacenter,
        Some(IpCategory::Vpn) => w.ip_vpn,
        Some(IpCategory::Residential) => w.ip_residential,
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn empty_list_returns_none() {
        let rep = CidrListReputation::empty();
        assert_eq!(rep.lookup(ip("10.0.0.1")), None);
    }

    #[test]
    fn parses_simple_list() {
        let content = "\
            # comment line\n\
            10.0.0.0/8 datacenter\n\
            \n\
            192.168.0.0/16 vpn\n\
            2001:db8::/32 tor\n\
        ";
        let rep = CidrListReputation::parse(content).unwrap();
        assert_eq!(rep.len(), 3);
        assert_eq!(rep.lookup(ip("10.5.6.7")), Some(IpCategory::Datacenter));
        assert_eq!(rep.lookup(ip("192.168.1.1")), Some(IpCategory::Vpn));
        assert_eq!(rep.lookup(ip("2001:db8::1")), Some(IpCategory::Tor));
        assert_eq!(rep.lookup(ip("8.8.8.8")), None);
    }

    #[test]
    fn ignores_inline_comments_and_blank_lines() {
        let content = "10.0.0.0/8 datacenter # hosting provider X\n\n\n";
        let rep = CidrListReputation::parse(content).unwrap();
        assert_eq!(rep.len(), 1);
    }

    #[test]
    fn unknown_category_skipped() {
        let content = "10.0.0.0/8 mystery_category\n";
        let rep = CidrListReputation::parse(content).unwrap();
        assert_eq!(rep.len(), 0);
    }

    #[test]
    fn malformed_cidr_errors() {
        let content = "not.a.cidr datacenter\n";
        let result = CidrListReputation::parse(content);
        assert!(result.is_err());
    }

    #[test]
    fn first_match_wins() {
        // Overlapping ranges — first listed wins.
        let content = "10.0.0.0/8 datacenter\n10.0.0.0/16 vpn\n";
        let rep = CidrListReputation::parse(content).unwrap();
        assert_eq!(rep.lookup(ip("10.0.0.1")), Some(IpCategory::Datacenter));
    }

    #[test]
    fn score_mapping() {
        assert_eq!(score_ip_reputation(Some(IpCategory::Tor)), SCORE_TOR);
        assert_eq!(
            score_ip_reputation(Some(IpCategory::Datacenter)),
            SCORE_DATACENTER
        );
        assert_eq!(score_ip_reputation(Some(IpCategory::Vpn)), SCORE_VPN);
        assert_eq!(
            score_ip_reputation(Some(IpCategory::Residential)),
            SCORE_RESIDENTIAL
        );
        assert_eq!(score_ip_reputation(None), 0);
    }

    #[test]
    fn store_swap_publishes_new_list() {
        let store = ReputationStore::empty();
        assert_eq!(store.lookup(ip("10.0.0.1")), None);
        store.replace(CidrListReputation::parse("10.0.0.0/8 datacenter\n").unwrap());
        assert_eq!(store.lookup(ip("10.0.0.1")), Some(IpCategory::Datacenter));
        // Swap to a different list — old entry is gone, new one is live.
        store.replace(CidrListReputation::parse("203.0.113.0/24 tor\n").unwrap());
        assert_eq!(store.lookup(ip("10.0.0.1")), None);
        assert_eq!(store.lookup(ip("203.0.113.7")), Some(IpCategory::Tor));
    }
}
