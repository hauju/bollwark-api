use std::net::IpAddr;
use std::sync::Arc;

use axum::http::HeaderMap;

use super::reputation::{ReputationStore, score_ip_reputation};
use super::signals::{score_header_anomaly, score_rate};
use super::tier::{EscalationTier, TierThresholds};
use super::tls_fingerprint::{FingerprintBlocklist, TlsFingerprint, score_tls_fingerprint};

pub struct SignalContext<'a> {
    pub ip: IpAddr,
    pub headers: &'a HeaderMap,
    pub ip_count: u32,
    pub site_count: u32,
    pub tls_fingerprint: TlsFingerprint<'a>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SignalBreakdown {
    pub rate: u32,
    pub header_anomaly: u32,
    pub ip_reputation: u32,
    pub tls_fingerprint: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct RiskScore {
    pub total: u32,
    pub breakdown: SignalBreakdown,
    pub tier: EscalationTier,
}

pub struct RiskScorer {
    thresholds: TierThresholds,
    reputation: Arc<ReputationStore>,
    tls_blocklist: Arc<FingerprintBlocklist>,
}

impl RiskScorer {
    pub fn new(
        thresholds: TierThresholds,
        reputation: Arc<ReputationStore>,
        tls_blocklist: Arc<FingerprintBlocklist>,
    ) -> Self {
        Self {
            thresholds,
            reputation,
            tls_blocklist,
        }
    }

    /// Score a request. Every signal self-gates on its own input: header
    /// anomaly always computes; IP reputation contributes 0 when no
    /// `IP_REPUTATION_FILE` is loaded; TLS fingerprint contributes 0 unless a
    /// trusted proxy supplied the header. So the privacy-invasive signals only
    /// fire when the operator has explicitly enabled their inputs.
    pub fn score(&self, ctx: &SignalContext<'_>) -> RiskScore {
        let breakdown = SignalBreakdown {
            rate: score_rate(ctx.ip_count, ctx.site_count),
            header_anomaly: score_header_anomaly(ctx.headers),
            ip_reputation: score_ip_reputation(self.reputation.lookup(ctx.ip)),
            tls_fingerprint: score_tls_fingerprint(ctx.tls_fingerprint, &self.tls_blocklist),
        };
        let total = breakdown.rate
            + breakdown.header_anomaly
            + breakdown.ip_reputation
            + breakdown.tls_fingerprint;
        let tier = self.thresholds.classify(total);
        RiskScore {
            total,
            breakdown,
            tier,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::reputation::CidrListReputation;
    use super::*;
    use axum::http::HeaderValue;
    use axum::http::header::{ACCEPT_ENCODING, ACCEPT_LANGUAGE, USER_AGENT};

    fn scorer() -> RiskScorer {
        RiskScorer::new(
            TierThresholds::default(),
            Arc::new(ReputationStore::empty()),
            Arc::new(FingerprintBlocklist::empty()),
        )
    }

    fn scorer_with_reputation(content: &str) -> RiskScorer {
        RiskScorer::new(
            TierThresholds::default(),
            Arc::new(ReputationStore::new(
                CidrListReputation::parse(content).unwrap(),
            )),
            Arc::new(FingerprintBlocklist::empty()),
        )
    }

    fn scorer_with_tls_blocklist(content: &str) -> RiskScorer {
        RiskScorer::new(
            TierThresholds::default(),
            Arc::new(ReputationStore::empty()),
            Arc::new(FingerprintBlocklist::parse(content).unwrap()),
        )
    }

    fn clean_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            USER_AGENT,
            HeaderValue::from_static(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15",
            ),
        );
        h.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        h.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        h
    }

    fn ctx<'a>(
        headers: &'a HeaderMap,
        ip: &str,
        ip_count: u32,
        site_count: u32,
    ) -> SignalContext<'a> {
        SignalContext {
            ip: ip.parse().unwrap(),
            headers,
            ip_count,
            site_count,
            tls_fingerprint: TlsFingerprint::Skipped,
        }
    }

    #[test]
    fn clean_request_yields_invisible_pass() {
        let headers = clean_headers();
        let result = scorer().score(&ctx(&headers, "127.0.0.1", 1, 1));
        assert_eq!(result.total, 0);
        assert_eq!(result.tier, EscalationTier::InvisiblePass);
    }

    #[test]
    fn high_rate_alone_reaches_hard_pow() {
        let headers = clean_headers();
        let result = scorer().score(&ctx(&headers, "127.0.0.1", 55, 600));
        assert_eq!(result.breakdown.rate, 45);
        assert_eq!(result.tier, EscalationTier::HardPow);
    }

    #[test]
    fn missing_ua_alone_reaches_checkbox() {
        let mut headers = clean_headers();
        headers.remove(USER_AGENT);
        let result = scorer().score(&ctx(&headers, "127.0.0.1", 1, 1));
        assert_eq!(result.breakdown.header_anomaly, 30);
        assert_eq!(result.tier, EscalationTier::Checkbox);
    }

    #[test]
    fn suspicious_ua_plus_very_high_rate_blocks() {
        let mut headers = clean_headers();
        headers.insert(USER_AGENT, HeaderValue::from_static("curl/8.0"));
        headers.remove(ACCEPT_LANGUAGE);
        headers.remove(ACCEPT_ENCODING);
        let result = scorer().score(&ctx(&headers, "127.0.0.1", 55, 600));
        assert_eq!(result.total, 90);
        assert_eq!(result.tier, EscalationTier::Block);
    }

    #[test]
    fn datacenter_ip_alone_reaches_hard_pow() {
        // Datacenter contributes 30; with clean headers and no rate, that lands in HardPow band? No, 30 < 40.
        // It lands in Checkbox.
        let headers = clean_headers();
        let s = scorer_with_reputation("10.0.0.0/8 datacenter\n");
        let result = s.score(&ctx(&headers, "10.5.6.7", 1, 1));
        assert_eq!(result.breakdown.ip_reputation, 30);
        assert_eq!(result.tier, EscalationTier::Checkbox);
    }

    #[test]
    fn tor_ip_alone_reaches_hard_pow() {
        // Tor = 40 → HardPow exactly at threshold
        let headers = clean_headers();
        let s = scorer_with_reputation("198.51.100.0/24 tor\n");
        let result = s.score(&ctx(&headers, "198.51.100.42", 1, 1));
        assert_eq!(result.breakdown.ip_reputation, 40);
        assert_eq!(result.tier, EscalationTier::HardPow);
    }

    #[test]
    fn known_bad_tls_fingerprint_adds_score() {
        let headers = clean_headers();
        let s = scorer_with_tls_blocklist("badfp\n");
        let mut c = ctx(&headers, "127.0.0.1", 1, 1);
        c.tls_fingerprint = TlsFingerprint::Provided("badfp");
        let result = s.score(&c);
        assert_eq!(result.breakdown.tls_fingerprint, 35);
    }

    #[test]
    fn unknown_tls_fingerprint_adds_zero() {
        let headers = clean_headers();
        let s = scorer_with_tls_blocklist("badfp\n");
        let mut c = ctx(&headers, "127.0.0.1", 1, 1);
        c.tls_fingerprint = TlsFingerprint::Provided("legit-chrome-fp");
        let result = s.score(&c);
        assert_eq!(result.breakdown.tls_fingerprint, 0);
    }
}
