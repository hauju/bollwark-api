//! Reverse-proxy aware client IP resolution.
//!
//! Behind a reverse proxy (Cloudflare, nginx, AWS ALB, …) the TCP peer is the
//! proxy itself. Rate, IP-reputation, and other per-IP signals must use the
//! original client instead, which the proxy passes in `X-Forwarded-For`.
//!
//! The header is trivially spoofable, so we only honor it when the immediate
//! peer is in the configured `TrustedProxies` allowlist. We then walk XFF
//! right-to-left, skipping trusted-proxy hops, until we find the first
//! untrusted IP — that's the client. If all hops are trusted (single proxy
//! prepending), we fall back to the leftmost.

use std::net::IpAddr;

use axum::http::HeaderMap;

use super::tls_fingerprint::TrustedProxies;

/// Resolve the client IP. When `peer` is in `trusted`, walk `X-Forwarded-For`
/// rightmost-untrusted. Otherwise return the peer as-is.
pub fn client_ip(peer: IpAddr, headers: &HeaderMap, trusted: &TrustedProxies) -> IpAddr {
    if trusted.is_empty() || !trusted.contains(peer) {
        return peer;
    }

    let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) else {
        return peer;
    };

    // Parse IPs left-to-right (header order: client, proxy1, proxy2, …),
    // then walk right-to-left looking for the first untrusted hop.
    let hops: Vec<IpAddr> = value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        // Strip optional `[ipv6]:port` or `ipv4:port` from each hop. Most
        // proxies don't add a port, but some do.
        .map(strip_port)
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .collect();

    if hops.is_empty() {
        return peer;
    }

    for ip in hops.iter().rev() {
        if !trusted.contains(*ip) {
            return *ip;
        }
    }
    // All hops were trusted — return the leftmost (original client per RFC).
    hops[0]
}

fn strip_port(s: &str) -> &str {
    // Bracketed IPv6: `[::1]:1234` → `::1`. We don't return the brackets,
    // since IpAddr::parse accepts the inner form.
    if let Some(rest) = s.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        return &rest[..end];
    }
    // IPv4 with port `1.2.3.4:5678` → `1.2.3.4`. A bare IPv6 contains
    // multiple colons, so only strip when there's exactly one.
    if s.matches(':').count() == 1
        && let Some((host, _)) = s.rsplit_once(':')
    {
        return host;
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn headers_with_xff(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", value.parse().unwrap());
        h
    }

    #[test]
    fn no_trusted_proxies_returns_peer() {
        let trusted = TrustedProxies::empty();
        let h = headers_with_xff("8.8.8.8");
        assert_eq!(client_ip(ip("10.0.0.1"), &h, &trusted), ip("10.0.0.1"));
    }

    #[test]
    fn untrusted_peer_ignores_xff() {
        let trusted = TrustedProxies::parse("10.0.0.0/8").unwrap();
        let h = headers_with_xff("8.8.8.8");
        // Peer is 1.2.3.4 — not in 10/8 — so XFF is ignored.
        assert_eq!(client_ip(ip("1.2.3.4"), &h, &trusted), ip("1.2.3.4"));
    }

    #[test]
    fn trusted_peer_no_xff_returns_peer() {
        let trusted = TrustedProxies::parse("10.0.0.0/8").unwrap();
        let h = HeaderMap::new();
        assert_eq!(client_ip(ip("10.0.0.1"), &h, &trusted), ip("10.0.0.1"));
    }

    #[test]
    fn single_proxy_extracts_client() {
        let trusted = TrustedProxies::parse("10.0.0.0/8").unwrap();
        let h = headers_with_xff("8.8.8.8");
        assert_eq!(client_ip(ip("10.0.0.1"), &h, &trusted), ip("8.8.8.8"));
    }

    #[test]
    fn multi_hop_skips_trusted() {
        let trusted = TrustedProxies::parse("10.0.0.0/8").unwrap();
        // client=8.8.8.8, then trusted hop 10.0.0.5, then peer=10.0.0.1.
        let h = headers_with_xff("8.8.8.8, 10.0.0.5");
        assert_eq!(client_ip(ip("10.0.0.1"), &h, &trusted), ip("8.8.8.8"));
    }

    #[test]
    fn all_trusted_returns_leftmost() {
        let trusted = TrustedProxies::parse("10.0.0.0/8").unwrap();
        let h = headers_with_xff("10.0.0.9, 10.0.0.5");
        assert_eq!(client_ip(ip("10.0.0.1"), &h, &trusted), ip("10.0.0.9"));
    }

    #[test]
    fn untrusted_attacker_in_chain_does_not_promote_past_first() {
        // Attacker prepends a forged client. Proxy appends the real client,
        // so XFF reads `forged, real-client`. Rightmost-untrusted picks the
        // real client and ignores the forgery.
        let trusted = TrustedProxies::parse("10.0.0.0/8").unwrap();
        let h = headers_with_xff("evil-prepend, 8.8.8.8");
        // "evil-prepend" doesn't parse as an IP and is dropped during parsing.
        // Real client wins.
        assert_eq!(client_ip(ip("10.0.0.1"), &h, &trusted), ip("8.8.8.8"));
    }

    #[test]
    fn ipv4_with_port_is_handled() {
        let trusted = TrustedProxies::parse("10.0.0.0/8").unwrap();
        let h = headers_with_xff("8.8.8.8:443");
        assert_eq!(client_ip(ip("10.0.0.1"), &h, &trusted), ip("8.8.8.8"));
    }

    #[test]
    fn bracketed_ipv6_with_port_is_handled() {
        let trusted = TrustedProxies::parse("10.0.0.0/8").unwrap();
        let h = headers_with_xff("[2001:db8::1]:443");
        assert_eq!(client_ip(ip("10.0.0.1"), &h, &trusted), ip("2001:db8::1"));
    }

    #[test]
    fn malformed_xff_falls_back_to_peer() {
        let trusted = TrustedProxies::parse("10.0.0.0/8").unwrap();
        let h = headers_with_xff("not-an-ip, also-bad");
        assert_eq!(client_ip(ip("10.0.0.1"), &h, &trusted), ip("10.0.0.1"));
    }
}
