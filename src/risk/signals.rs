use super::weights::{SignalWeights, current};
use axum::http::HeaderMap;
use axum::http::header::{ACCEPT_ENCODING, ACCEPT_LANGUAGE, USER_AGENT};

// --- Rate signal ---

pub const RATE_IP_VERY_HIGH: u32 = 50;
pub const RATE_IP_HIGH: u32 = 20;
pub const RATE_IP_ELEVATED: u32 = 10;

pub const RATE_IP_SCORE_VERY_HIGH: u32 = 30;
pub const RATE_IP_SCORE_HIGH: u32 = 15;
pub const RATE_IP_SCORE_ELEVATED: u32 = 8;

pub const RATE_SITE_VERY_HIGH: u32 = 500;
pub const RATE_SITE_HIGH: u32 = 200;

pub const RATE_SITE_SCORE_VERY_HIGH: u32 = 15;
pub const RATE_SITE_SCORE_HIGH: u32 = 8;

/// Length of the second, sustained per-IP window. The 60 s window sees bursts;
/// this one sees the source that paces itself just under the minute
/// thresholds — 9 requests a minute never trips `> RATE_IP_ELEVATED`, but
/// 135 in a quarter hour does.
pub const RATE_SUSTAINED_WINDOW_SECS: i64 = 900;

/// Sustained-window thresholds. Each is the rate a source must *hold* for the
/// whole window to reach the band — roughly 6 / 12 / 30 a minute — which no
/// single visitor produces (the widget fetches one puzzle per page load plus
/// one refresh per `CHALLENGE_TTL_SECS`) but a shared egress can, so the
/// lowest band stays below `TIER_CHECKBOX_MIN` on its own, like the 60 s one.
pub const RATE_IP_SUSTAINED_VERY_HIGH: u32 = 450;
pub const RATE_IP_SUSTAINED_HIGH: u32 = 180;
pub const RATE_IP_SUSTAINED_ELEVATED: u32 = 90;

fn ip_band(w: &SignalWeights, count: u32, very_high: u32, high: u32, elevated: u32) -> u32 {
    if count > very_high {
        w.rate_ip_very_high
    } else if count > high {
        w.rate_ip_high
    } else if count > elevated {
        w.rate_ip_elevated
    } else {
        0
    }
}

/// `ip_count` is the 60 s per-IP count, `ip_count_sustained` the 15 min one.
/// The IP component is the *worse* band of the two windows, never the sum: a
/// one-minute burst scores exactly as it did with one window, the signal's
/// ceiling stays at 45, and the sustained window only matters when the minute
/// window is quiet.
pub fn score_rate(ip_count: u32, ip_count_sustained: u32, site_count: u32) -> u32 {
    score_rate_with(current(), ip_count, ip_count_sustained, site_count)
}

/// [`score_rate`] against explicit weights; the plain form reads the
/// process-wide table from [`super::weights::current`].
pub fn score_rate_with(
    w: &SignalWeights,
    ip_count: u32,
    ip_count_sustained: u32,
    site_count: u32,
) -> u32 {
    let ip_component = ip_band(
        w,
        ip_count,
        RATE_IP_VERY_HIGH,
        RATE_IP_HIGH,
        RATE_IP_ELEVATED,
    )
    .max(ip_band(
        w,
        ip_count_sustained,
        RATE_IP_SUSTAINED_VERY_HIGH,
        RATE_IP_SUSTAINED_HIGH,
        RATE_IP_SUSTAINED_ELEVATED,
    ));

    let site_component = if site_count > RATE_SITE_VERY_HIGH {
        w.rate_site_very_high
    } else if site_count > RATE_SITE_HIGH {
        w.rate_site_high
    } else {
        0
    };

    ip_component + site_component
}

// --- Header anomaly signal ---

pub const UA_MISSING_SCORE: u32 = 30;
pub const UA_SUSPICIOUS_SCORE: u32 = 25;
pub const ACCEPT_LANGUAGE_MISSING_SCORE: u32 = 10;
pub const ACCEPT_ENCODING_MISSING_SCORE: u32 = 10;

/// A UA that claims to be a browser (`Mozilla/`) on a request carrying none of
/// the fetch-metadata headers every browser has attached for years (Chrome 76,
/// Firefox 90, Safari 16.4). They are forbidden header names — page script can
/// neither add nor suppress them — so their absence under a browser UA means
/// the request did not come from a browser. Kept below `TIER_CHECKBOX_MIN` on
/// its own: the false-positive population (pre-16.4 Safari, a header-stripping
/// proxy) should see no friction unless something else also fires.
pub const SEC_FETCH_MISSING_SCORE: u32 = 15;
/// A UA that claims Chromium (`Chrome/`) without the low-entropy client hints
/// Chromium has sent on every request since 89. WebKit and Gecko never send
/// them, hence the `Chrome/` gate (Chrome on iOS reports `CriOS/` and is
/// correctly excluded). Stacks with the fetch-metadata check: each alone is
/// ambiguous, both together — a Chrome UA with neither header family — is the
/// signature of an HTTP library with a copied UA string, and the sum equals
/// `UA_MISSING_SCORE`. Presence only; the value is never read.
pub const CLIENT_HINTS_MISSING_SCORE: u32 = 15;

const SEC_FETCH_HEADERS: &[&str] = &["sec-fetch-mode", "sec-fetch-site", "sec-fetch-dest"];

const UA_MIN_LEN: usize = 10;
const UA_BOT_NEEDLES: &[&str] = &[
    "curl",
    "wget",
    "python",
    "go-http",
    "libwww",
    "httpclient",
    "java/",
];

pub fn score_header_anomaly(headers: &HeaderMap) -> u32 {
    score_header_anomaly_with(current(), headers)
}

/// [`score_header_anomaly`] against explicit weights; the plain form reads the
/// process-wide table from [`super::weights::current`].
pub fn score_header_anomaly_with(w: &SignalWeights, headers: &HeaderMap) -> u32 {
    let mut score = 0;

    match headers.get(USER_AGENT).and_then(|v| v.to_str().ok()) {
        None => score += w.ua_missing,
        Some(ua) => {
            let lower = ua.to_ascii_lowercase();
            if ua.len() < UA_MIN_LEN || UA_BOT_NEEDLES.iter().any(|n| lower.contains(n)) {
                score += w.ua_suspicious;
            }
            // Browser impersonation: the UA claims a browser, the rest of the
            // request doesn't. Any one fetch-metadata header counts as present
            // so a proxy dropping one of the three can't trip the check.
            if lower.starts_with("mozilla/")
                && !SEC_FETCH_HEADERS.iter().any(|h| headers.contains_key(*h))
            {
                score += w.sec_fetch_missing;
            }
            if lower.contains("chrome/") && !headers.contains_key("sec-ch-ua") {
                score += w.client_hints_missing;
            }
        }
    }

    if !headers.contains_key(ACCEPT_LANGUAGE) {
        score += w.accept_language_missing;
    }

    if !headers.contains_key(ACCEPT_ENCODING) {
        score += w.accept_encoding_missing;
    }

    score
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    // --- Rate tests (mirror existing difficulty.rs cases) ---

    #[test]
    fn rate_zero_yields_zero() {
        assert_eq!(score_rate(0, 0, 0), 0);
    }

    #[test]
    fn rate_very_high_ip_only() {
        // 55 > 50 → 30
        assert_eq!(score_rate(55, 0, 0), RATE_IP_SCORE_VERY_HIGH);
    }

    #[test]
    fn rate_moderate_ip() {
        // 25 > 20 → 15
        assert_eq!(score_rate(25, 0, 0), RATE_IP_SCORE_HIGH);
    }

    #[test]
    fn rate_elevated_ip() {
        // 15 > 10 → 8
        assert_eq!(score_rate(15, 0, 0), RATE_IP_SCORE_ELEVATED);
    }

    #[test]
    fn rate_very_high_site_only() {
        assert_eq!(score_rate(0, 0, 600), RATE_SITE_SCORE_VERY_HIGH);
    }

    #[test]
    fn rate_combined() {
        // 30 + 15 = 45
        assert_eq!(
            score_rate(55, 0, 600),
            RATE_IP_SCORE_VERY_HIGH + RATE_SITE_SCORE_VERY_HIGH
        );
    }

    // --- Sustained (15 min) window ---

    #[test]
    fn rate_sustained_at_threshold_is_zero() {
        assert_eq!(score_rate(9, RATE_IP_SUSTAINED_ELEVATED, 0), 0);
    }

    #[test]
    fn rate_sustained_bands_fire_while_the_minute_is_quiet() {
        // 9/min never trips the 60 s window; held for 15 min it walks the bands.
        assert_eq!(score_rate(9, 91, 0), RATE_IP_SCORE_ELEVATED);
        assert_eq!(score_rate(9, 181, 0), RATE_IP_SCORE_HIGH);
        assert_eq!(score_rate(9, 451, 0), RATE_IP_SCORE_VERY_HIGH);
    }

    #[test]
    fn rate_windows_take_the_worse_band_not_the_sum() {
        // Both windows very high: still 30, the ceiling is unchanged.
        assert_eq!(score_rate(55, 500, 0), RATE_IP_SCORE_VERY_HIGH);
        // Minute high beats sustained elevated.
        assert_eq!(score_rate(25, 91, 0), RATE_IP_SCORE_HIGH);
        // Sustained high beats minute elevated.
        assert_eq!(score_rate(15, 181, 0), RATE_IP_SCORE_HIGH);
    }

    #[test]
    fn rate_sustained_stacks_with_site_like_the_minute_window() {
        assert_eq!(
            score_rate(9, 451, 600),
            RATE_IP_SCORE_VERY_HIGH + RATE_SITE_SCORE_VERY_HIGH
        );
    }

    // --- Header anomaly tests ---

    fn headers_browser_like() -> HeaderMap {
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
        // What a browser's `fetch()` attaches on its own.
        h.insert("sec-fetch-mode", HeaderValue::from_static("cors"));
        h.insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
        h.insert("sec-fetch-dest", HeaderValue::from_static("empty"));
        h
    }

    const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                             (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36";

    fn headers_chrome_like() -> HeaderMap {
        let mut h = headers_browser_like();
        h.insert(USER_AGENT, HeaderValue::from_static(CHROME_UA));
        h.insert(
            "sec-ch-ua",
            HeaderValue::from_static(
                r#""Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128""#,
            ),
        );
        h
    }

    fn strip_fetch_metadata(h: &mut HeaderMap) {
        for name in SEC_FETCH_HEADERS {
            h.remove(*name);
        }
    }

    #[test]
    fn clean_browser_headers_score_zero() {
        assert_eq!(score_header_anomaly(&headers_browser_like()), 0);
    }

    #[test]
    fn clean_chrome_headers_score_zero() {
        assert_eq!(score_header_anomaly(&headers_chrome_like()), 0);
    }

    #[test]
    fn browser_ua_without_fetch_metadata_scores() {
        let mut h = headers_browser_like();
        strip_fetch_metadata(&mut h);
        assert_eq!(score_header_anomaly(&h), SEC_FETCH_MISSING_SCORE);
    }

    #[test]
    fn one_fetch_metadata_header_counts_as_present() {
        let mut h = headers_browser_like();
        h.remove("sec-fetch-mode");
        h.remove("sec-fetch-dest");
        assert_eq!(score_header_anomaly(&h), 0);
    }

    #[test]
    fn chrome_ua_without_client_hints_scores() {
        let mut h = headers_chrome_like();
        h.remove("sec-ch-ua");
        assert_eq!(score_header_anomaly(&h), CLIENT_HINTS_MISSING_SCORE);
    }

    #[test]
    fn webkit_ua_without_client_hints_is_clean() {
        // `headers_browser_like` is Safari-shaped; WebKit never sends UA-CH.
        let h = headers_browser_like();
        assert!(!h.contains_key("sec-ch-ua"));
        assert_eq!(score_header_anomaly(&h), 0);
    }

    #[test]
    fn http_library_with_copied_chrome_ua_scores_like_a_missing_ua() {
        let mut h = headers_chrome_like();
        strip_fetch_metadata(&mut h);
        h.remove("sec-ch-ua");
        assert_eq!(
            score_header_anomaly(&h),
            SEC_FETCH_MISSING_SCORE + CLIENT_HINTS_MISSING_SCORE
        );
        assert_eq!(score_header_anomaly(&h), UA_MISSING_SCORE);
    }

    #[test]
    fn non_browser_ua_without_fetch_metadata_is_not_impersonation() {
        // An honest server-side client claims neither Mozilla nor Chromium.
        let mut h = headers_browser_like();
        strip_fetch_metadata(&mut h);
        h.insert(USER_AGENT, HeaderValue::from_static("AcmeFormsBackend/2.0"));
        assert_eq!(score_header_anomaly(&h), 0);
    }

    #[test]
    fn missing_user_agent_scores() {
        let mut h = headers_browser_like();
        h.remove(USER_AGENT);
        assert_eq!(score_header_anomaly(&h), UA_MISSING_SCORE);
    }

    #[test]
    fn suspicious_user_agent_scores() {
        let mut h = headers_browser_like();
        h.insert(USER_AGENT, HeaderValue::from_static("curl/8.0.1"));
        assert_eq!(score_header_anomaly(&h), UA_SUSPICIOUS_SCORE);
    }

    #[test]
    fn short_user_agent_scores() {
        let mut h = headers_browser_like();
        h.insert(USER_AGENT, HeaderValue::from_static("UA/1"));
        assert_eq!(score_header_anomaly(&h), UA_SUSPICIOUS_SCORE);
    }

    #[test]
    fn python_user_agent_scores() {
        let mut h = headers_browser_like();
        h.insert(
            USER_AGENT,
            HeaderValue::from_static("python-requests/2.31.0"),
        );
        assert_eq!(score_header_anomaly(&h), UA_SUSPICIOUS_SCORE);
    }

    #[test]
    fn missing_accept_language_scores() {
        let mut h = headers_browser_like();
        h.remove(ACCEPT_LANGUAGE);
        assert_eq!(score_header_anomaly(&h), ACCEPT_LANGUAGE_MISSING_SCORE);
    }

    #[test]
    fn missing_accept_encoding_scores() {
        let mut h = headers_browser_like();
        h.remove(ACCEPT_ENCODING);
        assert_eq!(score_header_anomaly(&h), ACCEPT_ENCODING_MISSING_SCORE);
    }

    #[test]
    fn all_anomalies_additive() {
        let h = HeaderMap::new();
        assert_eq!(
            score_header_anomaly(&h),
            UA_MISSING_SCORE + ACCEPT_LANGUAGE_MISSING_SCORE + ACCEPT_ENCODING_MISSING_SCORE
        );
    }
}
