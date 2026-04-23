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

pub fn score_rate(ip_count: u32, site_count: u32) -> u32 {
    let ip_component = if ip_count > RATE_IP_VERY_HIGH {
        RATE_IP_SCORE_VERY_HIGH
    } else if ip_count > RATE_IP_HIGH {
        RATE_IP_SCORE_HIGH
    } else if ip_count > RATE_IP_ELEVATED {
        RATE_IP_SCORE_ELEVATED
    } else {
        0
    };

    let site_component = if site_count > RATE_SITE_VERY_HIGH {
        RATE_SITE_SCORE_VERY_HIGH
    } else if site_count > RATE_SITE_HIGH {
        RATE_SITE_SCORE_HIGH
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

// --- Cookie age signal ---
//
// Missing cookies aren't strongly suspicious on their own (most legit users
// start with no cookie), but a cookie that was just issued and immediately
// reused likely means a script that re-fetches per request. Old cookies are
// a faint trust nudge.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookiePresence {
    /// Cookie signing isn't configured. Signal contributes 0.
    Disabled,
    /// Cookie signing is on, but the request didn't carry a valid cookie.
    Missing,
    /// Cookie signing is on and the request's cookie verified. Age in seconds.
    Present(u64),
}

pub const COOKIE_MISSING_SCORE: u32 = 5;
pub const COOKIE_VERY_YOUNG_SCORE: u32 = 20; // < 60s
pub const COOKIE_YOUNG_SCORE: u32 = 10; // < 5min
pub const COOKIE_FRESH_SCORE: u32 = 5; // < 1h

pub fn score_cookie_age(presence: CookiePresence) -> u32 {
    match presence {
        CookiePresence::Disabled => 0,
        CookiePresence::Missing => COOKIE_MISSING_SCORE,
        CookiePresence::Present(age) if age < 60 => COOKIE_VERY_YOUNG_SCORE,
        CookiePresence::Present(age) if age < 300 => COOKIE_YOUNG_SCORE,
        CookiePresence::Present(age) if age < 3600 => COOKIE_FRESH_SCORE,
        CookiePresence::Present(_) => 0,
    }
}

pub fn score_header_anomaly(headers: &HeaderMap) -> u32 {
    let mut score = 0;

    match headers.get(USER_AGENT).and_then(|v| v.to_str().ok()) {
        None => score += UA_MISSING_SCORE,
        Some(ua) => {
            let lower = ua.to_ascii_lowercase();
            if ua.len() < UA_MIN_LEN || UA_BOT_NEEDLES.iter().any(|n| lower.contains(n)) {
                score += UA_SUSPICIOUS_SCORE;
            }
        }
    }

    if !headers.contains_key(ACCEPT_LANGUAGE) {
        score += ACCEPT_LANGUAGE_MISSING_SCORE;
    }

    if !headers.contains_key(ACCEPT_ENCODING) {
        score += ACCEPT_ENCODING_MISSING_SCORE;
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
        assert_eq!(score_rate(0, 0), 0);
    }

    #[test]
    fn rate_very_high_ip_only() {
        // 55 > 50 → 30
        assert_eq!(score_rate(55, 0), RATE_IP_SCORE_VERY_HIGH);
    }

    #[test]
    fn rate_moderate_ip() {
        // 25 > 20 → 15
        assert_eq!(score_rate(25, 0), RATE_IP_SCORE_HIGH);
    }

    #[test]
    fn rate_elevated_ip() {
        // 15 > 10 → 8
        assert_eq!(score_rate(15, 0), RATE_IP_SCORE_ELEVATED);
    }

    #[test]
    fn rate_very_high_site_only() {
        assert_eq!(score_rate(0, 600), RATE_SITE_SCORE_VERY_HIGH);
    }

    #[test]
    fn rate_combined() {
        // 30 + 15 = 45
        assert_eq!(
            score_rate(55, 600),
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
        h
    }

    #[test]
    fn clean_browser_headers_score_zero() {
        assert_eq!(score_header_anomaly(&headers_browser_like()), 0);
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

    // --- Cookie age tests ---

    #[test]
    fn cookie_age_curve() {
        assert_eq!(score_cookie_age(CookiePresence::Disabled), 0);
        assert_eq!(
            score_cookie_age(CookiePresence::Missing),
            COOKIE_MISSING_SCORE
        );
        assert_eq!(
            score_cookie_age(CookiePresence::Present(0)),
            COOKIE_VERY_YOUNG_SCORE
        );
        assert_eq!(
            score_cookie_age(CookiePresence::Present(59)),
            COOKIE_VERY_YOUNG_SCORE
        );
        assert_eq!(
            score_cookie_age(CookiePresence::Present(60)),
            COOKIE_YOUNG_SCORE
        );
        assert_eq!(
            score_cookie_age(CookiePresence::Present(299)),
            COOKIE_YOUNG_SCORE
        );
        assert_eq!(
            score_cookie_age(CookiePresence::Present(300)),
            COOKIE_FRESH_SCORE
        );
        assert_eq!(
            score_cookie_age(CookiePresence::Present(3599)),
            COOKIE_FRESH_SCORE
        );
        assert_eq!(score_cookie_age(CookiePresence::Present(3600)), 0);
        assert_eq!(score_cookie_age(CookiePresence::Present(86400 * 30)), 0);
    }
}
