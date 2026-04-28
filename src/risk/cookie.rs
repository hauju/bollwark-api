use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub const COOKIE_NAME: &str = "__captcha_trust";
pub const COOKIE_MAX_AGE_SECS: u64 = 60 * 60 * 24 * 30; // 30 days

/// Signs and verifies trust cookies. Token format:
///
///   <hex(issued_at_unix_secs as 8 BE bytes)>.<hex(hmac_sha256(secret, those_bytes))>
///
/// Stateless — the cookie itself carries everything needed to verify it,
/// so no storage backend changes are required.
pub struct CookieSigner {
    key: Vec<u8>,
}

impl CookieSigner {
    pub fn new(secret: impl Into<Vec<u8>>) -> Self {
        Self { key: secret.into() }
    }

    pub fn issue(&self, now_secs: u64) -> String {
        let ts_bytes = now_secs.to_be_bytes();
        let mac = self.mac(&ts_bytes);
        format!("{}.{}", hex::encode(ts_bytes), hex::encode(mac))
    }

    /// Verify a cookie value and return its issuance time (unix seconds).
    /// Returns `None` for any kind of malformation, bad signature, or future
    /// timestamps (clock skew or tampering).
    pub fn verify(&self, value: &str, now_secs: u64) -> Option<u64> {
        let (ts_hex, sig_hex) = value.split_once('.')?;
        let ts_bytes = hex::decode(ts_hex).ok()?;
        if ts_bytes.len() != 8 {
            return None;
        }
        let sig = hex::decode(sig_hex).ok()?;
        // Constant-time verify via HMAC's verify_slice.
        let mut mac = HmacSha256::new_from_slice(&self.key).ok()?;
        mac.update(&ts_bytes);
        mac.verify_slice(&sig).ok()?;

        let mut ts_arr = [0u8; 8];
        ts_arr.copy_from_slice(&ts_bytes);
        let issued_at = u64::from_be_bytes(ts_arr);
        if issued_at > now_secs.saturating_add(60) {
            // Future timestamp beyond clock-skew tolerance — reject.
            return None;
        }
        Some(issued_at)
    }

    fn mac(&self, msg: &[u8]) -> Vec<u8> {
        let mut m = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        m.update(msg);
        m.finalize().into_bytes().to_vec()
    }
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `SameSite` attribute for the trust cookie. `Lax` (default) means the
/// cookie only flows on top-level same-origin navigation; widget iframes
/// embedded on a different origin won't see it. `None` makes the cookie
/// flow on every cross-origin request — required for cross-origin embeds —
/// but browsers reject `SameSite=None` without `Secure`, so the cookie
/// signal silently breaks if HTTPS isn't terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieSameSite {
    Lax,
    None,
}

impl CookieSameSite {
    fn as_attribute(&self) -> &'static str {
        match self {
            Self::Lax => "Lax",
            Self::None => "None",
        }
    }
}

/// Build the `Set-Cookie` header value for a freshly-issued trust cookie.
/// `secure=false` for local dev (HTTP); set true behind TLS.
pub fn set_cookie_header(token: &str, secure: bool, same_site: CookieSameSite) -> String {
    let mut s = format!(
        "{COOKIE_NAME}={token}; Max-Age={COOKIE_MAX_AGE_SECS}; Path=/; HttpOnly; SameSite={}",
        same_site.as_attribute()
    );
    if secure {
        s.push_str("; Secure");
    }
    s
}

/// Extract the trust cookie value from a `Cookie` header, if present.
pub fn extract_cookie(cookie_header: &str) -> Option<&str> {
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some(rest) = pair.strip_prefix(&format!("{COOKIE_NAME}=")) {
            return Some(rest);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let signer = CookieSigner::new(b"secret".to_vec());
        let token = signer.issue(1_700_000_000);
        let issued = signer.verify(&token, 1_700_000_500).unwrap();
        assert_eq!(issued, 1_700_000_000);
    }

    #[test]
    fn tampered_signature_rejected() {
        let signer = CookieSigner::new(b"secret".to_vec());
        let mut token = signer.issue(1_700_000_000);
        // Flip the last hex char of the signature.
        let last = token.pop().unwrap();
        let flipped = if last == 'f' { '0' } else { 'f' };
        token.push(flipped);
        assert!(signer.verify(&token, 1_700_000_500).is_none());
    }

    #[test]
    fn wrong_key_rejected() {
        let a = CookieSigner::new(b"secret-a".to_vec());
        let b = CookieSigner::new(b"secret-b".to_vec());
        let token = a.issue(1_700_000_000);
        assert!(b.verify(&token, 1_700_000_500).is_none());
    }

    #[test]
    fn malformed_rejected() {
        let signer = CookieSigner::new(b"secret".to_vec());
        assert!(signer.verify("not-a-token", 1_700_000_000).is_none());
        assert!(signer.verify("nodot", 1_700_000_000).is_none());
        assert!(signer.verify(".", 1_700_000_000).is_none());
        assert!(signer.verify("abcd.ef", 1_700_000_000).is_none()); // wrong length ts
    }

    #[test]
    fn future_timestamp_rejected() {
        let signer = CookieSigner::new(b"secret".to_vec());
        let token = signer.issue(1_700_000_000);
        // Server clock is 2 hours behind cookie's claimed issuance — too far for skew.
        assert!(signer.verify(&token, 1_700_000_000 - 7200).is_none());
    }

    #[test]
    fn small_clock_skew_tolerated() {
        let signer = CookieSigner::new(b"secret".to_vec());
        let token = signer.issue(1_700_000_000);
        // Within the 60s tolerance.
        assert_eq!(
            signer.verify(&token, 1_700_000_000 - 30),
            Some(1_700_000_000)
        );
    }

    #[test]
    fn extract_cookie_finds_trust() {
        let h = "foo=bar; __captcha_trust=abc.def; baz=qux";
        assert_eq!(extract_cookie(h), Some("abc.def"));
    }

    #[test]
    fn extract_cookie_returns_none_when_absent() {
        let h = "foo=bar; baz=qux";
        assert_eq!(extract_cookie(h), None);
    }

    #[test]
    fn set_cookie_format() {
        let s = set_cookie_header("tok", false, CookieSameSite::Lax);
        assert!(s.contains("__captcha_trust=tok"));
        assert!(s.contains("HttpOnly"));
        assert!(s.contains("SameSite=Lax"));
        assert!(!s.contains("Secure"));

        let s2 = set_cookie_header("tok", true, CookieSameSite::Lax);
        assert!(s2.contains("Secure"));
    }

    #[test]
    fn set_cookie_samesite_none() {
        let s = set_cookie_header("tok", true, CookieSameSite::None);
        assert!(s.contains("SameSite=None"));
        assert!(s.contains("Secure"));
    }
}
