use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Site {
    pub site_key: Uuid,
    pub secret_key: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    /// Optional browser-origin allowlist. Empty = allow any origin (the
    /// default; every existing site keeps behaving as before). When non-empty,
    /// `GET /v1/puzzle` refuses browser embeds whose `Origin` header isn't in
    /// the list. This is tenant hygiene — it stops a third party from embedding
    /// a customer's public `site_key` and burning their quota or polluting
    /// their stats — NOT bot defense: a non-browser client can forge the
    /// `Origin` header, so the real security boundary stays the site secret at
    /// `/v1/verify`.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

/// Cap on allowed-origins entries per site. Generous for real tenants while
/// bounding both the space-joined storage column and the per-request match
/// loop in the puzzle handler.
pub const MAX_ALLOWED_ORIGINS: usize = 32;

/// Normalize and validate a single allowed-origin entry. An origin is a full
/// `http(s)://host[:port]` token — lowercased, with no path, query, fragment,
/// trailing slash, or whitespace. Returns the normalized origin, or the
/// offending input (for a 400 message) on failure.
///
/// Matching against a request's `Origin` header is exact string equality after
/// lowercasing the header value, so we lowercase here at store time.
pub fn normalize_origin(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    // Reject empty and any internal whitespace — an origin is a single token.
    if trimmed.is_empty() || trimmed.chars().any(char::is_whitespace) {
        return Err(raw.to_string());
    }
    let lower = trimmed.to_ascii_lowercase();
    // Require an explicit scheme; `rest` is the authority (host[:port]).
    let rest = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .ok_or_else(|| raw.to_string())?;
    // The authority must be non-empty and carry no path/query/fragment —
    // anything past host[:port] isn't part of an origin.
    if rest.is_empty() || rest.contains('/') || rest.contains('?') || rest.contains('#') {
        return Err(raw.to_string());
    }
    Ok(lower)
}

/// Validate and normalize a whole allowed-origins list submitted at
/// provisioning time. Returns the normalized list, or a human-readable message
/// naming the problem (ready to drop into a 400 body). Enforces
/// `MAX_ALLOWED_ORIGINS`.
pub fn normalize_origins(raw: &[String]) -> Result<Vec<String>, String> {
    if raw.len() > MAX_ALLOWED_ORIGINS {
        return Err(format!(
            "too many allowed_origins (max {MAX_ALLOWED_ORIGINS})"
        ));
    }
    raw.iter()
        .map(|o| normalize_origin(o).map_err(|bad| format!("invalid origin: {bad}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_accepts_https_http_and_port() {
        assert_eq!(
            normalize_origin("https://example.com").unwrap(),
            "https://example.com"
        );
        assert_eq!(
            normalize_origin("http://example.com").unwrap(),
            "http://example.com"
        );
        assert_eq!(
            normalize_origin("https://example.com:8443").unwrap(),
            "https://example.com:8443"
        );
    }

    #[test]
    fn normalize_lowercases_and_trims() {
        assert_eq!(
            normalize_origin("  HTTPS://Example.COM  ").unwrap(),
            "https://example.com"
        );
    }

    #[test]
    fn normalize_rejects_path_trailing_slash_query_fragment() {
        assert!(normalize_origin("https://example.com/path").is_err());
        assert!(normalize_origin("https://example.com/").is_err());
        assert!(normalize_origin("https://example.com?a=1").is_err());
        assert!(normalize_origin("https://example.com#frag").is_err());
    }

    #[test]
    fn normalize_rejects_bare_hostname_empty_and_whitespace() {
        assert!(normalize_origin("example.com").is_err());
        assert!(normalize_origin("").is_err());
        assert!(normalize_origin("   ").is_err());
        assert!(normalize_origin("https://exa mple.com").is_err());
        // Scheme with empty authority.
        assert!(normalize_origin("https://").is_err());
    }

    #[test]
    fn normalize_origin_error_carries_offending_value() {
        assert_eq!(normalize_origin("example.com").unwrap_err(), "example.com");
    }

    #[test]
    fn normalize_origins_list_and_cap() {
        let ok = vec![
            "https://a.example".to_string(),
            "HTTP://B.example".to_string(),
        ];
        assert_eq!(
            normalize_origins(&ok).unwrap(),
            vec!["https://a.example", "http://b.example"]
        );

        let bad = vec!["https://ok.example".to_string(), "nope".to_string()];
        assert_eq!(normalize_origins(&bad).unwrap_err(), "invalid origin: nope");

        let too_many: Vec<String> = (0..MAX_ALLOWED_ORIGINS + 1)
            .map(|i| format!("https://s{i}.example"))
            .collect();
        assert!(
            normalize_origins(&too_many)
                .unwrap_err()
                .contains("too many")
        );
    }
}
