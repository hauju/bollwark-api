use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::{AppConfig, MIN_DIFFICULTY};
use crate::risk::{TierThresholds, VerifyThresholds};

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
    /// Per-site scoring overrides. Every field inside is optional and falls
    /// back to the process-wide env config, so `SitePolicy::default()` (the
    /// value every pre-existing site loads with) reproduces exactly the
    /// behaviour this service had before policies existed.
    #[serde(default)]
    pub policy: SitePolicy,
}

/// Per-site overrides for the knobs that are otherwise process-global env
/// vars. Exists because the thresholds that are right for a low-traffic
/// contact form are wrong for a login endpoint under credential-stuffing, and
/// one instance serves both — an operator running several tenants (or one
/// tenant with several very different forms) previously had to pick a single
/// setting for all of them, or run a second instance.
///
/// Every field is `Option`, and `None` means *inherit the env default* rather
/// than *use the type's zero*. That distinction is the whole point: a site
/// that overrides only `tier_block_min` keeps tracking the global values for
/// everything else, including later changes to them. [`SitePolicy::resolve`]
/// is the single place the overlay happens.
///
/// Field names deliberately mirror the env vars they shadow
/// (`TIER_BLOCK_MIN` → `tier_block_min`) so `CONFIGURATION.md` documents both.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SitePolicy {
    /// Overrides `TIER_CHECKBOX_MIN`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier_checkbox_min: Option<u32>,
    /// Overrides `TIER_HARD_POW_MIN`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier_hard_pow_min: Option<u32>,
    /// Overrides `TIER_BLOCK_MIN`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier_block_min: Option<u32>,
    /// Overrides `VERIFY_SHADOW_MIN`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_shadow_min: Option<u32>,
    /// Overrides `VERIFY_BLOCK_MIN`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_block_min: Option<u32>,
    /// Overrides `DEFAULT_DIFFICULTY`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_difficulty: Option<u32>,
    /// Overrides `MAX_DIFFICULTY` — the per-site clamp on every issued
    /// difficulty, so raising it is what lets a site escalate past the global
    /// ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_difficulty: Option<u32>,
    /// Whether risk verdicts are acted on. Omitted = [`SiteMode::Enforce`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<SiteMode>,
}

/// Whether this site's risk verdicts are enforced or merely observed.
///
/// `Monitor` exists for onboarding: pointing a real form at a new CAPTCHA is
/// a leap of faith, and the only honest way to make it isn't one is to run
/// the full pipeline against live traffic for a week and read what it *would*
/// have done. Scores, tiers and decisions are computed and logged exactly as
/// in `Enforce`, so the numbers seen while monitoring are the numbers that
/// enforcement will produce — flipping the switch changes no arithmetic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiteMode {
    /// Risk verdicts are acted on: Block-tier gets 429, a verify-time Block
    /// returns `success: false`. The default.
    #[default]
    Enforce,
    /// Risk verdicts are recorded but never refuse a visitor. A Block-tier
    /// request is issued a max-difficulty puzzle instead of a 429, and a
    /// verify-time Block returns `success: true`.
    ///
    /// Scoped deliberately to *risk* verdicts. It does not disable the load
    /// sheds (`MAX_ACTIVE_CHALLENGES`, the flooder shed), which protect the
    /// whole instance rather than judge this visitor — one monitored tenant
    /// must not be able to exhaust the challenge map for every other site.
    /// It also doesn't excuse an invalid proof of work or an unattested
    /// failover claim: neither is a judgement about the visitor's risk, so
    /// there is nothing there to observe rather than enforce.
    Monitor,
}

impl SiteMode {
    pub fn is_monitor(self) -> bool {
        matches!(self, Self::Monitor)
    }
}

/// A [`SitePolicy`] overlaid on the process config — every knob resolved to a
/// concrete value. Handlers work with this, never with the raw `Option`s, so
/// there is exactly one place the inheritance rule lives.
#[derive(Debug, Clone, Copy)]
pub struct EffectivePolicy {
    pub tiers: TierThresholds,
    pub verify: VerifyThresholds,
    pub default_difficulty: u32,
    pub max_difficulty: u32,
    pub mode: SiteMode,
}

impl SitePolicy {
    /// True when no field is overridden. Used by the storage layer to write
    /// SQL NULL instead of `{}`, so an untouched site stays visibly untouched
    /// in the database.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Overlay this policy on the process config.
    pub fn resolve(&self, config: &AppConfig) -> EffectivePolicy {
        EffectivePolicy {
            tiers: TierThresholds {
                checkbox: self.tier_checkbox_min.unwrap_or(config.tier_checkbox_min),
                hard_pow: self.tier_hard_pow_min.unwrap_or(config.tier_hard_pow_min),
                block: self.tier_block_min.unwrap_or(config.tier_block_min),
            },
            verify: VerifyThresholds {
                shadow_min: self.verify_shadow_min.unwrap_or(config.verify_shadow_min),
                block_min: self.verify_block_min.unwrap_or(config.verify_block_min),
            },
            default_difficulty: self.default_difficulty.unwrap_or(config.default_difficulty),
            max_difficulty: self.max_difficulty.unwrap_or(config.max_difficulty),
            // No env equivalent: enforcing is the only sane process-wide
            // default, and monitoring is a per-site onboarding state.
            mode: self.mode.unwrap_or_default(),
        }
    }

    /// Validate the policy *as it would actually take effect*, i.e. after the
    /// overlay. Checking the resolved values rather than the supplied subset is
    /// what catches a partial override that only breaks in combination with the
    /// globals — setting `tier_block_min: 10` alone is fine in isolation but
    /// puts Block below the global `TIER_CHECKBOX_MIN=20`, making two tiers
    /// unreachable.
    ///
    /// Returns a message ready to drop into a 400 body. Each rejected case
    /// silently disables protection for the site rather than erroring at
    /// request time, which is exactly the class of mistake `AppConfig::validated`
    /// panics on for the global equivalents — a write-time 400 is the same
    /// stance for something we can't panic on.
    pub fn validate(&self, config: &AppConfig) -> Result<(), String> {
        let e = self.resolve(config);

        if e.default_difficulty < MIN_DIFFICULTY || e.max_difficulty < MIN_DIFFICULTY {
            return Err(format!(
                "default_difficulty={} / max_difficulty={} — both must be at least \
                 {MIN_DIFFICULTY} once merged with the server defaults. A difficulty of 0 \
                 accepts any nonce without computing a hash, so every visitor to this site \
                 passes the proof-of-work.",
                e.default_difficulty, e.max_difficulty
            ));
        }
        if e.default_difficulty > e.max_difficulty {
            return Err(format!(
                "default_difficulty={} exceeds max_difficulty={} once merged with the server \
                 defaults. max_difficulty clamps every issued puzzle, so the base difficulty \
                 would silently be the lower value and no tier could escalate.",
                e.default_difficulty, e.max_difficulty
            ));
        }
        // `TierThresholds::classify` tests block → hard_pow → checkbox in that
        // order, so an out-of-order set doesn't error — it makes the middle
        // bands unreachable and quietly changes what every score maps to.
        if !(e.tiers.checkbox <= e.tiers.hard_pow && e.tiers.hard_pow <= e.tiers.block) {
            return Err(format!(
                "tier thresholds must be non-decreasing once merged with the server defaults, \
                 got checkbox={} hard_pow={} block={}. Out of order, the higher tier wins every \
                 comparison and the bands in between are never reachable.",
                e.tiers.checkbox, e.tiers.hard_pow, e.tiers.block
            ));
        }
        if e.verify.shadow_min > e.verify.block_min {
            return Err(format!(
                "verify_shadow_min={} must not exceed verify_block_min={} once merged with the \
                 server defaults — the shadow band would be empty and every flagged submission \
                 would hard-block instead of being logged for review.",
                e.verify.shadow_min, e.verify.block_min
            ));
        }
        // A zero block threshold matches *every* score, humans included: the
        // puzzle side 429s the whole site, the verify side fails every
        // submission. Both look like an outage, not a policy.
        if e.tiers.block == 0 {
            return Err(
                "tier_block_min must be at least 1 — 0 blocks every visitor to this \
                        site, including humans, before a puzzle is ever issued."
                    .to_string(),
            );
        }
        if e.verify.block_min == 0 {
            return Err(
                "verify_block_min must be at least 1 — 0 fails every submission for \
                        this site, including correctly solved ones."
                    .to_string(),
            );
        }
        Ok(())
    }
}

/// Cap on allowed-origins entries per site. Generous for real tenants while
/// bounding both the space-joined storage column and the per-request match
/// loop in the puzzle handler.
pub const MAX_ALLOWED_ORIGINS: usize = 32;

/// Cap on a site's display name.
pub const MAX_SITE_NAME_LEN: usize = 200;

/// Trim and validate a site name, returning the value to store.
///
/// Shared by `POST /v1/sites` and `PUT /v1/admin/sites/:id/name` for the same
/// reason `normalize_origins` is: two copies of the rule are two things that
/// drift, and a rename accepting what provisioning rejects would put a name in
/// the store that could never have been created there.
pub fn normalize_site_name(raw: &str) -> Result<String, String> {
    let name = raw.trim();
    if name.is_empty() {
        return Err("name is required".into());
    }
    if name.len() > MAX_SITE_NAME_LEN {
        return Err(format!(
            "name must be {MAX_SITE_NAME_LEN} characters or fewer"
        ));
    }
    Ok(name.to_string())
}

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
    fn a_site_name_is_trimmed_before_it_is_judged() {
        assert_eq!(normalize_site_name("  checkout  ").unwrap(), "checkout");
        // Whitespace-only is empty, not a 3-character name.
        assert_eq!(
            normalize_site_name("   "),
            Err("name is required".to_string())
        );
    }

    #[test]
    fn a_site_name_is_length_capped() {
        assert!(normalize_site_name(&"a".repeat(MAX_SITE_NAME_LEN)).is_ok());
        assert!(normalize_site_name(&"a".repeat(MAX_SITE_NAME_LEN + 1)).is_err());
        // The trim happens first, so padding a legal name over the cap is
        // still legal — otherwise a paste with a trailing newline would fail.
        assert!(normalize_site_name(&format!("  {}  ", "a".repeat(MAX_SITE_NAME_LEN))).is_ok());
    }

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

    // --- SitePolicy ---

    /// Config with the documented defaults, so each policy test states only
    /// the override it cares about.
    fn cfg() -> AppConfig {
        AppConfig::default()
    }

    #[test]
    fn empty_policy_resolves_to_the_global_config() {
        let c = cfg();
        let e = SitePolicy::default().resolve(&c);
        assert_eq!(e.tiers.checkbox, c.tier_checkbox_min);
        assert_eq!(e.tiers.hard_pow, c.tier_hard_pow_min);
        assert_eq!(e.tiers.block, c.tier_block_min);
        assert_eq!(e.verify.shadow_min, c.verify_shadow_min);
        assert_eq!(e.verify.block_min, c.verify_block_min);
        assert_eq!(e.default_difficulty, c.default_difficulty);
        assert_eq!(e.max_difficulty, c.max_difficulty);
    }

    #[test]
    fn partial_override_keeps_inheriting_the_rest() {
        let c = cfg();
        let p = SitePolicy {
            tier_block_min: Some(70),
            ..Default::default()
        };
        let e = p.resolve(&c);
        assert_eq!(e.tiers.block, 70);
        // Untouched fields still track the global values.
        assert_eq!(e.tiers.checkbox, c.tier_checkbox_min);
        assert_eq!(e.default_difficulty, c.default_difficulty);
    }

    #[test]
    fn default_policy_is_empty_and_serializes_to_an_empty_object() {
        assert!(SitePolicy::default().is_empty());
        assert_eq!(serde_json::to_string(&SitePolicy::default()).unwrap(), "{}");
        assert!(
            !SitePolicy {
                tier_block_min: Some(70),
                ..Default::default()
            }
            .is_empty()
        );
    }

    #[test]
    fn policy_round_trips_through_json() {
        let p = SitePolicy {
            tier_checkbox_min: Some(10),
            verify_block_min: Some(30),
            ..Default::default()
        };
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(serde_json::from_str::<SitePolicy>(&json).unwrap(), p);
    }

    #[test]
    fn empty_policy_validates() {
        assert!(SitePolicy::default().validate(&cfg()).is_ok());
    }

    #[test]
    fn rejects_zero_difficulty() {
        // 0 leading zero bits means every nonce verifies — the PoW is off.
        let err = SitePolicy {
            default_difficulty: Some(0),
            ..Default::default()
        }
        .validate(&cfg())
        .unwrap_err();
        assert!(err.contains("at least 1"), "{err}");

        assert!(
            SitePolicy {
                max_difficulty: Some(0),
                ..Default::default()
            }
            .validate(&cfg())
            .is_err()
        );
    }

    #[test]
    fn rejects_default_difficulty_above_max() {
        let err = SitePolicy {
            default_difficulty: Some(20),
            max_difficulty: Some(10),
            ..Default::default()
        }
        .validate(&cfg())
        .unwrap_err();
        assert!(err.contains("exceeds max_difficulty"), "{err}");
    }

    #[test]
    fn rejects_out_of_order_tier_thresholds() {
        let err = SitePolicy {
            tier_checkbox_min: Some(50),
            tier_hard_pow_min: Some(40),
            ..Default::default()
        }
        .validate(&cfg())
        .unwrap_err();
        assert!(err.contains("non-decreasing"), "{err}");
    }

    #[test]
    fn rejects_partial_override_that_only_breaks_against_the_globals() {
        // block_min alone looks fine; merged with the global checkbox=20 /
        // hard_pow=40 it puts Block underneath both. This is the case that
        // validating the *supplied* fields instead of the resolved ones
        // would let through.
        let c = cfg();
        assert!(c.tier_checkbox_min > 10);
        let err = SitePolicy {
            tier_block_min: Some(10),
            ..Default::default()
        }
        .validate(&c)
        .unwrap_err();
        assert!(err.contains("non-decreasing"), "{err}");
    }

    #[test]
    fn rejects_shadow_above_block_on_the_verify_side() {
        let err = SitePolicy {
            verify_shadow_min: Some(90),
            verify_block_min: Some(60),
            ..Default::default()
        }
        .validate(&cfg())
        .unwrap_err();
        assert!(err.contains("verify_shadow_min"), "{err}");
    }

    #[test]
    fn rejects_zero_block_thresholds() {
        // Both of these match every score, so the site is fully down rather
        // than strictly policed.
        let err = SitePolicy {
            tier_checkbox_min: Some(0),
            tier_hard_pow_min: Some(0),
            tier_block_min: Some(0),
            ..Default::default()
        }
        .validate(&cfg())
        .unwrap_err();
        assert!(err.contains("tier_block_min"), "{err}");

        let err = SitePolicy {
            verify_shadow_min: Some(0),
            verify_block_min: Some(0),
            ..Default::default()
        }
        .validate(&cfg())
        .unwrap_err();
        assert!(err.contains("verify_block_min"), "{err}");
    }

    #[test]
    fn mode_defaults_to_enforce_and_round_trips() {
        assert_eq!(
            SitePolicy::default().resolve(&cfg()).mode,
            SiteMode::Enforce
        );
        assert!(!SitePolicy::default().resolve(&cfg()).mode.is_monitor());

        let p = SitePolicy {
            mode: Some(SiteMode::Monitor),
            ..Default::default()
        };
        assert!(p.resolve(&cfg()).mode.is_monitor());
        // Wire form is the snake_case name, so the admin API reads as
        // {"mode":"monitor"} rather than a bare boolean.
        assert_eq!(serde_json::to_string(&p).unwrap(), r#"{"mode":"monitor"}"#);
        assert_eq!(
            serde_json::from_str::<SitePolicy>(r#"{"mode":"monitor"}"#).unwrap(),
            p
        );
    }

    #[test]
    fn monitor_mode_is_not_an_override_and_needs_no_validation() {
        // Monitoring changes what happens to a verdict, never how one is
        // computed, so it can't produce an invalid threshold set.
        let p = SitePolicy {
            mode: Some(SiteMode::Monitor),
            ..Default::default()
        };
        assert!(p.validate(&cfg()).is_ok());
        // ...and it leaves every threshold inheriting.
        let e = p.resolve(&cfg());
        assert_eq!(e.tiers.block, cfg().tier_block_min);
        assert_eq!(e.verify.block_min, cfg().verify_block_min);
    }

    #[test]
    fn accepts_a_realistic_stricter_login_policy() {
        // The motivating case: a login form that should escalate sooner and
        // hard-block on any behavioural flag.
        let p = SitePolicy {
            tier_checkbox_min: Some(10),
            tier_hard_pow_min: Some(25),
            tier_block_min: Some(60),
            verify_shadow_min: Some(20),
            verify_block_min: Some(30),
            ..Default::default()
        };
        assert!(p.validate(&cfg()).is_ok());
        assert_eq!(p.resolve(&cfg()).tiers.hard_pow, 25);
    }
}
