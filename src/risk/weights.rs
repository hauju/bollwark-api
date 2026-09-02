//! Signal weights as one process-wide table, overridable from a file.
//!
//! Every scorer's "+N" lives as a `pub const` next to the check it belongs
//! to — those are the defaults and the documentation. This module gathers
//! them into [`SignalWeights`] so a deployment can override any subset with
//! `SIGNAL_WEIGHTS_FILE` (a JSON object of `CONSTANT_NAME: integer`) without
//! a rebuild. It is the return path of the self-improvement loop: the hosted
//! service tunes against its anonymised training samples and ships a file;
//! a self-hoster can subscribe to it or tune locally against their own
//! `training_samples`.
//!
//! Weights are a property of this service, like the rest of the process
//! config, so they are installed once at boot ([`install`]) and read through
//! [`current`]. Every scorer has a `*_with(&SignalWeights, …)` form for
//! tests and offline evaluation; the plain form is `*_with(current(), …)`.
//! Thresholds that are counts rather than scores — the rate bands, the dedup
//! window, the timing slack — stay constants on purpose: they are calibrated
//! against how browsers behave, not against how bots score.

use std::sync::OnceLock;

use super::{behavior, reputation, signals, tls_fingerprint, verify};

macro_rules! weights {
    ($( $field:ident : $default:path = $key:literal ),* $(,)?) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct SignalWeights {
            $( pub $field: u32, )*
        }

        impl Default for SignalWeights {
            fn default() -> Self {
                Self { $( $field: $default, )* }
            }
        }

        impl SignalWeights {
            /// Every key `SIGNAL_WEIGHTS_FILE` accepts, in table order.
            pub const NAMES: &'static [&'static str] = &[ $( $key, )* ];

            fn set_by_name(&mut self, name: &str, value: u32) -> bool {
                match name {
                    $( $key => { self.$field = value; true } )*
                    _ => false,
                }
            }

            /// `(name, default, value)` for every weight that differs from
            /// its default — what the boot log prints.
            pub fn overrides(&self) -> Vec<(&'static str, u32, u32)> {
                let d = Self::default();
                let mut out = Vec::new();
                $( if self.$field != d.$field { out.push(($key, d.$field, self.$field)); } )*
                out
            }
        }
    };
}

weights! {
    rate_ip_very_high: signals::RATE_IP_SCORE_VERY_HIGH = "RATE_IP_SCORE_VERY_HIGH",
    rate_ip_high: signals::RATE_IP_SCORE_HIGH = "RATE_IP_SCORE_HIGH",
    rate_ip_elevated: signals::RATE_IP_SCORE_ELEVATED = "RATE_IP_SCORE_ELEVATED",
    rate_site_very_high: signals::RATE_SITE_SCORE_VERY_HIGH = "RATE_SITE_SCORE_VERY_HIGH",
    rate_site_high: signals::RATE_SITE_SCORE_HIGH = "RATE_SITE_SCORE_HIGH",
    ua_missing: signals::UA_MISSING_SCORE = "UA_MISSING_SCORE",
    ua_suspicious: signals::UA_SUSPICIOUS_SCORE = "UA_SUSPICIOUS_SCORE",
    accept_language_missing: signals::ACCEPT_LANGUAGE_MISSING_SCORE = "ACCEPT_LANGUAGE_MISSING_SCORE",
    accept_encoding_missing: signals::ACCEPT_ENCODING_MISSING_SCORE = "ACCEPT_ENCODING_MISSING_SCORE",
    sec_fetch_missing: signals::SEC_FETCH_MISSING_SCORE = "SEC_FETCH_MISSING_SCORE",
    client_hints_missing: signals::CLIENT_HINTS_MISSING_SCORE = "CLIENT_HINTS_MISSING_SCORE",
    ip_tor: reputation::SCORE_TOR = "SCORE_TOR",
    ip_datacenter: reputation::SCORE_DATACENTER = "SCORE_DATACENTER",
    ip_vpn: reputation::SCORE_VPN = "SCORE_VPN",
    ip_residential: reputation::SCORE_RESIDENTIAL = "SCORE_RESIDENTIAL",
    tls_fingerprint_bad: tls_fingerprint::FINGERPRINT_BAD_SCORE = "FINGERPRINT_BAD_SCORE",
    honeypot_tripped: verify::HONEYPOT_TRIPPED_SCORE = "HONEYPOT_TRIPPED_SCORE",
    time_very_short: verify::TIME_VERY_SHORT_SCORE = "TIME_VERY_SHORT_SCORE",
    time_short: verify::TIME_SHORT_SCORE = "TIME_SHORT_SCORE",
    remote_ip_mismatch: verify::REMOTE_IP_MISMATCH_SCORE = "REMOTE_IP_MISMATCH_SCORE",
    behavior_flatline: behavior::BEHAVIOR_FLATLINE_SCORE = "BEHAVIOR_FLATLINE_SCORE",
    behavior_no_pointer: behavior::BEHAVIOR_NO_POINTER_SCORE = "BEHAVIOR_NO_POINTER_SCORE",
    behavior_instant_interaction: behavior::BEHAVIOR_INSTANT_INTERACTION_SCORE = "BEHAVIOR_INSTANT_INTERACTION_SCORE",
    behavior_automation: behavior::BEHAVIOR_AUTOMATION_SCORE = "BEHAVIOR_AUTOMATION_SCORE",
    behavior_headless: behavior::BEHAVIOR_HEADLESS_SCORE = "BEHAVIOR_HEADLESS_SCORE",
    behavior_impossible_timing: behavior::BEHAVIOR_IMPOSSIBLE_TIMING_SCORE = "BEHAVIOR_IMPOSSIBLE_TIMING_SCORE",
    behavior_duplicate: behavior::BEHAVIOR_DUPLICATE_SCORE = "BEHAVIOR_DUPLICATE_SCORE",
}

impl SignalWeights {
    /// Parse a JSON object of `CONSTANT_NAME: integer`. Unknown names and
    /// non-integer values are errors rather than warnings: a weights file is
    /// a deliberate act, and a typo silently leaving the default in place is
    /// exactly the failure an operator would never notice.
    pub fn parse(json: &str) -> Result<Self, String> {
        let map: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(json).map_err(|e| format!("not a JSON object: {e}"))?;
        let mut weights = Self::default();
        for (name, value) in map {
            let n = value
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| format!("{name}: expected a non-negative integer, got {value}"))?;
            if !weights.set_by_name(&name, n) {
                return Err(format!(
                    "{name}: unknown weight (known: {})",
                    Self::NAMES.join(", ")
                ));
            }
        }
        Ok(weights)
    }

    pub fn from_file(path: &str) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        Self::parse(&text).map_err(|e| format!("{path}: {e}"))
    }
}

static CURRENT: OnceLock<SignalWeights> = OnceLock::new();

/// Install the process-wide weights. Once, at boot, before anything is
/// scored; a second call — or one after a scorer already ran — is refused
/// and hands the rejected table back.
pub fn install(weights: SignalWeights) -> Result<(), SignalWeights> {
    CURRENT.set(weights)
}

/// The weights every scorer reads: the defaults until [`install`] ran.
pub fn current() -> &'static SignalWeights {
    CURRENT.get_or_init(SignalWeights::default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::{
        BehaviorPresence, BehaviorReport, FingerprintBlocklist, IpCategory, TlsFingerprint,
    };
    use axum::http::HeaderMap;

    #[test]
    fn defaults_are_the_constants() {
        let d = SignalWeights::default();
        assert_eq!(d.ua_missing, signals::UA_MISSING_SCORE);
        assert_eq!(d.ip_tor, reputation::SCORE_TOR);
        assert_eq!(d.behavior_duplicate, behavior::BEHAVIOR_DUPLICATE_SCORE);
        assert!(d.overrides().is_empty());
        assert_eq!(SignalWeights::NAMES.len(), 27);
    }

    #[test]
    fn parse_overrides_a_subset_and_keeps_the_rest() {
        let w = SignalWeights::parse(r#"{ "UA_MISSING_SCORE": 5, "SCORE_TOR": 99 }"#).unwrap();
        assert_eq!(w.ua_missing, 5);
        assert_eq!(w.ip_tor, 99);
        assert_eq!(w.ua_suspicious, signals::UA_SUSPICIOUS_SCORE);
        assert_eq!(
            w.overrides(),
            vec![
                ("UA_MISSING_SCORE", signals::UA_MISSING_SCORE, 5),
                ("SCORE_TOR", reputation::SCORE_TOR, 99),
            ]
        );
        assert_eq!(
            SignalWeights::parse("{}").unwrap(),
            SignalWeights::default()
        );
    }

    #[test]
    fn parse_refuses_unknown_names_and_non_integers() {
        let err = SignalWeights::parse(r#"{ "UA_MISING_SCORE": 5 }"#).unwrap_err();
        assert!(err.contains("unknown weight"), "{err}");
        for bad in [
            r#"{ "UA_MISSING_SCORE": -1 }"#,
            r#"{ "UA_MISSING_SCORE": 1.5 }"#,
            r#"{ "UA_MISSING_SCORE": "30" }"#,
            r#"{ "UA_MISSING_SCORE": 4294967296 }"#,
            "[]",
        ] {
            assert!(SignalWeights::parse(bad).is_err(), "{bad}");
        }
    }

    /// The plumbing: every scorer reads the table it is handed.
    #[test]
    fn scorers_read_the_weights_they_are_given() {
        let mut w = SignalWeights::default();
        w.ua_missing = 7;
        w.rate_ip_elevated = 3;
        w.ip_tor = 11;
        w.tls_fingerprint_bad = 13;
        w.time_very_short = 17;
        w.remote_ip_mismatch = 19;
        w.behavior_flatline = 23;

        assert_eq!(
            signals::score_header_anomaly_with(&w, &HeaderMap::new()),
            7 + signals::ACCEPT_LANGUAGE_MISSING_SCORE + signals::ACCEPT_ENCODING_MISSING_SCORE
        );
        assert_eq!(signals::score_rate_with(&w, 15, 0, 0), 3);
        assert_eq!(
            reputation::score_ip_reputation_with(&w, Some(IpCategory::Tor)),
            11
        );
        let list = FingerprintBlocklist::parse("bad\n").unwrap();
        assert_eq!(
            tls_fingerprint::score_tls_fingerprint_with(&w, TlsFingerprint::Provided("bad"), &list),
            13
        );
        assert_eq!(verify::score_time_on_page_with(&w, Some(100)), 17);
        assert_eq!(verify::score_remote_ip_with(&w, true), 19);
        assert_eq!(
            behavior::score_behavior_with(&w, BehaviorPresence::Present(BehaviorReport::default())),
            23
        );
        // And the plain forms are the defaults, since nothing was installed.
        assert_eq!(
            verify::score_remote_ip(true),
            verify::REMOTE_IP_MISMATCH_SCORE
        );
    }
}
