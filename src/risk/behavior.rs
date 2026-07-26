//! Behavioral telemetry signal.
//!
//! The bundled widget instruments the host page for low-cost interaction
//! signals between mount and submit: pointer movement, touches, key/scroll/
//! focus events, and the time-to-first-interaction. The widget POSTs a
//! compact summary alongside the PoW solution; we score it at verify-time.
//!
//! The aim is *not* to fingerprint the user. We only care about presence/
//! absence of *any* organic interaction. A real user fills out a form with
//! at least *some* mouse movement or touches; a naïve headless driver that
//! just fetches a puzzle and submits will report a flatline.
//!
//! A sophisticated bot can fake these counters trivially. The point is to
//! raise the floor — we are not trying to catch determined attackers, we
//! are trying to catch the cheap ones, and to give the weighted ensemble
//! one more signal that's well-correlated with the puzzle-time signals.
//!
//! Older clients that don't include the block at all are treated as
//! `Absent` and contribute zero — we don't want to penalise existing
//! integrations on rollout.

use serde::Deserialize;

/// Wire format for the `behavior` field in `VerifyRequest`. All fields are
/// optional and clamped on the server, so a malicious client that sends
/// `mouse_moves: u32::MAX` cannot poison the score.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
pub struct BehaviorReport {
    #[serde(default)]
    pub mouse_moves: u32,
    #[serde(default)]
    pub touches: u32,
    /// Click + keypress + scroll + focus events. Lumped together because
    /// any one of them is sufficient evidence of organic interaction; the
    /// widget doesn't need to disambiguate.
    #[serde(default)]
    pub interactions: u32,
    /// ms from widget mount to first non-mousemove interaction. `None`
    /// means no such interaction occurred before submit.
    #[serde(default)]
    pub first_interaction_ms: Option<u64>,
    /// `navigator.webdriver` snapshot at widget mount. `Some(true)` is the
    /// W3C-defined CDP-driven-Chrome marker (Playwright, Puppeteer,
    /// Selenium, browser-harness in default mode all set it). Trivial to
    /// patch out, but a useful filter for the long tail of unsophisticated
    /// agents. `None` = older widget that didn't include the field.
    #[serde(default)]
    pub webdriver: Option<bool>,
    /// Automation-driver artifacts found at widget mount: ChromeDriver's
    /// `cdc_`-prefixed globals and legacy Selenium/PhantomJS markers.
    /// Scores as the same dimension as `webdriver` (see `score_behavior`) —
    /// its value is catching drivers that scrub `navigator.webdriver` but
    /// leave the globals behind. `None` = older widget.
    #[serde(default)]
    pub automation: Option<bool>,
    /// Coarse headless-environment hints (`HeadlessChrome` UA, zero outer
    /// window dimensions, empty `navigator.languages`). Noisier than the
    /// automation signals and defeated by modern headless modes, so it's
    /// weighted below the shadow threshold on its own. `None` = older widget.
    #[serde(default)]
    pub headless: Option<bool>,
}

/// Distinguishes "no client behavior block at all" (older widget,
/// non-widget integration) from "block sent but empty" (likely a bot).
#[derive(Debug, Clone, Copy)]
pub enum BehaviorPresence {
    Absent,
    Present(BehaviorReport),
}

// Total flatline (no pointer activity *and* no other interaction) is the
// strongest behavioural signal — at this score it lands a clean request in
// the shadow band on its own.
pub const BEHAVIOR_FLATLINE_SCORE: u32 = 30;
// Click without prior cursor movement: characteristic of a driver that
// dispatches synthetic clicks rather than moving a real cursor.
pub const BEHAVIOR_NO_POINTER_SCORE: u32 = 15;
// Submitting <50ms after the first interaction is implausibly fast — even
// a one-click form takes longer than that for a human.
pub const BEHAVIOR_INSTANT_INTERACTION_MS: u64 = 50;
pub const BEHAVIOR_INSTANT_INTERACTION_SCORE: u32 = 20;
// The browser is driven — `navigator.webdriver === true` and/or driver
// artifacts on `window`/`document`. Calibrated so that *alone* it lands at
// the shadow-fail threshold (success=true, logged); both markers can be
// patched out, so we don't hard-block on them. Combined with any other
// behaviour penalty it crosses the block threshold.
pub const BEHAVIOR_AUTOMATION_SCORE: u32 = 30;
// Headless-environment hints. Deliberately below the shadow threshold on
// its own: the checks are coarser than the automation markers and the
// populations they can misfire on (in-app WebViews, embedded browsers) are
// real traffic. It earns its keep in combination, not alone.
pub const BEHAVIOR_HEADLESS_SCORE: u32 = 20;

pub fn score_behavior(presence: BehaviorPresence) -> u32 {
    let BehaviorPresence::Present(b) = presence else {
        return 0;
    };

    let no_pointer = b.mouse_moves == 0 && b.touches == 0;
    let no_interaction = b.interactions == 0;

    let mut score = 0;
    if no_pointer && no_interaction {
        score += BEHAVIOR_FLATLINE_SCORE;
    } else if no_pointer {
        score += BEHAVIOR_NO_POINTER_SCORE;
    }

    if matches!(b.first_interaction_ms, Some(t) if t < BEHAVIOR_INSTANT_INTERACTION_MS) {
        score += BEHAVIOR_INSTANT_INTERACTION_SCORE;
    }

    // `webdriver` and `automation` are two views of one fact — the browser is
    // driven — so they saturate rather than sum. Summing would push every
    // driven browser to 60 and reverse the deliberate stance that a driven
    // browser showing organic interaction is ShadowFail, not Block (see the
    // e2e browser-harness-simulator regression test). The artifact probe adds
    // *recall*, not weight: it catches drivers that scrub `navigator.webdriver`.
    if matches!(b.webdriver, Some(true)) || matches!(b.automation, Some(true)) {
        score += BEHAVIOR_AUTOMATION_SCORE;
    }

    if matches!(b.headless, Some(true)) {
        score += BEHAVIOR_HEADLESS_SCORE;
    }

    score
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> BehaviorReport {
        BehaviorReport {
            mouse_moves: 12,
            touches: 0,
            interactions: 3,
            first_interaction_ms: Some(800),
            webdriver: Some(false),
            automation: Some(false),
            headless: Some(false),
        }
    }

    #[test]
    fn absent_is_neutral() {
        assert_eq!(score_behavior(BehaviorPresence::Absent), 0);
    }

    #[test]
    fn organic_interaction_passes() {
        assert_eq!(score_behavior(BehaviorPresence::Present(report())), 0);
    }

    #[test]
    fn touch_only_user_passes() {
        let mut r = report();
        r.mouse_moves = 0;
        r.touches = 5;
        assert_eq!(score_behavior(BehaviorPresence::Present(r)), 0);
    }

    #[test]
    fn flatline_scores_high() {
        let r = BehaviorReport::default();
        assert_eq!(
            score_behavior(BehaviorPresence::Present(r)),
            BEHAVIOR_FLATLINE_SCORE
        );
    }

    #[test]
    fn click_without_pointer_scores() {
        let r = BehaviorReport {
            mouse_moves: 0,
            touches: 0,
            interactions: 1,
            first_interaction_ms: Some(1_500),
            ..Default::default()
        };
        assert_eq!(
            score_behavior(BehaviorPresence::Present(r)),
            BEHAVIOR_NO_POINTER_SCORE
        );
    }

    #[test]
    fn instant_interaction_compounds() {
        let r = BehaviorReport {
            mouse_moves: 0,
            touches: 0,
            interactions: 1,
            first_interaction_ms: Some(10),
            ..Default::default()
        };
        // no_pointer (15) + instant (20)
        assert_eq!(
            score_behavior(BehaviorPresence::Present(r)),
            BEHAVIOR_NO_POINTER_SCORE + BEHAVIOR_INSTANT_INTERACTION_SCORE
        );
    }

    #[test]
    fn instant_threshold_is_inclusive_low() {
        let r = BehaviorReport {
            mouse_moves: 5,
            touches: 0,
            interactions: 1,
            first_interaction_ms: Some(BEHAVIOR_INSTANT_INTERACTION_MS),
            ..Default::default()
        };
        // Exactly at threshold: not penalised
        assert_eq!(score_behavior(BehaviorPresence::Present(r)), 0);
    }

    #[test]
    fn no_first_interaction_doesnt_trigger_instant() {
        let r = BehaviorReport {
            mouse_moves: 5,
            touches: 0,
            interactions: 0,
            first_interaction_ms: None,
            ..Default::default()
        };
        assert_eq!(score_behavior(BehaviorPresence::Present(r)), 0);
    }

    #[test]
    fn webdriver_flag_alone_lands_in_shadow_band() {
        let r = BehaviorReport {
            mouse_moves: 30,
            interactions: 5,
            first_interaction_ms: Some(1_500),
            webdriver: Some(true),
            ..Default::default()
        };
        // Otherwise organic, but webdriver=true → 30 → shadow_min boundary.
        assert_eq!(
            score_behavior(BehaviorPresence::Present(r)),
            BEHAVIOR_AUTOMATION_SCORE
        );
    }

    #[test]
    fn webdriver_plus_flatline_scores_block_band() {
        let r = BehaviorReport {
            webdriver: Some(true),
            ..Default::default()
        };
        // Flatline (30) + webdriver (30) = 60 → block_min boundary.
        assert_eq!(
            score_behavior(BehaviorPresence::Present(r)),
            BEHAVIOR_FLATLINE_SCORE + BEHAVIOR_AUTOMATION_SCORE
        );
    }

    #[test]
    fn automation_artifacts_score_like_webdriver() {
        // A driver that scrubbed navigator.webdriver but left cdc_ globals
        // behind — the case the artifact probe exists to catch.
        let r = BehaviorReport {
            mouse_moves: 30,
            interactions: 5,
            first_interaction_ms: Some(1_500),
            webdriver: Some(false),
            automation: Some(true),
            ..Default::default()
        };
        assert_eq!(
            score_behavior(BehaviorPresence::Present(r)),
            BEHAVIOR_AUTOMATION_SCORE
        );
    }

    #[test]
    fn webdriver_and_automation_saturate() {
        // Both markers describe one fact (driven browser), so they must not
        // sum — otherwise every driven browser lands at block_min and the
        // "organic interaction ⇒ ShadowFail" stance is silently reversed.
        let r = BehaviorReport {
            mouse_moves: 30,
            interactions: 5,
            first_interaction_ms: Some(1_500),
            webdriver: Some(true),
            automation: Some(true),
            ..Default::default()
        };
        assert_eq!(
            score_behavior(BehaviorPresence::Present(r)),
            BEHAVIOR_AUTOMATION_SCORE
        );
    }

    #[test]
    fn headless_alone_stays_below_shadow_band() {
        // 20 < the default VERIFY_SHADOW_MIN of 30 — a false positive on an
        // otherwise-organic visitor must not change their outcome.
        let mut r = report();
        r.headless = Some(true);
        assert_eq!(
            score_behavior(BehaviorPresence::Present(r)),
            BEHAVIOR_HEADLESS_SCORE
        );
    }

    #[test]
    fn headless_compounds_with_automation() {
        let r = BehaviorReport {
            mouse_moves: 30,
            interactions: 5,
            first_interaction_ms: Some(1_500),
            webdriver: Some(true),
            headless: Some(true),
            ..Default::default()
        };
        assert_eq!(
            score_behavior(BehaviorPresence::Present(r)),
            BEHAVIOR_AUTOMATION_SCORE + BEHAVIOR_HEADLESS_SCORE
        );
    }

    #[test]
    fn new_probes_absent_scores_like_legacy_widget() {
        // Older widgets omit both fields entirely — they must stay neutral so
        // existing integrations don't shift on rollout.
        let r = BehaviorReport {
            mouse_moves: 30,
            touches: 0,
            interactions: 5,
            first_interaction_ms: Some(1_500),
            webdriver: Some(false),
            automation: None,
            headless: None,
        };
        assert_eq!(score_behavior(BehaviorPresence::Present(r)), 0);
    }

    #[test]
    fn webdriver_false_does_not_score() {
        let r = BehaviorReport {
            mouse_moves: 30,
            interactions: 5,
            first_interaction_ms: Some(1_500),
            webdriver: Some(false),
            ..Default::default()
        };
        assert_eq!(score_behavior(BehaviorPresence::Present(r)), 0);
    }

    #[test]
    fn webdriver_missing_does_not_score() {
        let r = BehaviorReport {
            mouse_moves: 30,
            interactions: 5,
            first_interaction_ms: Some(1_500),
            webdriver: None,
            ..Default::default()
        };
        assert_eq!(score_behavior(BehaviorPresence::Present(r)), 0);
    }
}
