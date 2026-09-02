//! Behavioral telemetry signal.
//!
//! The bundled widget instruments the host page for low-cost interaction
//! signals between mount and submit: pointer movement, touches, key/scroll/
//! focus events, and the time-to-first-interaction. The widget POSTs a
//! compact summary alongside the PoW solution; we score it at verify-time.
//!
//! The aim is *not* to fingerprint the user. We only care about presence/
//! absence of *any* organic interaction. A naïve headless driver that just
//! fetches a puzzle and submits will report a flatline.
//!
//! Note what is deliberately *not* inferred: that a real user must have moved
//! a mouse, or must have paused before touching the page. Keyboard and
//! screen-reader visitors are pointer-free by definition, and anyone already
//! typing or scrolling when a late-loading widget mounts registers an instant
//! first interaction. Both signals are therefore scored only alongside an
//! *isolated* interaction count (`BEHAVIOR_ISOLATED_INTERACTION_MAX`) — the
//! lone synthetic event they were written to catch. Scoring them
//! unconditionally penalised people for how they navigate, which is both wrong
//! and, for a deliberately keyboard-operable widget, self-defeating.
//!
//! A sophisticated bot can fake these counters trivially. The point is to
//! raise the floor — we are not trying to catch determined attackers, we
//! are trying to catch the cheap ones, and to give the weighted ensemble
//! one more signal that's well-correlated with the puzzle-time signals.
//!
//! Two of the checks here are about the blob rather than about the visitor:
//! a timeline the server can prove impossible, and a blob one site has seen
//! byte-identically several times inside a window. Both need context the blob
//! doesn't carry (the server-derived dwell, a per-site occurrence count), so
//! they take it as an argument and stay pure — see `score_impossible_timing`
//! and `score_duplicate_blob`.
//!
//! Older clients that don't include the block at all are treated as
//! `Absent` and contribute zero — we don't want to penalise existing
//! integrations on rollout.

use super::weights::{SignalWeights, current};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

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
// An *isolated* synthetic click: one interaction, no cursor movement before
// it. Characteristic of a driver that dispatches `el.click()` rather than
// moving a real cursor. (Mainline Playwright/Puppeteer don't land here — CDP
// synthesises a `mouseMoved` first — so this targets the cheaper
// `dispatchEvent` / injected-script tail.)
pub const BEHAVIOR_NO_POINTER_SCORE: u32 = 15;
// Interaction count above which an isolated-burst signal stops being evidence
// of a driver. Gates both `BEHAVIOR_NO_POINTER_SCORE` and
// `BEHAVIOR_INSTANT_INTERACTION_SCORE`, because both express the same shape:
// a lone synthetic event at mount, versus a trail of organic activity.
//
// A visitor navigating by keyboard or screen reader is pointer-free by
// definition, and one who was already typing or scrolling when a late-loading
// widget mounted has a sub-50ms first interaction. Both used to score — a
// penalty for how someone navigates rather than for anything they did. Neither
// can reach submit in one event: every Tab, keystroke and scroll is counted in
// `interactions`, so the minimum real path (Tab, activate, Tab, submit) is
// already four, and filling any field is dozens. The bot these signals were
// written for is, by construction, exactly one.
//
// A bot can of course report two interactions instead of one and shed both
// penalties. That costs it nothing today either — `mouse_moves: 1` and
// `first_interaction_ms: 800` already do it — which is the module-level stance
// above: raise the floor against the cheap tail, don't pretend the counters
// are unforgeable.
pub const BEHAVIOR_ISOLATED_INTERACTION_MAX: u32 = 1;
// First interaction landing <50ms after the widget mounted is implausibly
// fast for a *deliberate* one — a human has not read the form yet. Note this
// measures mount → first interaction (see `first_interaction_ms`), not
// first-interaction → submit.
//
// Only scored for an isolated interaction (see above). Note the population
// this misfired on was never only keyboard users: `mousemove` doesn't set
// `first_interaction_ms` but `scroll` does, so anyone mid-scroll when the
// widget mounted was penalised too.
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

// ── Blob plausibility: checks the blob's own fields can't answer ────────────

// How far `first_interaction_ms` may legitimately exceed the server's dwell.
//
// The widget sets its page-load anchor at construction, *before* the
// `GET /v1/puzzle` that mints the challenge, and measures
// `first_interaction_ms` from it. The server's dwell clock
// (`challenge.dwell_since`, inherited across pre-expiry refreshes) starts
// later, by however long that first fetch took. That offset is the whole of
// the legitimate excess: an interaction at wall time `t` claims
// `t - page_load`, while the server credits at most `t_submit - dwell_since`,
// so
//
//     first_interaction_ms - time_on_page_ms  <=  dwell_since - page_load
//
// with equality only if the visitor submitted at the very instant they first
// interacted. Beyond that offset the blob describes an interaction that
// happened after the visitor was already submitting, which cannot occur —
// hence "impossible", not "unlikely".
//
// 30s is far past any real offset (the widget's own retry backoff totals
// 1.2s; a cold DNS+TLS handshake on a bad mobile link is a few seconds more).
// The headroom buys a second property worth more than tight calibration: a
// visitor whose first interaction was within 30s of the widget mounting can
// never trip this, *whatever* happens to the dwell anchor. That matters
// because the anchor can legitimately jump forward — a pre-expiry refresh
// deferred while the tab was hidden past the TTL cites a challenge the server
// has already swept, and an unmatched citation re-anchors dwell to now. The
// slack is what keeps that visitor out of this check.
pub const BEHAVIOR_IMPOSSIBLE_TIMING_SLACK_MS: u64 = 30_000;
// Same calibration as the automation markers: shadow band alone under the
// default 30/60, never a block on its own. The check is a certainty about the
// blob, not about the visitor, and a client-asserted field is not something to
// hard-fail a first-time rollout on.
pub const BEHAVIOR_IMPOSSIBLE_TIMING_SCORE: u32 = 30;

// How many byte-identical activity-claiming blobs one site may receive inside
// `BEHAVIOR_DUPLICATE_WINDOW_SECS` before the next one scores.
//
// Humans do not produce identical counters. `first_interaction_ms` alone is a
// millisecond reading, so two real visitors collide only when it is `None` —
// no click, keypress, scroll, focus or touch before submit — which leaves
// `mouse_moves` as the single varying field. A total flatline is that case
// with `mouse_moves: 0`, and it is both expected in bulk and already worth
// +30, so it is excluded from dedup entirely (see `claims_activity`); what
// remains is the visitor who moved a pointer and did nothing else. Two of
// those can plausibly land on the same small count on a busy site, so the
// threshold sits well clear of it at 5 while still tripping a script at its
// fifth submission.
pub const BEHAVIOR_DUPLICATE_MIN: u32 = 5;
// 10 minutes. Long enough that a script pacing itself under the 60s rate
// window still accumulates (one submission a minute reaches 5 well inside it),
// short enough that the in-memory map reclaims promptly.
pub const BEHAVIOR_DUPLICATE_WINDOW_SECS: i64 = 600;
pub const BEHAVIOR_DUPLICATE_SCORE: u32 = 30;

/// Whether a blob claims any activity at all. Only these are deduplicated: a
/// flatline is the one blob real clients repeat verbatim (every visitor who
/// submits without touching the page produces it), and it already scores
/// `BEHAVIOR_FLATLINE_SCORE` on its own.
pub fn claims_activity(b: &BehaviorReport) -> bool {
    b.mouse_moves > 0 || b.touches > 0 || b.interactions > 0
}

/// Deterministic fingerprint of a blob's *fields*, used as the dedup key.
///
/// Hashes the parsed struct rather than the raw JSON: field order, whitespace
/// and omitted-versus-explicit defaults are all free for a script to vary, so
/// hashing bytes would make dedup trivially evadable. The value lives in
/// memory for one window and is never logged or persisted — a hash of event
/// counters identifies no person.
pub fn behavior_fingerprint(b: &BehaviorReport) -> u64 {
    let mut hasher = DefaultHasher::new();
    b.mouse_moves.hash(&mut hasher);
    b.touches.hash(&mut hasher);
    b.interactions.hash(&mut hasher);
    b.first_interaction_ms.hash(&mut hasher);
    b.webdriver.hash(&mut hasher);
    b.automation.hash(&mut hasher);
    b.headless.hash(&mut hasher);
    hasher.finish()
}

/// The blob claims an interaction that happened after the visitor existed.
///
/// `time_on_page_ms` is the server-derived dwell, passed in so this stays a
/// pure function; `None` (the failover path, which has no challenge) means
/// there is nothing to compare against and scores 0.
pub fn score_impossible_timing(presence: BehaviorPresence, time_on_page_ms: Option<u64>) -> u32 {
    score_impossible_timing_with(current(), presence, time_on_page_ms)
}

/// [`score_impossible_timing`] against explicit weights; the plain form reads the
/// process-wide table from [`super::weights::current`].
pub fn score_impossible_timing_with(
    w: &SignalWeights,
    presence: BehaviorPresence,
    time_on_page_ms: Option<u64>,
) -> u32 {
    let (BehaviorPresence::Present(b), Some(dwell)) = (presence, time_on_page_ms) else {
        return 0;
    };
    // No first interaction reported — nothing to contradict. Pointer-only
    // visitors live here: `mousemove` never sets the field.
    let Some(first) = b.first_interaction_ms else {
        return 0;
    };
    if first > dwell.saturating_add(BEHAVIOR_IMPOSSIBLE_TIMING_SLACK_MS) {
        w.behavior_impossible_timing
    } else {
        0
    }
}

/// This exact blob has been submitted for this site `duplicate_count` times
/// inside the dedup window (the count includes the submission being scored).
///
/// The count comes from the store, computed by the handler and passed in, so
/// the scorer stays pure and database-free — the same shape as the puzzle
/// handler passing `ip_count`/`site_count` into `SignalContext`.
pub fn score_duplicate_blob(presence: BehaviorPresence, duplicate_count: u32) -> u32 {
    score_duplicate_blob_with(current(), presence, duplicate_count)
}

/// [`score_duplicate_blob`] against explicit weights; the plain form reads the
/// process-wide table from [`super::weights::current`].
pub fn score_duplicate_blob_with(
    w: &SignalWeights,
    presence: BehaviorPresence,
    duplicate_count: u32,
) -> u32 {
    let BehaviorPresence::Present(b) = presence else {
        return 0;
    };
    if claims_activity(&b) && duplicate_count >= BEHAVIOR_DUPLICATE_MIN {
        w.behavior_duplicate
    } else {
        0
    }
}

pub fn score_behavior(presence: BehaviorPresence) -> u32 {
    score_behavior_with(current(), presence)
}

/// [`score_behavior`] against explicit weights; the plain form reads the
/// process-wide table from [`super::weights::current`].
pub fn score_behavior_with(w: &SignalWeights, presence: BehaviorPresence) -> u32 {
    let BehaviorPresence::Present(b) = presence else {
        return 0;
    };

    let no_pointer = b.mouse_moves == 0 && b.touches == 0;
    let no_interaction = b.interactions == 0;
    // "At most one event happened all session" — the shape both isolated-burst
    // signals below are actually looking for.
    let isolated = b.interactions <= BEHAVIOR_ISOLATED_INTERACTION_MAX;

    let mut score = 0;
    if no_pointer && no_interaction {
        score += w.behavior_flatline;
    } else if no_pointer && isolated {
        // Pointer-free *and* barely any interaction at all. Pointer-free with
        // a real interaction trail is a keyboard or screen-reader visitor and
        // scores nothing here — see BEHAVIOR_ISOLATED_INTERACTION_MAX.
        score += w.behavior_no_pointer;
    }

    // Same gate: an instant first interaction is only driver-shaped when it's
    // the *only* interaction. Someone already typing or scrolling when the
    // widget mounted trips the timing but has a trail behind it.
    if isolated && matches!(b.first_interaction_ms, Some(t) if t < BEHAVIOR_INSTANT_INTERACTION_MS)
    {
        score += w.behavior_instant_interaction;
    }

    // `webdriver` and `automation` are two views of one fact — the browser is
    // driven — so they saturate rather than sum. Summing would push every
    // driven browser to 60 and reverse the deliberate stance that a driven
    // browser showing organic interaction is ShadowFail, not Block (see the
    // e2e browser-harness-simulator regression test). The artifact probe adds
    // *recall*, not weight: it catches drivers that scrub `navigator.webdriver`.
    if matches!(b.webdriver, Some(true)) || matches!(b.automation, Some(true)) {
        score += w.behavior_automation;
    }

    if matches!(b.headless, Some(true)) {
        score += w.behavior_headless;
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
    fn isolated_click_without_pointer_scores() {
        // One interaction, no cursor: the synthetic-click driver this signal
        // was written for.
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
    fn keyboard_only_visitor_scores_nothing() {
        // Tab, type, Tab, activate, Tab, submit — pointer-free by definition,
        // but nothing about it resembles a driver. This scoring 15 was a
        // penalty for how someone navigates; the widget is keyboard-operable
        // on purpose, so the scorer must not contradict that.
        let r = BehaviorReport {
            mouse_moves: 0,
            touches: 0,
            interactions: 24,
            first_interaction_ms: Some(1_500),
            ..Default::default()
        };
        assert_eq!(score_behavior(BehaviorPresence::Present(r)), 0);
    }

    #[test]
    fn no_pointer_penalty_stops_at_the_isolated_interaction_boundary() {
        let at_boundary = BehaviorReport {
            mouse_moves: 0,
            touches: 0,
            interactions: BEHAVIOR_ISOLATED_INTERACTION_MAX,
            first_interaction_ms: Some(1_500),
            ..Default::default()
        };
        let past_boundary = BehaviorReport {
            interactions: BEHAVIOR_ISOLATED_INTERACTION_MAX + 1,
            ..at_boundary
        };
        assert_eq!(
            score_behavior(BehaviorPresence::Present(at_boundary)),
            BEHAVIOR_NO_POINTER_SCORE
        );
        assert_eq!(score_behavior(BehaviorPresence::Present(past_boundary)), 0);
    }

    #[test]
    fn flatline_is_unaffected_by_the_interaction_gate() {
        // Zero interactions still takes the flatline branch, which is checked
        // first — the gate must not accidentally downgrade a total flatline.
        let r = BehaviorReport {
            mouse_moves: 0,
            touches: 0,
            interactions: 0,
            ..Default::default()
        };
        assert_eq!(
            score_behavior(BehaviorPresence::Present(r)),
            BEHAVIOR_FLATLINE_SCORE
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
    fn instant_first_interaction_with_organic_trail_scores_zero() {
        // Already typing when a late-loading widget mounts: the first
        // interaction lands instantly, but the trail behind it is not
        // driver-shaped. Pointer-free too, so before the gate this was 35 —
        // straight into the shadow band, and a block under a tight policy.
        let r = BehaviorReport {
            mouse_moves: 0,
            touches: 0,
            interactions: 8,
            first_interaction_ms: Some(10),
            ..Default::default()
        };
        assert_eq!(score_behavior(BehaviorPresence::Present(r)), 0);
    }

    #[test]
    fn instant_interaction_penalty_stops_at_the_isolated_boundary() {
        // Mid-scroll at mount is the non-keyboard version of the same
        // misfire: `scroll` sets first_interaction_ms, `mousemove` does not.
        let at_boundary = BehaviorReport {
            mouse_moves: 5,
            touches: 0,
            interactions: BEHAVIOR_ISOLATED_INTERACTION_MAX,
            first_interaction_ms: Some(10),
            ..Default::default()
        };
        let past_boundary = BehaviorReport {
            interactions: BEHAVIOR_ISOLATED_INTERACTION_MAX + 1,
            ..at_boundary
        };
        // Pointer present, so this isolates the instant-interaction term.
        assert_eq!(
            score_behavior(BehaviorPresence::Present(at_boundary)),
            BEHAVIOR_INSTANT_INTERACTION_SCORE
        );
        assert_eq!(score_behavior(BehaviorPresence::Present(past_boundary)), 0);
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

    // ── Impossible timing ──

    #[test]
    fn impossible_timing_is_absent_safe() {
        assert_eq!(
            score_impossible_timing(BehaviorPresence::Absent, Some(1_000)),
            0
        );
    }

    #[test]
    fn impossible_timing_needs_a_server_dwell() {
        // The failover path has no challenge and so no dwell — nothing to
        // contradict, and it must not become a free penalty during an outage.
        let r = BehaviorReport {
            first_interaction_ms: Some(600_000),
            interactions: 3,
            ..report()
        };
        assert_eq!(
            score_impossible_timing(BehaviorPresence::Present(r), None),
            0
        );
    }

    #[test]
    fn impossible_timing_ignores_a_missing_first_interaction() {
        // A pointer-only visitor never sets the field; absence can't lie.
        let r = BehaviorReport {
            first_interaction_ms: None,
            ..report()
        };
        assert_eq!(
            score_impossible_timing(BehaviorPresence::Present(r), Some(0)),
            0
        );
    }

    #[test]
    fn impossible_timing_boundary_is_the_slack() {
        let dwell = 2_000;
        let at_slack = BehaviorReport {
            first_interaction_ms: Some(dwell + BEHAVIOR_IMPOSSIBLE_TIMING_SLACK_MS),
            ..report()
        };
        let past_slack = BehaviorReport {
            first_interaction_ms: Some(dwell + BEHAVIOR_IMPOSSIBLE_TIMING_SLACK_MS + 1),
            ..report()
        };
        assert_eq!(
            score_impossible_timing(BehaviorPresence::Present(at_slack), Some(dwell)),
            0,
            "exactly one slack ahead is still explainable by the puzzle fetch"
        );
        assert_eq!(
            score_impossible_timing(BehaviorPresence::Present(past_slack), Some(dwell)),
            BEHAVIOR_IMPOSSIBLE_TIMING_SCORE
        );
    }

    #[test]
    fn organic_widget_timings_are_never_impossible() {
        // The ordinary case: the interaction predates the submit, so the
        // claim is below the dwell and the slack is not even consulted.
        let r = report(); // first_interaction_ms = 800
        assert_eq!(
            score_impossible_timing(BehaviorPresence::Present(r), Some(30_000)),
            0
        );
    }

    #[test]
    fn keyboard_only_visitor_is_untouched_by_the_plausibility_checks() {
        // Pointer-free with a real interaction trail. `first_interaction_ms`
        // is set (keydown does set it, unlike mousemove), so this visitor is
        // in scope for the timing check and must still score nothing.
        let keyboard = BehaviorReport {
            mouse_moves: 0,
            touches: 0,
            interactions: 24,
            first_interaction_ms: Some(1_500),
            ..Default::default()
        };
        let p = BehaviorPresence::Present(keyboard);
        assert_eq!(score_behavior(p), 0);
        assert_eq!(score_impossible_timing(p, Some(1_500)), 0);
        assert_eq!(score_duplicate_blob(p, BEHAVIOR_DUPLICATE_MIN - 1), 0);
    }

    // ── Duplicate blobs ──

    #[test]
    fn duplicate_is_absent_safe() {
        assert_eq!(
            score_duplicate_blob(BehaviorPresence::Absent, BEHAVIOR_DUPLICATE_MIN * 10),
            0
        );
    }

    #[test]
    fn duplicate_boundary_is_the_threshold() {
        let p = BehaviorPresence::Present(report());
        assert_eq!(score_duplicate_blob(p, BEHAVIOR_DUPLICATE_MIN - 1), 0);
        assert_eq!(
            score_duplicate_blob(p, BEHAVIOR_DUPLICATE_MIN),
            BEHAVIOR_DUPLICATE_SCORE
        );
    }

    #[test]
    fn flatline_is_excluded_from_dedup() {
        // Every visitor who submits without touching the page produces this
        // exact blob, so repeats are expected — and it already scores +30.
        let flat = BehaviorReport::default();
        assert!(!claims_activity(&flat));
        assert_eq!(
            score_duplicate_blob(
                BehaviorPresence::Present(flat),
                BEHAVIOR_DUPLICATE_MIN * 100
            ),
            0
        );
        // A flatline carrying only environment probes is still a flatline.
        let probed = BehaviorReport {
            webdriver: Some(false),
            automation: Some(false),
            headless: Some(false),
            ..Default::default()
        };
        assert!(!claims_activity(&probed));
    }

    #[test]
    fn any_single_counter_makes_a_blob_eligible_for_dedup() {
        for r in [
            BehaviorReport {
                mouse_moves: 1,
                ..Default::default()
            },
            BehaviorReport {
                touches: 1,
                ..Default::default()
            },
            BehaviorReport {
                interactions: 1,
                ..Default::default()
            },
        ] {
            assert!(claims_activity(&r));
        }
    }

    #[test]
    fn both_plausibility_checks_stack() {
        // Independent facts: one is about this submission's internal
        // consistency, the other about the population of submissions. Unlike
        // webdriver/automation they are not two views of one thing, so they
        // sum — and a client that trips both has earned block_min.
        let r = BehaviorReport {
            mouse_moves: 20,
            interactions: 2,
            first_interaction_ms: Some(120_000),
            ..Default::default()
        };
        let p = BehaviorPresence::Present(r);
        let total = score_behavior(p)
            + score_impossible_timing(p, Some(1_000))
            + score_duplicate_blob(p, BEHAVIOR_DUPLICATE_MIN);
        assert_eq!(
            total,
            BEHAVIOR_IMPOSSIBLE_TIMING_SCORE + BEHAVIOR_DUPLICATE_SCORE
        );
    }

    // ── Fingerprint ──

    #[test]
    fn fingerprint_is_stable_and_field_sensitive() {
        let a = report();
        assert_eq!(behavior_fingerprint(&a), behavior_fingerprint(&report()));

        for changed in [
            BehaviorReport {
                mouse_moves: a.mouse_moves + 1,
                ..a
            },
            BehaviorReport {
                touches: a.touches + 1,
                ..a
            },
            BehaviorReport {
                interactions: a.interactions + 1,
                ..a
            },
            BehaviorReport {
                first_interaction_ms: Some(801),
                ..a
            },
            BehaviorReport {
                first_interaction_ms: None,
                ..a
            },
            BehaviorReport {
                webdriver: Some(true),
                ..a
            },
            BehaviorReport {
                automation: None,
                ..a
            },
            BehaviorReport {
                headless: Some(true),
                ..a
            },
        ] {
            assert_ne!(
                behavior_fingerprint(&a),
                behavior_fingerprint(&changed),
                "every wire field must be covered by the fingerprint"
            );
        }
    }

    #[test]
    fn fingerprint_ignores_json_shape() {
        // Hashing the parsed struct, not the bytes: re-ordering keys or
        // spelling out a default must not mint a fresh dedup identity.
        let a: BehaviorReport = serde_json::from_str(
            r#"{"mouse_moves":12,"interactions":3,"first_interaction_ms":800}"#,
        )
        .unwrap();
        let b: BehaviorReport = serde_json::from_str(
            r#"{ "first_interaction_ms" : 800 , "interactions": 3, "touches": 0,
                 "mouse_moves": 12 }"#,
        )
        .unwrap();
        assert_eq!(behavior_fingerprint(&a), behavior_fingerprint(&b));
    }
}
