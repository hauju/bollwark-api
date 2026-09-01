//! Verify-time risk scoring.
//!
//! Runs as a second pass at `/v1/verify` time, after the puzzle was issued
//! and (presumably) solved. The signals available here weren't observable
//! at puzzle issuance: how long the widget was mounted before the user
//! submitted, whether the honeypot was tripped, and the behavioral telemetry
//! the widget collected.
//!
//! The decision is three-state: `Pass`, `ShadowFail`, `Block`.
//! `ShadowFail` returns `success: true` to the caller but emits a structured
//! warn log so an operator can review the request offline.

use super::behavior::{
    BEHAVIOR_FLATLINE_SCORE, BehaviorPresence, score_behavior, score_duplicate_blob,
    score_impossible_timing,
};

#[derive(Debug, Clone, Copy)]
pub struct VerifyContext {
    pub honeypot_tripped: bool,
    pub time_on_page_ms: Option<u64>,
    pub behavior: BehaviorPresence,
    /// How many times this exact behaviour blob has been submitted for this
    /// site inside the dedup window, including this submission. Supplied by
    /// the handler from the store — the scorer stays pure, exactly as the
    /// puzzle side passes `ip_count`/`site_count` into `SignalContext`.
    /// `0` means "not counted" (no blob, a flatline, or the failover path).
    pub behavior_duplicate_count: u32,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct VerifyBreakdown {
    pub honeypot: u32,
    pub time_on_page: u32,
    pub behavior: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct VerifyScore {
    pub total: u32,
    pub breakdown: VerifyBreakdown,
    pub decision: VerifyDecision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyDecision {
    /// Score below the shadow threshold — pass through.
    Pass,
    /// Score in the shadow band — return success but log for review.
    ShadowFail,
    /// Score at or above the block threshold — return failure.
    Block,
}

#[derive(Debug, Clone, Copy)]
pub struct VerifyThresholds {
    pub shadow_min: u32,
    pub block_min: u32,
}

impl Default for VerifyThresholds {
    fn default() -> Self {
        Self {
            shadow_min: 30,
            block_min: 60,
        }
    }
}

// Honeypot is the strongest signal: any non-empty value is conclusive bot
// behavior, so it always pushes past the block threshold on its own.
pub const HONEYPOT_TRIPPED_SCORE: u32 = 100;

// Time-on-page bands. Anything under 500ms is essentially impossible for a
// human (no time to read the form, let alone fill it). 500ms–2s is suspicious.
// The handler derives this value server-side as `now - challenge.dwell_since`,
// an anchor that survives the widget's pre-expiry refreshes, so it's the true
// elapsed time since the visitor arrived — not a client-reported figure a bot
// could inflate, and no longer reset to zero by a background refresh the
// visitor never saw.
pub const TIME_VERY_SHORT_MS: u64 = 500;
pub const TIME_SHORT_MS: u64 = 2_000;
pub const TIME_VERY_SHORT_SCORE: u32 = 50;
pub const TIME_SHORT_SCORE: u32 = 25;

pub fn score_time_on_page(ms: Option<u64>) -> u32 {
    match ms {
        None => 0, // Field is optional; absence isn't suspicious on its own.
        Some(t) if t < TIME_VERY_SHORT_MS => TIME_VERY_SHORT_SCORE,
        Some(t) if t < TIME_SHORT_MS => TIME_SHORT_SCORE,
        _ => 0,
    }
}

pub struct VerifyScorer {
    /// `VERIFY_REQUIRE_BEHAVIOR`: score a missing behavior blob like a
    /// flatline instead of 0. For deployments where every legitimate client
    /// is the bundled widget (which always sends the blob), an absent blob
    /// is at least as suspicious as an empty one — without this, a bot
    /// hitting the API directly opts out of the behavioral layer entirely.
    require_behavior: bool,
}

impl VerifyScorer {
    pub fn new(require_behavior: bool) -> Self {
        Self { require_behavior }
    }

    /// `thresholds` is a per-call input rather than scorer state so a site's
    /// [`crate::site::types::SitePolicy`] can move the shadow/block bands
    /// without changing what any signal is worth. The signal weights above are
    /// a property of this service; the bands are a property of the site.
    pub fn score(&self, ctx: &VerifyContext, thresholds: VerifyThresholds) -> VerifyScore {
        let breakdown = VerifyBreakdown {
            honeypot: if ctx.honeypot_tripped {
                HONEYPOT_TRIPPED_SCORE
            } else {
                0
            },
            time_on_page: score_time_on_page(ctx.time_on_page_ms),
            // All three behaviour-blob terms fold into one component so the
            // decision-log schema doesn't move. They sum rather than saturate:
            // `score_behavior` judges what the counters describe, the timing
            // check judges whether this submission's timeline is internally
            // possible, and the dedup check judges the blob against every
            // other blob this site received. Three separate facts, unlike the
            // `webdriver`/`automation` pair inside `score_behavior`, which are
            // two readings of one.
            behavior: match ctx.behavior {
                BehaviorPresence::Absent if self.require_behavior => BEHAVIOR_FLATLINE_SCORE,
                b => {
                    score_behavior(b)
                        + score_impossible_timing(b, ctx.time_on_page_ms)
                        + score_duplicate_blob(b, ctx.behavior_duplicate_count)
                }
            },
        };
        let total = breakdown.honeypot + breakdown.time_on_page + breakdown.behavior;
        let decision = if total >= thresholds.block_min {
            VerifyDecision::Block
        } else if total >= thresholds.shadow_min {
            VerifyDecision::ShadowFail
        } else {
            VerifyDecision::Pass
        };
        VerifyScore {
            total,
            breakdown,
            decision,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::BehaviorReport;

    fn scorer() -> VerifyScorer {
        VerifyScorer::new(false)
    }

    fn strict_scorer() -> VerifyScorer {
        VerifyScorer::new(true)
    }

    fn ctx() -> VerifyContext {
        VerifyContext {
            honeypot_tripped: false,
            time_on_page_ms: Some(10_000),
            behavior: BehaviorPresence::Absent,
            behavior_duplicate_count: 0,
        }
    }

    #[test]
    fn honeypot_tripped_blocks_unconditionally() {
        let mut c = ctx();
        c.honeypot_tripped = true;
        let s = scorer().score(&c, VerifyThresholds::default());
        assert_eq!(s.breakdown.honeypot, HONEYPOT_TRIPPED_SCORE);
        assert_eq!(s.decision, VerifyDecision::Block);
    }

    #[test]
    fn very_fast_submit_shadows() {
        let mut c = ctx();
        c.time_on_page_ms = Some(100);
        let s = scorer().score(&c, VerifyThresholds::default());
        // 50 (very short) → shadow band but not block
        assert_eq!(s.total, 50);
        assert_eq!(s.decision, VerifyDecision::ShadowFail);
    }

    #[test]
    fn time_short_band_passes() {
        let mut c = ctx();
        c.time_on_page_ms = Some(1_500);
        let s = scorer().score(&c, VerifyThresholds::default());
        // 25 (short) → < shadow_min(30) → Pass
        assert_eq!(s.total, 25);
        assert_eq!(s.decision, VerifyDecision::Pass);
    }

    #[test]
    fn clean_submit_passes() {
        let s = scorer().score(&ctx(), VerifyThresholds::default());
        assert_eq!(s.total, 0);
        assert_eq!(s.decision, VerifyDecision::Pass);
    }

    #[test]
    fn behavior_flatline_lands_in_shadow() {
        let mut c = ctx();
        c.behavior = BehaviorPresence::Present(super::super::behavior::BehaviorReport::default());
        let s = scorer().score(&c, VerifyThresholds::default());
        // 30 (flatline) → ShadowFail
        assert_eq!(s.breakdown.behavior, 30);
        assert_eq!(s.decision, VerifyDecision::ShadowFail);
    }

    #[test]
    fn behavior_organic_passes() {
        let mut c = ctx();
        c.behavior = BehaviorPresence::Present(super::super::behavior::BehaviorReport {
            mouse_moves: 20,
            touches: 0,
            interactions: 2,
            first_interaction_ms: Some(800),
            ..Default::default()
        });
        let s = scorer().score(&c, VerifyThresholds::default());
        assert_eq!(s.breakdown.behavior, 0);
        assert_eq!(s.decision, VerifyDecision::Pass);
    }

    #[test]
    fn require_behavior_scores_absent_as_flatline() {
        // ctx() has no behavior blob — with the flag, absence lands in the
        // shadow band on its own, same as a flatline blob would.
        let s = strict_scorer().score(&ctx(), VerifyThresholds::default());
        assert_eq!(
            s.breakdown.behavior,
            super::super::behavior::BEHAVIOR_FLATLINE_SCORE
        );
        assert_eq!(s.decision, VerifyDecision::ShadowFail);
    }

    #[test]
    fn require_behavior_leaves_present_blobs_untouched() {
        let mut c = ctx();
        c.behavior = BehaviorPresence::Present(super::super::behavior::BehaviorReport {
            mouse_moves: 20,
            touches: 0,
            interactions: 2,
            first_interaction_ms: Some(800),
            ..Default::default()
        });
        let s = strict_scorer().score(&c, VerifyThresholds::default());
        assert_eq!(s.breakdown.behavior, 0);
        assert_eq!(s.decision, VerifyDecision::Pass);
    }

    #[test]
    fn absent_behavior_is_neutral_by_default() {
        // Default posture (flag off): legacy/server-to-server callers with
        // no blob contribute 0 — the pre-existing rollout guarantee.
        let s = scorer().score(&ctx(), VerifyThresholds::default());
        assert_eq!(s.breakdown.behavior, 0);
        assert_eq!(s.decision, VerifyDecision::Pass);
    }

    #[test]
    fn missing_time_on_page_is_neutral() {
        let mut c = ctx();
        c.time_on_page_ms = None;
        let s = scorer().score(&c, VerifyThresholds::default());
        assert_eq!(s.breakdown.time_on_page, 0);
        assert_eq!(s.decision, VerifyDecision::Pass);
    }

    #[test]
    fn time_curve() {
        assert_eq!(score_time_on_page(None), 0);
        assert_eq!(score_time_on_page(Some(0)), TIME_VERY_SHORT_SCORE);
        assert_eq!(score_time_on_page(Some(499)), TIME_VERY_SHORT_SCORE);
        assert_eq!(score_time_on_page(Some(500)), TIME_SHORT_SCORE);
        assert_eq!(score_time_on_page(Some(1_999)), TIME_SHORT_SCORE);
        assert_eq!(score_time_on_page(Some(2_000)), 0);
    }

    /// The disparate-impact regression. A keyboard-only visitor is
    /// pointer-free by definition, and used to collect +15 for it. Combined
    /// with the short-dwell band that reached 40 — a hard block under the
    /// tightened `verify_block_min` this project documents as a realistic
    /// login policy — where a mouse user doing the identical thing scored 25
    /// and passed. The widget is deliberately keyboard-operable; the scorer
    /// must not undo that.
    #[test]
    fn keyboard_only_visitor_passes_even_under_a_tight_policy() {
        let keyboard = BehaviorReport {
            mouse_moves: 0,
            touches: 0,
            interactions: 24,
            first_interaction_ms: Some(1_500),
            ..Default::default()
        };
        let c = VerifyContext {
            honeypot_tripped: false,
            // Inside the <2s band, so the time signal contributes its +25.
            time_on_page_ms: Some(1_500),
            behavior: BehaviorPresence::Present(keyboard),
            behavior_duplicate_count: 0,
        };
        let tight = VerifyThresholds {
            shadow_min: 20,
            block_min: 30,
        };
        let s = scorer().score(&c, tight);

        assert_eq!(s.breakdown.behavior, 0, "keyboard use is not a penalty");
        assert_eq!(s.total, 25, "only the short-dwell band should contribute");
        // Not blocked. What remains is the short-dwell band, which a mouse
        // user with the same 1.5s dwell scores identically — equal treatment
        // is the property under test, not immunity.
        assert_eq!(s.decision, VerifyDecision::ShadowFail);
        assert_ne!(s.decision, VerifyDecision::Block);
    }

    /// The second half of the same disparate-impact story. A keyboard user who
    /// was already typing when a late-loading widget mounted registers an
    /// instant first interaction — before the gate that was +20 on top of the
    /// pointer-free +15, i.e. 35, ShadowFail at defaults and a hard block under
    /// the tightened policy this project documents. Neither term is a
    /// judgement about what they did, only about how they navigate.
    #[test]
    fn keyboard_visitor_typing_at_mount_passes_under_a_tight_policy() {
        let typing_at_mount = BehaviorReport {
            mouse_moves: 0,
            touches: 0,
            interactions: 8,
            first_interaction_ms: Some(10),
            ..Default::default()
        };
        let c = VerifyContext {
            honeypot_tripped: false,
            time_on_page_ms: Some(1_500),
            behavior: BehaviorPresence::Present(typing_at_mount),
            behavior_duplicate_count: 0,
        };
        let tight = VerifyThresholds {
            shadow_min: 20,
            block_min: 30,
        };
        let s = scorer().score(&c, tight);

        assert_eq!(s.breakdown.behavior, 0, "navigation style is not a penalty");
        assert_eq!(s.total, 25, "only the short-dwell band should contribute");
        assert_ne!(s.decision, VerifyDecision::Block);
    }

    /// A fabricated blob claiming an interaction from long before the visitor
    /// existed. Alone it must shadow, never block — the same rollout stance as
    /// `VERIFY_REQUIRE_BEHAVIOR`.
    #[test]
    fn impossible_timing_alone_shadows() {
        let mut c = ctx();
        c.time_on_page_ms = Some(10_000);
        c.behavior = BehaviorPresence::Present(BehaviorReport {
            mouse_moves: 20,
            interactions: 2,
            first_interaction_ms: Some(120_000),
            ..Default::default()
        });
        let s = scorer().score(&c, VerifyThresholds::default());
        assert_eq!(
            s.breakdown.behavior,
            super::super::behavior::BEHAVIOR_IMPOSSIBLE_TIMING_SCORE
        );
        assert_eq!(s.decision, VerifyDecision::ShadowFail);
    }

    /// Same organic-looking blob, arriving for the Nth time on one site.
    #[test]
    fn duplicate_blob_alone_shadows() {
        let mut c = ctx();
        c.behavior = BehaviorPresence::Present(BehaviorReport {
            mouse_moves: 20,
            interactions: 2,
            first_interaction_ms: Some(800),
            ..Default::default()
        });
        c.behavior_duplicate_count = super::super::behavior::BEHAVIOR_DUPLICATE_MIN;
        let s = scorer().score(&c, VerifyThresholds::default());
        assert_eq!(
            s.breakdown.behavior,
            super::super::behavior::BEHAVIOR_DUPLICATE_SCORE
        );
        assert_eq!(s.decision, VerifyDecision::ShadowFail);
    }

    /// Below the threshold the same blob is worth nothing: humans share a
    /// site, and four coincidences are not evidence.
    #[test]
    fn duplicate_below_threshold_passes() {
        let mut c = ctx();
        c.behavior = BehaviorPresence::Present(BehaviorReport {
            mouse_moves: 20,
            interactions: 2,
            first_interaction_ms: Some(800),
            ..Default::default()
        });
        c.behavior_duplicate_count = super::super::behavior::BEHAVIOR_DUPLICATE_MIN - 1;
        let s = scorer().score(&c, VerifyThresholds::default());
        assert_eq!(s.breakdown.behavior, 0);
        assert_eq!(s.decision, VerifyDecision::Pass);
    }

    /// The two checks are independent facts, so they stack — and a client
    /// that is both internally impossible and mass-produced reaches block_min
    /// on the behaviour component alone. Neither gets there by itself.
    #[test]
    fn impossible_and_duplicate_stack_to_block() {
        let mut c = ctx();
        c.time_on_page_ms = Some(10_000);
        c.behavior = BehaviorPresence::Present(BehaviorReport {
            mouse_moves: 20,
            interactions: 2,
            first_interaction_ms: Some(120_000),
            ..Default::default()
        });
        c.behavior_duplicate_count = super::super::behavior::BEHAVIOR_DUPLICATE_MIN;
        let s = scorer().score(&c, VerifyThresholds::default());
        assert_eq!(
            s.breakdown.behavior,
            super::super::behavior::BEHAVIOR_IMPOSSIBLE_TIMING_SCORE
                + super::super::behavior::BEHAVIOR_DUPLICATE_SCORE
        );
        assert_eq!(s.decision, VerifyDecision::Block);
    }

    /// Neither check may resurrect a blob that was never sent: an absent blob
    /// stays 0 whatever dwell or duplicate count accompanies it.
    #[test]
    fn absent_blob_is_untouched_by_the_plausibility_checks() {
        let mut c = ctx();
        // A zero dwell would make any claimed first interaction "impossible",
        // and the duplicate count is absurd — neither may invent a blob.
        c.time_on_page_ms = Some(0);
        c.behavior_duplicate_count = super::super::behavior::BEHAVIOR_DUPLICATE_MIN * 10;
        let s = scorer().score(&c, VerifyThresholds::default());
        assert_eq!(s.breakdown.behavior, 0);
        assert_eq!(s.total, TIME_VERY_SHORT_SCORE, "only the dwell band fires");
    }
}
