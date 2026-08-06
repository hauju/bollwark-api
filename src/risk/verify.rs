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

use super::behavior::{BEHAVIOR_FLATLINE_SCORE, BehaviorPresence, score_behavior};

#[derive(Debug, Clone, Copy)]
pub struct VerifyContext {
    pub honeypot_tripped: bool,
    pub time_on_page_ms: Option<u64>,
    pub behavior: BehaviorPresence,
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
// The handler derives this value server-side as `now - challenge.created_at`
// (issuance ≈ widget mount, or the widget's most recent pre-expiry refresh),
// so it's the true elapsed time including PoW solve — not a client-reported
// figure a bot could inflate. A legit user submitting right after a background
// refresh lands at +25/+50 at worst — ShadowFail territory, never Block on
// this signal alone.
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
            behavior: match ctx.behavior {
                BehaviorPresence::Absent if self.require_behavior => BEHAVIOR_FLATLINE_SCORE,
                b => score_behavior(b),
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
}
