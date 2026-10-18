//! Bounded offline search. No I/O, identifiers, raw telemetry or model calls.
use serde::Serialize;

pub const KEYS: [&str; 10] = [
    "TIME_VERY_SHORT_SCORE",
    "TIME_SHORT_SCORE",
    "REMOTE_IP_MISMATCH_SCORE",
    "BEHAVIOR_FLATLINE_SCORE",
    "BEHAVIOR_NO_POINTER_SCORE",
    "BEHAVIOR_INSTANT_INTERACTION_SCORE",
    "BEHAVIOR_AUTOMATION_SCORE",
    "BEHAVIOR_HEADLESS_SCORE",
    "BEHAVIOR_IMPOSSIBLE_TIMING_SCORE",
    "BEHAVIOR_DUPLICATE_SCORE",
];
pub type Weights = [u32; KEYS.len()];

#[derive(Clone, Debug)]
pub struct Sample {
    pub spam: bool,
    /// Signal activations, derived using the production scorer.
    pub active: [bool; KEYS.len()],
    /// Untuned contribution (honeypot).
    pub fixed_score: u32,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Metrics {
    pub legit: usize,
    pub spam: usize,
    pub legit_blocked: usize,
    pub spam_blocked: usize,
}
impl Metrics {
    pub fn false_positive_rate(self) -> f64 {
        if self.legit == 0 {
            1.0
        } else {
            self.legit_blocked as f64 / self.legit as f64
        }
    }
    /// Wilson 95% upper bound: zero observed failures is not zero risk.
    pub fn false_positive_upper_95(self) -> f64 {
        if self.legit == 0 {
            return 1.0;
        }
        let n = self.legit as f64;
        let p = self.false_positive_rate();
        let z2 = 1.96_f64.powi(2);
        (p + z2 / (2.0 * n) + 1.96 * (p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt())
            / (1.0 + z2 / n)
    }
}

pub fn evaluate(samples: &[Sample], weights: &Weights, block_min: u32) -> Metrics {
    let mut m = Metrics::default();
    for s in samples {
        let score = s
            .active
            .iter()
            .zip(weights)
            .filter(|(active, _)| **active)
            .fold(u64::from(s.fixed_score), |total, (_, weight)| {
                total + u64::from(*weight)
            });
        let blocked = score >= u64::from(block_min);
        if s.spam {
            m.spam += 1;
            m.spam_blocked += usize::from(blocked);
        } else {
            m.legit += 1;
            m.legit_blocked += usize::from(blocked);
        }
    }
    m
}

#[derive(Clone, Copy, Serialize)]
pub struct Policy {
    pub block_min: u32,
    pub max_false_positive_rate: f64,
    pub min_per_class: usize,
}
impl Policy {
    pub fn validate(self) -> Result<(), &'static str> {
        if self.block_min == 0
            || !self.max_false_positive_rate.is_finite()
            || !(0.0..=0.05).contains(&self.max_false_positive_rate)
            || self.min_per_class < 20
        {
            return Err(
                "require positive block threshold, false-positive ceiling in 0..=0.05, and at least 20 labels per class",
            );
        }
        Ok(())
    }
    fn enough(self, m: Metrics) -> bool {
        m.legit >= self.min_per_class && m.spam >= self.min_per_class
    }
}

/// Train only on the training partition. Fixed budget: three coordinate sweeps,
/// +/- five, ten or fifteen points, bounded to half..one-and-a-half of the baseline (never zero).
pub fn search(
    train: &[Sample],
    baseline: Weights,
    policy: Policy,
) -> Result<Weights, &'static str> {
    policy.validate()?;
    if baseline.iter().any(|w| *w == 0 || *w > 1000) {
        return Err("baseline weights must be in 1..=1000");
    }
    let base = evaluate(train, &baseline, policy.block_min);
    if !policy.enough(base) {
        return Err("insufficient training labels");
    }
    let mut best = baseline;
    let mut best_metrics = base;
    for _ in 0..3 {
        for i in 0..KEYS.len() {
            for delta in [-15_i32, -10, -5, 5, 10, 15] {
                let mut candidate = best;
                candidate[i] = (best[i] as i32 + delta).clamp(
                    (baseline[i] / 2).max(1) as i32,
                    (baseline[i] + baseline[i] / 2) as i32,
                ) as u32;
                // Keep noisy single probes below block and preserve dwell ordering.
                if candidate[0] < candidate[1]
                    || candidate[2..].iter().any(|w| *w >= policy.block_min)
                {
                    continue;
                }
                let m = evaluate(train, &candidate, policy.block_min);
                let improves = m.spam_blocked > best_metrics.spam_blocked
                    || (m.spam_blocked == best_metrics.spam_blocked
                        && m.legit_blocked < best_metrics.legit_blocked);
                if improves
                    && m.legit_blocked <= base.legit_blocked
                    && m.false_positive_rate() <= policy.max_false_positive_rate
                {
                    best = candidate;
                    best_metrics = m;
                }
            }
        }
    }
    Ok(best)
}

#[derive(Serialize)]
pub struct Comparison {
    pub baseline: Metrics,
    pub candidate: Metrics,
    pub candidate_false_positive_upper_95: f64,
    pub accepted: bool,
}

/// Evaluate once on untouched data. Require strict detection gain, no observed
/// false-positive regression, enough labels, and the conservative FPR bound.
pub fn compare(
    samples: &[Sample],
    baseline: &Weights,
    candidate: &Weights,
    policy: Policy,
) -> Comparison {
    let base = evaluate(samples, baseline, policy.block_min);
    let cand = evaluate(samples, candidate, policy.block_min);
    let upper = cand.false_positive_upper_95();
    Comparison {
        baseline: base,
        candidate: cand,
        candidate_false_positive_upper_95: upper,
        accepted: policy.validate().is_ok()
            && policy.enough(cand)
            && cand.spam_blocked > base.spam_blocked
            && cand.legit_blocked <= base.legit_blocked
            && upper <= policy.max_false_positive_rate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn data() -> Vec<Sample> {
        let legit = Sample {
            spam: false,
            active: [false; 10],
            fixed_score: 0,
        };
        let mut spam = Sample {
            spam: true,
            ..legit.clone()
        };
        spam.active[3] = true;
        spam.active[6] = true;
        [vec![legit; 400], vec![spam; 100]].concat()
    }
    fn policy() -> Policy {
        Policy {
            block_min: 60,
            max_false_positive_rate: 0.01,
            min_per_class: 100,
        }
    }
    #[test]
    fn improves_without_blocking_legitimate_samples() {
        let baseline = [25; 10];
        let candidate = search(&data(), baseline, policy()).unwrap();
        assert!(compare(&data(), &baseline, &candidate, policy()).accepted);
        assert!(candidate.iter().all(|w| (12..=37).contains(w)));
    }
    #[test]
    fn refuses_regressions_and_small_holdouts() {
        let baseline = [25; 10];
        let candidate = [35; 10];
        let mut holdout = data();
        holdout[0].active[3] = true;
        holdout[0].active[6] = true;
        assert!(!compare(&holdout, &baseline, &candidate, policy()).accepted);
        assert!(!compare(&data()[390..], &baseline, &candidate, policy()).accepted);
        assert!(!compare(&data(), &baseline, &baseline, policy()).accepted);
    }
    #[test]
    fn empty_or_one_class_data_cannot_pass() {
        assert!(search(&[], [25; 10], policy()).is_err());
        assert!(search(&data()[400..], [25; 10], policy()).is_err());
        assert_eq!(Metrics::default().false_positive_upper_95(), 1.0);
    }
    #[test]
    fn zero_observed_failures_still_needs_evidence() {
        let m = Metrics {
            legit: 100,
            ..Metrics::default()
        };
        assert!(m.false_positive_upper_95() > 0.03);
        assert!(
            Policy {
                max_false_positive_rate: f64::NAN,
                ..policy()
            }
            .validate()
            .is_err()
        );
    }
}
