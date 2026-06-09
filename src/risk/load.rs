//! Aggregate site-load difficulty floor.
//!
//! Unlike the per-request risk signals, this raises PoW difficulty based on
//! *aggregate* traffic to a site: when the whole site is hot, every visitor —
//! however individually benign — does more work. It catches distributed
//! floods where each IP looks fine on its own but the site-wide request count
//! is abnormal. The floor composes with the per-request tier via `max()` and
//! never blocks; blocking stays a per-request risk decision.
//!
//! Inspired by mCaptcha's traffic-tiered defense, but expressed in leading
//! zero bits so it drops into the existing difficulty path unchanged.

/// One rung of the ladder: once the site's request count in the rate window
/// reaches `visitor_threshold`, the PoW difficulty floor becomes `difficulty`
/// (leading zero bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadLevel {
    pub visitor_threshold: u32,
    pub difficulty: u32,
}

/// Ordered set of load rungs, held sorted by `visitor_threshold` descending so
/// `floor_for` returns the highest difficulty whose threshold the current load
/// meets. An empty ladder is a no-op — the floor is always 0.
#[derive(Debug, Clone, Default)]
pub struct LoadLadder {
    levels: Vec<LoadLevel>,
}

impl LoadLadder {
    /// Parse a `LOAD_LADDER` spec: comma-separated `threshold:difficulty`
    /// pairs, e.g. `"200:20,500:22,1000:24"`. Whitespace around tokens is
    /// ignored and empty entries (e.g. a trailing comma) are skipped, so an
    /// empty or whitespace-only spec yields an empty ladder. Malformed input
    /// is an error — the caller fails loud rather than silently running
    /// without the floor it was configured to apply.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut levels = Vec::new();
        for entry in spec.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let (threshold, difficulty) = entry
                .split_once(':')
                .ok_or_else(|| format!("load ladder entry {entry:?} is missing ':'"))?;
            let visitor_threshold = threshold
                .trim()
                .parse()
                .map_err(|_| format!("load ladder threshold {threshold:?} is not a number"))?;
            let difficulty = difficulty
                .trim()
                .parse()
                .map_err(|_| format!("load ladder difficulty {difficulty:?} is not a number"))?;
            levels.push(LoadLevel {
                visitor_threshold,
                difficulty,
            });
        }
        levels.sort_by_key(|level| std::cmp::Reverse(level.visitor_threshold));
        Ok(Self { levels })
    }

    /// Difficulty floor for the current per-site request count. Returns the
    /// difficulty of the highest rung whose threshold `site_count` meets, or
    /// 0 when no rung applies (including the empty ladder).
    pub fn floor_for(&self, site_count: u32) -> u32 {
        self.levels
            .iter()
            .find(|level| site_count >= level.visitor_threshold)
            .map_or(0, |level| level.difficulty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_spec_is_a_no_op() {
        let ladder = LoadLadder::parse("").unwrap();
        assert_eq!(ladder.floor_for(0), 0);
        assert_eq!(ladder.floor_for(1_000_000), 0);
    }

    #[test]
    fn whitespace_and_trailing_comma_are_ignored() {
        let ladder = LoadLadder::parse("  200:20 , 500:22 , ").unwrap();
        assert_eq!(ladder.floor_for(199), 0);
        assert_eq!(ladder.floor_for(200), 20);
        assert_eq!(ladder.floor_for(500), 22);
    }

    #[test]
    fn floor_picks_highest_matching_rung_regardless_of_input_order() {
        // Deliberately unsorted input.
        let ladder = LoadLadder::parse("1000:24,200:20,500:22").unwrap();
        assert_eq!(ladder.floor_for(0), 0); // below lowest threshold
        assert_eq!(ladder.floor_for(199), 0);
        assert_eq!(ladder.floor_for(200), 20); // exact boundary
        assert_eq!(ladder.floor_for(350), 20); // between rungs
        assert_eq!(ladder.floor_for(500), 22);
        assert_eq!(ladder.floor_for(999), 22);
        assert_eq!(ladder.floor_for(1000), 24);
        assert_eq!(ladder.floor_for(50_000), 24); // above the top rung
    }

    #[test]
    fn missing_colon_is_an_error() {
        let err = LoadLadder::parse("200:20,500").unwrap_err();
        assert!(err.contains("missing ':'"), "{err}");
    }

    #[test]
    fn non_numeric_threshold_is_an_error() {
        assert!(LoadLadder::parse("abc:20").is_err());
    }

    #[test]
    fn non_numeric_difficulty_is_an_error() {
        assert!(LoadLadder::parse("200:high").is_err());
    }
}
