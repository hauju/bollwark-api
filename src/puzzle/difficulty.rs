use crate::config::AppConfig;

pub struct DifficultyCalculator {
    default: u32,
    min: u32,
    max: u32,
}

impl DifficultyCalculator {
    pub fn new(config: &AppConfig) -> Self {
        Self {
            default: config.default_difficulty,
            min: config.min_difficulty,
            max: config.max_difficulty,
        }
    }

    /// Compute adaptive difficulty based on rate counters.
    ///
    /// - `ip_count`: requests from this IP in the current window
    /// - `site_count`: requests to this site_key in the current window
    pub fn compute(&self, ip_count: u32, site_count: u32) -> u32 {
        let mut difficulty = self.default;

        // Increase difficulty for high IP request rates
        if ip_count > 50 {
            difficulty += 4;
        } else if ip_count > 20 {
            difficulty += 2;
        } else if ip_count > 10 {
            difficulty += 1;
        }

        // Increase difficulty for high site request rates
        if site_count > 500 {
            difficulty += 2;
        } else if site_count > 200 {
            difficulty += 1;
        }

        difficulty.clamp(self.min, self.max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn calc() -> DifficultyCalculator {
        DifficultyCalculator {
            default: 20,
            min: 16,
            max: 28,
        }
    }

    #[test]
    fn test_default_difficulty() {
        assert_eq!(calc().compute(0, 0), 20);
    }

    #[test]
    fn test_high_ip_rate() {
        assert_eq!(calc().compute(55, 0), 24);
    }

    #[test]
    fn test_moderate_ip_rate() {
        assert_eq!(calc().compute(25, 0), 22);
    }

    #[test]
    fn test_high_site_rate() {
        assert_eq!(calc().compute(0, 600), 22);
    }

    #[test]
    fn test_combined_signals() {
        // ip > 50 (+4) + site > 500 (+2) = 20 + 6 = 26
        assert_eq!(calc().compute(55, 600), 26);
    }

    #[test]
    fn test_clamp_max() {
        // ip > 50 (+4) + site > 500 (+2) = 20 + 6 = 26, within max=28
        let calc = DifficultyCalculator {
            default: 26,
            min: 16,
            max: 28,
        };
        // 26 + 4 + 2 = 32, clamped to 28
        assert_eq!(calc.compute(55, 600), 28);
    }

    #[test]
    fn test_clamp_min() {
        let calc = DifficultyCalculator {
            default: 14,
            min: 16,
            max: 28,
        };
        assert_eq!(calc.compute(0, 0), 16);
    }
}
