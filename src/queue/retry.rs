// src/queue/retry.rs
//
// Retry schedule with exponential backoff for failed delivery attempts.

use std::time::Duration;

/// Configurable retry policy for outbound delivery.
#[derive(Debug, Clone)]
pub struct RetrySchedule {
    /// Initial delay before first retry (e.g., 60s).
    pub initial_delay: Duration,
    /// Multiplier applied after each failed attempt (e.g., 2.0 = double each time).
    pub backoff_multiplier: f64,
    /// Maximum delay cap between retries (e.g., 1 hour).
    pub max_delay: Duration,
    /// Maximum number of delivery attempts before giving up.
    pub max_attempts: u32,
}

impl Default for RetrySchedule {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_secs(60),   // 1 minute
            backoff_multiplier: 2.0,
            max_delay: Duration::from_secs(3600),     // 1 hour
            max_attempts: 10,
        }
    }
}

impl RetrySchedule {
    /// Create a new retry schedule with custom parameters.
    pub fn new(
        initial_delay: Duration,
        backoff_multiplier: f64,
        max_delay: Duration,
        max_attempts: u32,
    ) -> Self {
        Self {
            initial_delay,
            backoff_multiplier,
            max_delay,
            max_attempts,
        }
    }

    /// Compute the delay before the Nth attempt (1-indexed).
    /// Attempt 1 is immediate (0 delay), attempt 2 uses initial_delay, etc.
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        if attempt <= 1 {
            return Duration::ZERO;
        }
        // attempt 2 -> initial_delay * (multiplier ^ 0)
        // attempt 3 -> initial_delay * (multiplier ^ 1)
        // etc.
        let exponent = (attempt - 2) as f64;
        let delay_secs = self.initial_delay.as_secs_f64()
            * self.backoff_multiplier.powi(exponent as i32);
        let delay = Duration::from_secs_f64(delay_secs);
        delay.min(self.max_delay)
    }

    /// Returns true if we should give up after `attempt` failed attempts.
    pub fn should_give_up(&self, attempt: u32) -> bool {
        attempt >= self.max_attempts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_schedule() {
        let sched = RetrySchedule::default();
        assert_eq!(sched.delay_for_attempt(1), Duration::ZERO);
        assert_eq!(sched.delay_for_attempt(2), Duration::from_secs(60));
        assert_eq!(sched.delay_for_attempt(3), Duration::from_secs(120));
        assert_eq!(sched.delay_for_attempt(4), Duration::from_secs(240));
    }

    #[test]
    fn max_delay_cap() {
        let sched = RetrySchedule::new(
            Duration::from_secs(60),
            10.0, // aggressive multiplier
            Duration::from_secs(300), // 5 min cap
            10,
        );
        // Without cap: attempt 3 would be 60*10 = 600s, but capped at 300s
        assert_eq!(sched.delay_for_attempt(3), Duration::from_secs(300));
    }

    #[test]
    fn give_up_logic() {
        let sched = RetrySchedule::new(
            Duration::from_secs(10),
            1.0,
            Duration::from_secs(60),
            5,
        );
        assert!(!sched.should_give_up(1));
        assert!(!sched.should_give_up(4));
        assert!(sched.should_give_up(5));
        assert!(sched.should_give_up(10));
    }
}
