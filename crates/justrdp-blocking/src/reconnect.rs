#![forbid(unsafe_code)]

//! Reconnection policy for the Auto-Reconnect runtime (roadmap §9.2).
//!
//! The state machine and HMAC-MD5 SecurityVerifier computation live in
//! `justrdp-connector`. This module defines the runtime-side retry policy
//! that the blocking layer will consult when a session drops.
//!
//! *Scaffold: policy is defined but not yet wired into [`crate::RdpClient`].*

use core::time::Duration;

/// Controls when and how often the blocking runtime retries after a drop.
#[derive(Debug, Clone)]
pub struct ReconnectPolicy {
    /// Maximum number of reconnect attempts before giving up. `0` disables
    /// automatic reconnect entirely.
    pub max_attempts: u32,
    /// Initial delay between the drop and the first reconnect attempt.
    pub initial_delay: Duration,
    /// Maximum delay between attempts (cap for exponential backoff).
    pub max_delay: Duration,
    /// Multiplier applied to the delay after each failed attempt.
    /// A value of `1.0` produces constant-interval retries.
    pub backoff: f32,
}

impl ReconnectPolicy {
    /// Disable automatic reconnect (default for now).
    pub fn disabled() -> Self {
        Self {
            max_attempts: 0,
            initial_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
            backoff: 1.0,
        }
    }

    /// Sensible default: up to 5 attempts with 1s / 2s / 4s / 8s / 10s backoff.
    pub fn aggressive() -> Self {
        Self {
            max_attempts: 5,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(10),
            backoff: 2.0,
        }
    }

    /// Compute the delay before the Nth attempt (1-indexed).
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }
        let mut delay = self.initial_delay.as_secs_f32();
        for _ in 1..attempt {
            delay *= self.backoff;
        }
        let capped = delay.min(self.max_delay.as_secs_f32());
        Duration::from_secs_f32(capped)
    }
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self::disabled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_has_zero_attempts() {
        let p = ReconnectPolicy::disabled();
        assert_eq!(p.max_attempts, 0);
        assert_eq!(p.delay_for_attempt(0), Duration::ZERO);
    }

    #[test]
    fn aggressive_backoff_doubles() {
        let p = ReconnectPolicy::aggressive();
        assert_eq!(p.delay_for_attempt(1), Duration::from_secs(1));
        assert_eq!(p.delay_for_attempt(2), Duration::from_secs(2));
        assert_eq!(p.delay_for_attempt(3), Duration::from_secs(4));
        assert_eq!(p.delay_for_attempt(4), Duration::from_secs(8));
        // capped at max_delay (10s)
        assert_eq!(p.delay_for_attempt(5), Duration::from_secs(10));
        assert_eq!(p.delay_for_attempt(10), Duration::from_secs(10));
    }

    #[test]
    fn default_is_disabled() {
        let p = ReconnectPolicy::default();
        assert_eq!(p.max_attempts, 0);
    }
}
