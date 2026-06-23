//! Post-deploy telemetry confirmation for the Webwright spike (MIK-5205
//! AC.deploy).
//!
//! After the diff merges to `main` and the cron builds and deploys the release
//! binary, telemetry must confirm the change is active for a sustained window
//! (30 minutes).  This module models that confirmation: active samples of the
//! `webwright-spike` signal are recorded and the window is checked.

use chrono::{DateTime, TimeDelta, Utc};

/// The branch the diff targets for the spike.
pub const DEPLOY_TARGET_BRANCH: &str = "main";

/// The minimum post-deploy observation window before the change is declared
/// active.
#[must_use]
pub fn confirmation_window() -> TimeDelta {
    TimeDelta::minutes(30)
}

/// Records post-deploy telemetry samples for a named signal and decides whether
/// the change is confirmed active.
#[derive(Debug, Clone)]
pub struct DeployTelemetry {
    signal: String,
    target_branch: String,
    samples: Vec<(DateTime<Utc>, bool)>,
}

impl DeployTelemetry {
    /// Create a telemetry recorder for `signal` targeting `main`.
    #[must_use]
    pub fn new(signal: impl Into<String>) -> Self {
        Self {
            signal: signal.into(),
            target_branch: DEPLOY_TARGET_BRANCH.to_string(),
            samples: Vec::new(),
        }
    }

    /// The signal name this recorder confirms.
    #[must_use]
    pub fn signal(&self) -> &str {
        &self.signal
    }

    /// The branch the deploy targets.
    #[must_use]
    pub fn target_branch(&self) -> &str {
        &self.target_branch
    }

    /// Record a sample: `active` is whether the signal was observed at `at`.
    pub fn record_sample(&mut self, at: DateTime<Utc>, active: bool) {
        self.samples.push((at, active));
    }

    /// The span between the first and last recorded sample.
    #[must_use]
    pub fn observed_window(&self) -> TimeDelta {
        match (self.samples.first(), self.samples.last()) {
            (Some((first, _)), Some((last, _))) => *last - *first,
            _ => TimeDelta::zero(),
        }
    }

    /// Whether the change is confirmed active: every recorded sample is active
    /// and they span at least the [`confirmation_window`].
    #[must_use]
    pub fn confirms_active(&self) -> bool {
        if self.samples.is_empty() {
            return false;
        }
        let all_active = self.samples.iter().all(|&(_, active)| active);
        all_active && self.observed_window() >= confirmation_window()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span_active(minutes: i64) -> DeployTelemetry {
        let mut t = DeployTelemetry::new("webwright-spike");
        let start = Utc::now();
        for m in (0..=minutes).step_by(5) {
            t.record_sample(start + TimeDelta::minutes(m), true);
        }
        t
    }

    #[test]
    fn thirty_minutes_of_active_samples_confirms() {
        let t = span_active(30);
        assert_eq!(t.target_branch(), "main");
        assert!(t.confirms_active());
    }

    #[test]
    fn short_window_does_not_confirm() {
        let t = span_active(10);
        assert!(!t.confirms_active());
    }

    #[test]
    fn a_single_inactive_sample_breaks_confirmation() {
        let mut t = span_active(30);
        t.record_sample(Utc::now() + TimeDelta::minutes(35), false);
        assert!(!t.confirms_active());
    }
}
