// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Error-budget configuration — the YAML face of the kill-switch budgets.
//!
//! The running budgets (`ErrorBudgetConfig`, `CapabilityErrorBudgetConfig`)
//! carry `Duration`s and no serde, and every field has a default that has been
//! shipping. This section is therefore all-`Option`: a key that is absent keeps
//! today's value, and only the keys the operator wrote override anything
//! (GH #475).

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::kill_switch::budget::{CapabilityErrorBudgetConfig, ErrorBudgetConfig};

/// Largest accepted sliding window, in calls.
///
/// The window is a `VecDeque` of samples per backend and per capability, so an
/// unbounded value is an allocation an operator typo can ask for. `100_000` calls
/// is far past any window that still reacts in useful time.
const MAX_WINDOW_SIZE: usize = 100_000;

/// Operator-facing `error_budget:` section.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ErrorBudgetSection {
    /// Backend failure-rate threshold that triggers auto-kill, in (0.0, 1.0].
    pub threshold: Option<f64>,
    /// Number of calls in the backend sliding window.
    pub window_size: Option<usize>,
    /// Maximum age of calls in the backend sliding window (e.g. `"5m"`).
    #[serde(with = "crate::config::humantime_serde::option")]
    pub window_duration: Option<Duration>,
    /// Minimum calls in the window before the backend budget is evaluated.
    pub min_samples: Option<usize>,
    /// Per-capability overrides.
    pub capability: CapabilityErrorBudgetSection,
}

/// Operator-facing `error_budget.capability:` sub-section.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct CapabilityErrorBudgetSection {
    /// Per-capability failure-rate threshold, in (0.0, 1.0].
    pub threshold: Option<f64>,
    /// Number of calls in the per-capability sliding window.
    pub window_size: Option<usize>,
    /// Maximum age of calls in the per-capability sliding window.
    #[serde(with = "crate::config::humantime_serde::option")]
    pub window_duration: Option<Duration>,
    /// Minimum calls before the per-capability budget is evaluated.
    pub min_samples: Option<usize>,
    /// How long a disabled capability stays offline before auto-recovering.
    #[serde(with = "crate::config::humantime_serde::option")]
    pub cooldown: Option<Duration>,
}

/// The four checks every level shares, run against MERGED values.
///
/// Merged, not raw `Option`s: `min_samples: 60` alone is reachable against the
/// backend's default window of 100 and unreachable against the capability's
/// default of 50, so a check that skips when its partner key is absent misses
/// exactly the nested case.
fn validate_window(
    prefix: &str,
    threshold: f64,
    window_size: usize,
    window_duration: Duration,
    min_samples: usize,
) -> Result<()> {
    // `!(0.0 < t <= 1.0)` rather than `t <= 0.0 || t > 1.0`: NaN compares false
    // to everything, so the second spelling accepts `.nan` and the budget then
    // never fires.
    if !(threshold > 0.0 && threshold <= 1.0) {
        return Err(Error::ConfigValidation(format!(
            "{prefix}.threshold must be in (0.0, 1.0]; got {threshold} — a threshold outside that \
             range either kills on the first failure or can never be reached"
        )));
    }
    if window_size == 0 || window_size > MAX_WINDOW_SIZE {
        return Err(Error::ConfigValidation(format!(
            "{prefix}.window_size must be between 1 and {MAX_WINDOW_SIZE}; got {window_size}"
        )));
    }
    if window_duration.is_zero() {
        return Err(Error::ConfigValidation(format!(
            "{prefix}.window_duration must be non-zero; a zero-length window expires every sample \
             before it is counted"
        )));
    }
    if min_samples == 0 {
        return Err(Error::ConfigValidation(format!(
            "{prefix}.min_samples must be at least 1; got 0"
        )));
    }
    if min_samples > window_size {
        return Err(Error::ConfigValidation(format!(
            "{prefix}.min_samples ({min_samples}) exceeds {prefix}.window_size ({window_size}); \
             the window can never hold enough samples for the budget to be evaluated"
        )));
    }
    Ok(())
}

impl ErrorBudgetSection {
    /// The backend budget this section asks for, field-by-field over today's
    /// defaults.
    #[must_use]
    pub fn backend_config(&self) -> ErrorBudgetConfig {
        let base = ErrorBudgetConfig::default();
        ErrorBudgetConfig {
            threshold: self.threshold.unwrap_or(base.threshold),
            window_size: self.window_size.unwrap_or(base.window_size),
            window_duration: self.window_duration.unwrap_or(base.window_duration),
            min_samples: self.min_samples.unwrap_or(base.min_samples),
        }
    }

    /// The per-capability budget this section asks for.
    #[must_use]
    pub fn capability_config(&self) -> CapabilityErrorBudgetConfig {
        let base = CapabilityErrorBudgetConfig::default();
        let c = &self.capability;
        CapabilityErrorBudgetConfig {
            threshold: c.threshold.unwrap_or(base.threshold),
            window_size: c.window_size.unwrap_or(base.window_size),
            window_duration: c.window_duration.unwrap_or(base.window_duration),
            min_samples: c.min_samples.unwrap_or(base.min_samples),
            cooldown: c.cooldown.unwrap_or(base.cooldown),
        }
    }

    /// Reject a section that would silently disable the kill switch.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigValidation`] naming the first offending field.
    pub fn validate(&self) -> Result<()> {
        let backend = self.backend_config();
        validate_window(
            "error_budget",
            backend.threshold,
            backend.window_size,
            backend.window_duration,
            backend.min_samples,
        )?;

        let capability = self.capability_config();
        validate_window(
            "error_budget.capability",
            capability.threshold,
            capability.window_size,
            capability.window_duration,
            capability.min_samples,
        )?;
        if capability.cooldown.is_zero() {
            return Err(Error::ConfigValidation(
                "error_budget.capability.cooldown must be non-zero; a zero cooldown re-enables a \
                 disabled capability on its very next call"
                    .to_string(),
            ));
        }
        Ok(())
    }
}
