// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Principal-keyed call budget (MIK-7215.CONTROL.2).
//!
//! Refuses a caller that has made more calls than its policy allows inside an
//! explicit window.
//!
//! # Why the principal, not the session
//!
//! The obvious implementation counts calls per `session_id`. After MCP
//! 2026-07-28 there is no session: every request is its own, so a per-session
//! counter never passes one and the budget never binds — a control that
//! reports success on every request while protecting nothing. See
//! [`crate::security::firewall::tenant_guard`] for the same defect shape in a
//! sibling control. The counting key is therefore the authenticated
//! principal, over an explicit window
//! ([`crate::security::firewall::principal_window`]).

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::principal_window::{PrincipalWindow, Usage};

/// What the guard decided about one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetVerdict {
    /// Proceed: budget disabled, or this principal is still inside its limit.
    Allowed,
    /// Refuse: this principal has exceeded its call budget for the window.
    Refused {
        /// Calls this principal has made inside the window, including this one.
        total: usize,
        /// The configured ceiling that was exceeded.
        limit: usize,
    },
    /// Refuse: a call was made by nobody in particular.
    ///
    /// Distinct from [`Self::Refused`]: counting unattributed calls together
    /// would let the busiest anonymous caller spend every anonymous caller's
    /// shared allowance, and counting them separately is a limit of one that
    /// never binds. Neither is a budget, so the caller decides instead.
    Unattributable,
}

/// Budget-guard policy. Disabled unless switched on.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BudgetGuardConfig {
    /// Whether the guard runs at all.
    pub enabled: bool,
    /// Calls one principal may make inside the window before being refused.
    pub max_calls_per_window: usize,
    /// How long a call observation counts against its principal.
    pub window_secs: u64,
}

impl Default for BudgetGuardConfig {
    /// Disabled, with a limit and window that apply only once switched on.
    ///
    /// Off by default for the same reason as every other opt-in firewall
    /// control here: a wrong limit on an existing deployment refuses
    /// legitimate traffic, and a control that arrives unannounced as an
    /// outage does not stay switched on.
    fn default() -> Self {
        Self {
            enabled: false,
            max_calls_per_window: 600,
            window_secs: 60,
        }
    }
}

/// Per-principal call-budget limiter.
pub struct BudgetGuard {
    config: BudgetGuardConfig,
    seen: PrincipalWindow,
}

impl BudgetGuard {
    /// Build a guard from policy.
    #[must_use]
    pub fn new(config: BudgetGuardConfig) -> Self {
        let seen = PrincipalWindow::new(Duration::from_secs(config.window_secs));
        Self { config, seen }
    }

    /// Judge one request on behalf of `principal`.
    ///
    /// Records the call under `server:tool` and reports whether this
    /// principal has now made more calls inside the window than the policy
    /// allows.
    pub fn check(&self, principal: Option<&str>, server: &str, tool: &str) -> BudgetVerdict {
        if !self.config.enabled {
            return BudgetVerdict::Allowed;
        }

        let key = format!("{server}:{tool}");
        match self.seen.record(principal, &key) {
            Usage::Unkeyed => BudgetVerdict::Unattributable,
            Usage::Counted { total, .. } if total > self.config.max_calls_per_window => {
                BudgetVerdict::Refused {
                    total,
                    limit: self.config.max_calls_per_window,
                }
            }
            Usage::Counted { .. } => BudgetVerdict::Allowed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled(limit: usize) -> BudgetGuardConfig {
        BudgetGuardConfig {
            enabled: true,
            max_calls_per_window: limit,
            window_secs: 60,
        }
    }

    #[test]
    fn disabled_guard_always_allows() {
        let guard = BudgetGuard::new(BudgetGuardConfig::default());
        for _ in 0..1000 {
            assert_eq!(
                guard.check(Some("principal:a"), "srv", "tool"),
                BudgetVerdict::Allowed
            );
        }
    }

    #[test]
    fn enabled_guard_refuses_once_the_limit_is_exceeded() {
        let guard = BudgetGuard::new(enabled(2));
        assert_eq!(
            guard.check(Some("principal:a"), "srv", "tool"),
            BudgetVerdict::Allowed
        );
        assert_eq!(
            guard.check(Some("principal:a"), "srv", "tool"),
            BudgetVerdict::Allowed
        );
        assert_eq!(
            guard.check(Some("principal:a"), "srv", "tool"),
            BudgetVerdict::Refused { total: 3, limit: 2 }
        );
    }

    #[test]
    fn a_call_with_no_principal_is_unattributable_not_zero() {
        let guard = BudgetGuard::new(enabled(2));
        assert_eq!(
            guard.check(None, "srv", "tool"),
            BudgetVerdict::Unattributable
        );
    }

    #[test]
    fn two_principals_do_not_share_one_budget() {
        let guard = BudgetGuard::new(enabled(1));
        assert_eq!(
            guard.check(Some("principal:a"), "srv", "tool"),
            BudgetVerdict::Allowed
        );
        // Principal A is now at its limit; principal B is unaffected.
        assert_eq!(
            guard.check(Some("principal:b"), "srv", "tool"),
            BudgetVerdict::Allowed
        );
    }
}
