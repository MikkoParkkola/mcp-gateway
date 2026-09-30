// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Cross-tenant data-minimisation guard (MIK-7116.TENANT.1).
//!
//! Refuses a caller that reaches across more customers in a short span than
//! its work plausibly requires. One tenant at a time is ordinary; twenty in a
//! minute is a caller enumerating a customer table, whatever it was asked to
//! do.
//!
//! # Why the principal, not the session
//!
//! The requirement was written as "within one session". Under a stateless
//! transport there is no session to be within: each request is its own, so
//! every request carries exactly one tenant and the limit is never reached.
//! That guard would pass every test that asserts an *allow* and fail nothing —
//! which is why every acceptance test for this control asserts a *refusal*.
//! The counting key is therefore the authenticated principal, and the span is
//! an explicit window ([`crate::security::firewall::principal_window`]).

use std::collections::BTreeSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::principal_window::{PrincipalWindow, Usage};

/// What the guard decided about one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantVerdict {
    /// Proceed: no tenant identifiers, or a caller still inside its span.
    Allowed,
    /// Refuse: this principal has reached across too many tenants.
    Refused {
        /// Distinct tenants this principal has touched inside the window.
        distinct: usize,
        /// The configured ceiling that was exceeded.
        limit: usize,
    },
    /// Refuse: tenant data was requested by nobody in particular.
    ///
    /// Distinct from [`Self::Refused`] because the reasons differ and the
    /// operator response differs: a refusal means a caller went too wide, this
    /// means the request carried no identity to hold responsible. Counting
    /// unattributed requests together would let the busiest anonymous caller
    /// spend everyone else's allowance; counting them separately is a limit of
    /// one per caller that never binds. Neither is a budget, so neither is
    /// offered.
    Unattributable,
}

/// Tenant-guard policy. Disabled unless switched on.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TenantGuardConfig {
    /// Whether the guard may refuse a request. Tenant attribution in the audit
    /// logs (MIK-7116.MIN.1) runs whenever `arg_keys` is set, even when this
    /// is `false`: the observe-only rollout.
    pub enabled: bool,
    /// Distinct tenants one principal may touch inside the window.
    pub max_tenants_per_window: usize,
    /// How long a tenant observation counts against its principal.
    pub window_secs: u64,
    /// Argument keys whose values name a tenant, at any nesting depth. The
    /// same keys attribute tool results (text-JSON included) to tenants in
    /// the audit logs, hashed, never raw.
    pub arg_keys: Vec<String>,
}

impl Default for TenantGuardConfig {
    /// Disabled, with a limit and window that apply only once switched on.
    ///
    /// Off by default because a wrong `arg_keys` list on an existing
    /// deployment refuses legitimate traffic, and a security control that
    /// arrives unannounced as an outage does not stay switched on.
    fn default() -> Self {
        Self {
            enabled: false,
            max_tenants_per_window: 3,
            window_secs: 300,
            arg_keys: Vec::new(),
        }
    }
}

/// Largest `content[].text` block [`TenantGuard::response_tenants`] parses.
const MAX_PARSED_TEXT_BYTES: usize = 1024 * 1024;

/// Per-principal cross-tenant reach limiter.
pub struct TenantGuard {
    config: TenantGuardConfig,
    seen: PrincipalWindow,
}

impl TenantGuard {
    /// Build a guard from policy.
    #[must_use]
    pub fn new(config: TenantGuardConfig) -> Self {
        let seen = PrincipalWindow::new(Duration::from_secs(config.window_secs));
        Self { config, seen }
    }

    /// Judge one request's arguments on behalf of `principal`.
    ///
    /// Records the tenants named in `args` and reports whether this principal
    /// has now reached across more of them than the policy allows.
    pub fn check(&self, principal: Option<&str>, args: &Value) -> TenantVerdict {
        if !self.config.enabled {
            return TenantVerdict::Allowed;
        }

        let mut tenants = Vec::new();
        self.collect(args, &mut tenants);
        if tenants.is_empty() {
            // No tenant data in play, so nothing to minimise — including when
            // the caller is anonymous. An unattributable *non-tenant* request
            // is an ordinary request.
            return TenantVerdict::Allowed;
        }

        let mut verdict = TenantVerdict::Allowed;
        for tenant in tenants {
            match self.seen.record(principal, &tenant) {
                Usage::Unkeyed => return TenantVerdict::Unattributable,
                Usage::Counted { distinct, .. }
                    if distinct > self.config.max_tenants_per_window =>
                {
                    verdict = TenantVerdict::Refused {
                        distinct,
                        limit: self.config.max_tenants_per_window,
                    };
                }
                Usage::Counted { .. } => {}
            }
        }
        verdict
    }

    /// The tenants a request names, under the configured `arg_keys`, with the
    /// guard's own walk. Pure: it records nothing, so attribution never counts
    /// against the guard, and it runs whether or not the guard may refuse.
    pub(crate) fn request_tenants(&self, args: &Value) -> BTreeSet<String> {
        let mut tenants = Vec::new();
        self.collect(args, &mut tenants);
        tenants.into_iter().collect()
    }

    /// The tenants a tool result names: the request walk over the result, plus
    /// every `content[].text` block that parses as JSON, which is how most
    /// backends return rows. Pure, like [`Self::request_tenants`].
    pub(crate) fn response_tenants(&self, result: &Value) -> BTreeSet<String> {
        if self.config.arg_keys.is_empty() {
            return BTreeSet::new();
        }
        let mut tenants = Vec::new();
        self.collect(result, &mut tenants);
        let texts = result
            .get("content")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|block| block.get("text").and_then(Value::as_str));
        for text in texts {
            // ponytail: a text block over 1 MiB is not parsed (an attribution
            // miss); response inspection already scans the same text.
            if text.len() > MAX_PARSED_TEXT_BYTES {
                continue;
            }
            if let Ok(parsed @ (Value::Object(_) | Value::Array(_))) = serde_json::from_str(text) {
                self.collect(&parsed, &mut tenants);
            }
        }
        tenants.into_iter().collect()
    }

    /// Gather every value under a configured tenant key, at any depth.
    ///
    /// Recursive because tenant identifiers arrive nested — a `customer_id`
    /// inside a `filter` object is the same reach as one at the top level, and
    /// a guard that inspects only the top level is evaded by wrapping the
    /// argument in an object.
    fn collect(&self, value: &Value, out: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    if self.config.arg_keys.iter().any(|k| k == key)
                        && let Some(tenant) = Self::tenant_name(child)
                    {
                        out.push(tenant);
                        continue;
                    }
                    self.collect(child, out);
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.collect(item, out);
                }
            }
            _ => {}
        }
    }

    /// Render a tenant identifier as a string, if the value is one.
    ///
    /// Strings and numbers both name tenants in practice. A structure under a
    /// tenant key is not an identifier, and is recursed into instead.
    fn tenant_name(value: &Value) -> Option<String> {
        match value {
            Value::String(s) if !s.is_empty() => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "tenant_attribution_tests.rs"]
mod attribution_tests;
