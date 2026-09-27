// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! S1-S4 stage methods (design doc `2026-09-27-direct-route-guards.md` §2.1):
//! one control implementation per stage, in `MetaMcp`, at the lifecycle stage
//! each already runs today. Red-commit stubs only (MIK-7597); no call site
//! wires them in yet, so every method is unused until the fix commit.
#![allow(dead_code)]

use crate::Result;
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::JsonRpcResponse;

/// The direct-route shape of a dispatch, carrying what each stage needs to
/// identify the call without reaching back into the HTTP request (design doc
/// §2.1: `server` is the `{name}` path segment, `tool` is `params.name`).
pub(crate) struct BackendCall<'a> {
    pub server: &'a str,
    pub tool: &'a str,
    pub session_id: Option<&'a str>,
    pub api_key_name: Option<&'a str>,
    pub trace_id: &'a str,
}

/// The direct-route classification of a completed dispatch, feeding S3
/// accounting and S4 payload gating (design doc §2.1a). `spend` marks
/// whether the call is eligible for spend recording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectOutcome {
    Success {
        spend: bool,
    },
    Failure {
        spend: bool,
    },
    IgnoredRateLimit {
        spend: bool,
    },
    /// Sentinel: matches no row of the adapter table, so every
    /// classification assertion in the red commit fails on this stub
    /// (test plan "Red commit": "the sentinel stub matches no row").
    Unclassified,
}

impl DirectOutcome {
    /// Stub classifier (design doc §2.1a). Always returns the sentinel until
    /// the fix commit implements the adapter table.
    pub(crate) fn from_response(r: &Result<JsonRpcResponse>) -> Self {
        let _ = r;
        Self::Unclassified
    }
}

/// The six controls one implementation each replaces (design doc §2.1 table).
pub(crate) const DISPATCH_CONTROLS: &[&str] = &[
    "kill_switch",
    "capability_disable",
    "session_profile",
    "cost_budget",
    "error_budget",
    "response_gates",
];

// Red-commit stubs: every stage ignores `self` and always succeeds until the
// fix commit wires in the real control. `unnecessary_wraps` is not applicable
// to `account_dispatch`, whose signature has no `Result`; the attribute is
// harmless where it doesn't fire.
#[allow(clippy::unused_self, clippy::unnecessary_wraps)]
impl MetaMcp {
    /// S1 policy: kill switch, capability disable, session profile.
    pub(crate) fn admit_target(&self, call: &BackendCall<'_>) -> Result<()> {
        let _ = call;
        Ok(())
    }

    /// S2 spend: budget admission immediately before dispatch.
    pub(crate) fn admit_spend_for(&self, call: &BackendCall<'_>) -> Result<Vec<String>> {
        let _ = call;
        Ok(Vec::new())
    }

    /// S3 accounting: error budget and spend recording, at completion.
    pub(crate) fn account_dispatch(&self, call: &BackendCall<'_>, outcome: DirectOutcome) {
        let _ = (call, outcome);
    }

    /// S4 payload: response gates on a successful result.
    pub(crate) fn gate_payload(
        &self,
        call: &BackendCall<'_>,
        value: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let _ = call;
        Ok(value)
    }
}

#[cfg(test)]
#[path = "dispatch_guards_tests.rs"]
mod dispatch_guards_tests;
