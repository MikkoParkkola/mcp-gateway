// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Direct-route guard chain (design doc `2026-09-27-direct-route-guards.md`
//! §2.1a), reconciled with the meta-route chain at §2.2. Red-commit
//! pass-through stubs only (MIK-7597); no call site wires these into
//! `backend_handlers.rs` yet.
#![allow(dead_code)]

use crate::Result;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::invoke::dispatch_guards::{BackendCall, DirectOutcome};

/// Namespace for the direct-route stage calls; a unit type rather than free
/// functions so call sites read `DirectRouteGuards::before_dispatch(..)`
/// alongside the `MetaMcp` stage methods it wraps.
pub(crate) struct DirectRouteGuards;

// Red-commit stubs: every stage is a pass-through until the fix commit wires
// in `dispatch_guards`.
#[allow(clippy::unnecessary_wraps)]
impl DirectRouteGuards {
    /// S1 policy, run before idempotency, cache and nonce. Pass-through stub.
    pub(crate) fn run(meta: &MetaMcp, call: &BackendCall<'_>) -> Result<()> {
        let _ = (meta, call);
        Ok(())
    }

    /// S2 spend, run once immediately before an actual backend dispatch.
    /// Pass-through stub.
    pub(crate) fn before_dispatch(meta: &MetaMcp, call: &BackendCall<'_>) -> Result<Vec<String>> {
        let _ = (meta, call);
        Ok(Vec::new())
    }

    /// S3 accounting and S4 payload gating, run at dispatch completion.
    /// Pass-through stub.
    pub(crate) fn after_dispatch(
        meta: &MetaMcp,
        call: &BackendCall<'_>,
        outcome: DirectOutcome,
        value: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let _ = (meta, call, outcome);
        Ok(value)
    }
}
