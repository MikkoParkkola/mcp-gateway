// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Render-guard non-bypassability (MIK-5854 / MIK-6690).
//!
//! `GuardedValue` wraps a tool result that has passed the context-integrity
//! render guard. Its inner field is private to this module, so the ONLY ways to
//! obtain one are the two named, greppable constructors below. Because
//! `MetaMcp::invoke_tool_traced` returns `Result<GuardedValue>`, the compiler
//! rejects any `return Ok(...)` that has not produced a `GuardedValue` — a
//! future code path cannot emit un-guarded tool content from the chokepoint
//! without consciously calling one of these constructors (which review/grep
//! will catch).

use std::sync::Arc;

use crate::protocol::{ChainSource, UpstreamChain};
use serde_json::Value;

type Upstream = Option<Arc<UpstreamChain>>;

/// A tool result that has passed (or is exempt from) the render guard,
/// with its chain eligibility (A3: `NotEligible` unless marked `backend`) and
/// the upstream chain outcome a chained backend's answer carries (inc3 D4).
pub(super) struct GuardedValue(Value, ChainSource, Upstream);

impl GuardedValue {
    /// Seal a value that has just been through `apply_context_integrity`.
    /// Call this ONLY immediately after the guard runs on live dispatch.
    pub(super) fn sealed_by_guard(value: Value) -> Self {
        Self(value, ChainSource::NotEligible, None)
    }

    /// Seal a cached value: guarded at store time, never chain-eligible. The
    /// call is noted as a cached delivery (MIK-7116.MIN.1).
    pub(super) fn from_cache(value: Value) -> Self {
        super::audit::note_cached();
        Self(value, ChainSource::NotEligible, None)
    }

    /// Mark a live MCP-backend answer that every gate passed through, with
    /// its upstream chain outcome when the backend is chained.
    #[must_use]
    pub(super) fn backend(self, upstream: Upstream) -> Self {
        Self(self.0, ChainSource::Backend, upstream)
    }

    /// Apply gateway-authored, non-content augmentation (trace id,
    /// predictions, cost warnings, signature) while preserving guard status.
    /// The closure must only add gateway metadata, never new tool content.
    #[must_use]
    pub(super) fn augment(self, f: impl FnOnce(Value) -> Value) -> Self {
        Self(f(self.0), self.1, self.2)
    }

    /// Unwrap at the single delivery boundary.
    pub(super) fn into_parts(self) -> (Value, ChainSource, Upstream) {
        (self.0, self.1, self.2)
    }
}
