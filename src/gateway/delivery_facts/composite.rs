// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How a composite ended, as [`super::composite_ended`] reads it, and the
//! step-trace bookkeeping that end keeps or drops.

use serde_json::Value;

use super::{DeliveryFacts, with};

/// How a composite ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompositeEnd {
    Succeeded,
    /// In an error, or a tool error result.
    Failed,
}

impl CompositeEnd {
    /// `Failed` for an error or a tool error result (`isError: true`).
    pub(crate) fn of(result: &crate::Result<Value>) -> Self {
        match result {
            Ok(answer) if !crate::protocol::cacheable::is_error(answer) => Self::Succeeded,
            _ => Self::Failed,
        }
    }

    /// `Failed` for an error: a composite whose output is not a tool result.
    #[cfg(test)]
    pub(crate) fn of_outcome<T>(result: &crate::Result<T>) -> Self {
        if result.is_err() {
            Self::Failed
        } else {
            Self::Succeeded
        }
    }
}

/// The open step cell's step wrote its record under `trace`: the trace a
/// composite settlement joins when the plan ends refused on this step.
pub(crate) fn note_step_trace(trace: &str) {
    with(|facts| facts.noted_trace = Some(trace.into()));
}

/// Forget the latest step's record trace and code: what the composite can
/// end on is no longer that step.
pub(super) fn forget_last_step(facts: &mut DeliveryFacts) {
    facts.last_step_trace = None;
    facts.last_step_withheld = None;
}
