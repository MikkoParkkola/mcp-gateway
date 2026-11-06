// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How a composite's end marks its cell: refused only when it fails on a
//! refused step, keeping that step's record trace and code for the
//! settlement record ([`super::step`]).

use serde_json::Value;

use super::{LastStep, ResponseEffect, forget_last_step, with, worst};

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

/// The composite ends as `end`. It records `refused` when it fails while its
/// latest step's refusal still stands: the step it ends on was refused. That
/// step's record trace and code are kept then, and dropped otherwise ([`super::step`]).
pub(crate) fn composite_ended(end: CompositeEnd) {
    with(|facts| {
        if end == CompositeEnd::Failed && facts.last_step == LastStep::Refused {
            facts.effect = facts.effect.max(ResponseEffect::Refused);
            // The refusing gate's own code, which the plan's wrapper error
            // would otherwise replace in the settlement record.
            if let Some(code) = facts.last_step_withheld.take() {
                facts.withheld_code = Some(code);
            }
        } else {
            forget_last_step(facts);
        }
        // A composite that fails ends on its latest step's fold; one that
        // succeeds carries only the failures it reported.
        let ended_on = facts.last_step_folded.take();
        if end == CompositeEnd::Failed {
            facts.folded = worst(facts.folded, ended_on);
        }
    });
}
