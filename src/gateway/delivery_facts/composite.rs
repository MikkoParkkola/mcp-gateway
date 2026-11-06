// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How a composite ended, as [`super::composite_ended`] reads it.

use serde_json::Value;

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
