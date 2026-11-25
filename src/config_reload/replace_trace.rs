// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What one write got to: the intent it appended, whether its new bytes were
//! written and whether the original went back. Kept beside the writer.

use std::sync::atomic::{AtomicBool, Ordering};

use super::IntentId;

/// What a write got to, filled by its task as it goes and read by
/// the writer's `spawn_locked` after the join, so a task that panicked or was aborted
/// after its append still yields the intent id.
#[derive(Debug, Default)]
pub(crate) struct WriteTrace {
    pub(super) intent_id: std::sync::OnceLock<IntentId>,
    /// Set immediately before the new bytes are written; cleared again only
    /// when a write that failed before its rename is cleanly abandoned, as
    /// its bytes never reached the file (a failed cleanup leaves it set).
    pub(super) written: AtomicBool,
    /// Set when the original was put back after `written`.
    pub(super) restored: AtomicBool,
}

impl WriteTrace {
    /// The intent this write appended; a write appends one at most.
    pub(super) fn keep_intent(&self, id: IntentId) {
        let _ = self.intent_id.set(id);
    }

    pub(super) fn snapshot(&self) -> Trace {
        Trace {
            intent_id: self.intent_id.get().cloned(),
            written: self.written.load(Ordering::SeqCst),
            restored: self.restored.load(Ordering::SeqCst),
        }
    }
}

/// The plain copy of a [`WriteTrace`] a caller gets beside a refused write.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Trace {
    pub(crate) intent_id: Option<IntentId>,
    pub(crate) written: bool,
    pub(crate) restored: bool,
}
