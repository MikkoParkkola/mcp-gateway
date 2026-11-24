// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Typed refusal classes shared by the writer and its callers.

use super::lock_api::{ReloadRefusal, ReloadRefusalKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RefusalClass {
    Posture,
    Invalid,
    ShuttingDown,
    Internal,
    /// Keys wait in gateway.yaml for a restart and this candidate keeps them;
    /// `waiting` names them, as the shared decision found them.
    RestartPending {
        waiting: crate::config_reload::first_key::WaitingKeys,
    },
    /// The key list is refused for a reason with its own fixed sentence
    /// (the first-key question's), which a route shows as its message.
    KeyList(crate::config_reload::first_key::KeyListRefusal),
}

/// Only the typed reload refusal establishes a posture refusal.
pub(super) fn post_write_class(refusal: &ReloadRefusal) -> RefusalClass {
    use crate::config_reload::{ReloadFailure, reload_failure};
    match refusal.kind {
        ReloadRefusalKind::Posture => RefusalClass::Posture,
        ReloadRefusalKind::Other
            if reload_failure(&refusal.text) == ReloadFailure::ShuttingDown =>
        {
            RefusalClass::ShuttingDown
        }
        // A status change the check before the write did not see: the bytes it
        // judged were rolled back, so it is no restart-pending answer and its
        // sentence is not shown. A faulty first key there is the same case.
        ReloadRefusalKind::Other | ReloadRefusalKind::StatusChange | ReloadRefusalKind::Faulty => {
            RefusalClass::Internal
        }
    }
}
