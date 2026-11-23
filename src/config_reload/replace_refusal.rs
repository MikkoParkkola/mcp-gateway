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
        ReloadRefusalKind::Other => RefusalClass::Internal,
        ReloadRefusalKind::StatusChange => RefusalClass::RestartPending {
            waiting: crate::config_reload::first_key::WaitingKeys::new(refusal.waiting.clone()),
        },
    }
}
