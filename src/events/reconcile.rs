// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The reconcile step (Family-fix MIK-7940, design r3): one function decides
//! what each subscription should be from the live inputs, and one applier
//! makes the stored rows, started keys and upstream work match it. Every
//! trigger posts a cause instead of adjusting state itself.
//!
//! This module holds the decision for backend-notification rows (design r3
//! D1a, D2, D3, D4). Webhook and REST-watch rows are held, never deleted, by
//! the existing hold judgement (D1b), which the applier runs unchanged.

use std::collections::BTreeSet;

use super::upstream::{Kind, parse_name};

/// What the reconcile wants for one stored row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Fate {
    /// Delivered to, and its source key started.
    Live,
    /// Kept, sent nothing, no key; resumes by itself (lease-bounded).
    Held,
    /// Deleted with its pending records.
    Withdrawn,
    /// Past its expiry: its key and upstream work go now, and the expiry
    /// settlement buries its records and removes it (D4).
    Expired,
}

/// The backend side of the view a pass judges under the catalogue gate.
pub(super) struct BackendView<'a> {
    /// Backends the configuration and registry hold now.
    pub present: &'a BTreeSet<String>,
    /// Present backends whose transport offers no upstream notifications.
    pub ineligible: &'a BTreeSet<String>,
    /// Whether the catalogue read behind `present` was complete.
    pub complete: bool,
}

/// The fate of a row named `name`, or `None` when it is not a backend
/// notification row (its source judges it).
pub(super) fn backend_fate(name: &str, expired: bool, view: &BackendView<'_>) -> Option<Fate> {
    let (backend, kind) = parse_name(name)?;
    if expired {
        return Some(Fate::Expired);
    }
    if !view.present.contains(backend) {
        // D1a: a complete view proves the backend gone; D2: a partial one
        // proves nothing, so the row waits for the next complete read.
        return Some(if view.complete {
            Fate::Withdrawn
        } else {
            Fate::Held
        });
    }
    // D3: an ineligible backend cannot deliver its upstream kinds; its tool
    // changes are the gateway's own and stay.
    if view.ineligible.contains(backend) && kind != Kind::ToolsChanged {
        return Some(Fate::Withdrawn);
    }
    Some(Fate::Live)
}

#[cfg(test)]
#[path = "reconcile_tests.rs"]
mod tests;
