// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The first API key on a single-user gateway. A gateway never changes
//! between single-user and multi-user while running (ADR-008); this module is
//! the one place that decides whether a write may still keep a file whose only
//! fault is that change, which a restart then applies.

use super::{Generation, ReloadOutcome};
use crate::config::{Config, EnvOverlay};

/// What the guarded writer does with a candidate whose reload would change
/// the gateway between single-user and multi-user. Every write names one:
/// there is no default, so a caller that could hold bytes is visible here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StatusChange {
    /// Refused before anything is written, as before this module existed.
    Refuse,
    /// Kept on disk for the next start when the candidate only waits for a
    /// restart (see [`waiting_first_key`]); the first-key create alone.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the create route passes it once the hold lands")
    )]
    HoldForRestart,
}

/// The reload a written replacement ended with.
#[derive(Debug)]
pub(crate) enum ReplaceReload {
    /// The reload accepted the new bytes.
    Applied(ReloadOutcome),
    /// The reload refused the bytes only for the status change; they stay on
    /// disk and a restart applies them. `keys` are the waiting keys' names.
    #[cfg_attr(not(test), expect(dead_code, reason = "the create route reads it"))]
    HeldForRestart { refusal: String, keys: Vec<String> },
}

/// Whether a candidate is a first key that only a restart can apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Waiting {
    /// The status rule accepts the candidate.
    No,
    /// The status rule refuses it, it adds keys the running table lacks, those
    /// keys build, and a start from it is not refused. Never empty.
    Yes { keys: Vec<String> },
    /// The status rule refuses it and some other check fails as well; the text
    /// is that check's own.
    Faulty { reason: String },
}

/// The one question every writer, reload and route asks about a candidate.
///
/// Checked in this order, the first failure winning, so a file with two
/// faults is reported by its real fault and never told to restart: the key
/// table builds on the running auth settings (resolution, collisions); a
/// start from the candidate is not refused; it adds at least one key. The key
/// table is built directly rather than through `Generation::prepare`, which
/// would ask the status rule again.
pub(crate) fn waiting_first_key(
    running: &Config,
    published: &Generation,
    candidate: &Config,
    overlay: &EnvOverlay,
) -> Waiting {
    let Err(status) = super::refuse_multi_user_flip(running, &candidate.auth) else {
        return Waiting::No;
    };
    if let Err(e) = published.auth().with_keys_of(&candidate.auth, overlay) {
        return Waiting::Faulty {
            reason: format!("auth.api_keys: {e}"),
        };
    }
    if let Some(reason) = crate::gateway::next_start_refusal(candidate) {
        return Waiting::Faulty { reason };
    }
    let held: std::collections::BTreeSet<&str> = (published.config().auth.api_keys.iter())
        .map(|key| key.name.as_str())
        .collect();
    let keys: Vec<String> = (candidate.auth.api_keys.iter())
        .filter(|key| !held.contains(key.name.as_str()))
        .map(|key| key.name.clone())
        .collect();
    if keys.is_empty() {
        // A change that only removes keys: the existing refusal, unchanged.
        Waiting::Faulty { reason: status }
    } else {
        Waiting::Yes { keys }
    }
}
