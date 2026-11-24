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
        not(any(test, feature = "webui")),
        expect(dead_code, reason = "passed by the web UI's key create")
    )]
    HoldForRestart,
}

/// The reload a written replacement ended with.
#[derive(Debug)]
pub(crate) enum ReplaceReload {
    /// The reload accepted the new bytes.
    Applied(
        #[cfg_attr(
            not(any(test, feature = "webui")),
            expect(
                dead_code,
                reason = "read by the web UI routes that write gateway.yaml"
            )
        )]
        ReloadOutcome,
    ),
    /// The reload refused the bytes only for the status change; they stay on
    /// disk and a restart applies them. `keys` are the waiting keys' names.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the routes answer by the variant; its fields are the tests' to read"
        )
    )]
    HeldForRestart { refusal: String, keys: Vec<String> },
}

/// Whether a candidate is a first key that only a restart can apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Waiting {
    /// The status rule accepts the candidate.
    No,
    /// The status rule refuses it, it adds keys the running table lacks, those
    /// keys build, and a start from it is not refused. `keys` is never empty;
    /// `status` is the status rule's own sentence, so no caller asks it again.
    // `status` is never shown: only the derived `PartialEq` reads it, which
    // keeps it out of every refusal, ledger and route text (a source pin).
    Yes { keys: Vec<String>, status: String },
    /// The status rule refuses it and some other check fails as well; the text
    /// is that check's own, and `cause` says which check, so no caller reads
    /// the text to tell them apart.
    Faulty { reason: String, cause: FaultCause },
}

/// Which check a faulty candidate failed, first failure winning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FaultCause {
    /// Its key table does not build on the running auth settings.
    KeyTable,
    /// A start from it would be refused.
    Start,
    /// It changes the status without adding a key: a removal only.
    RemovalOnly,
}

/// The keys `config` holds that the published key table lacks, in file
/// order: what a restart from `config` would bring in.
pub(crate) fn waiting_names(published: &Generation, config: &Config) -> Vec<String> {
    let held: std::collections::BTreeSet<&str> = (published.config().auth.api_keys.iter())
        .map(|key| key.name.as_str())
        .collect();
    (config.auth.api_keys.iter())
        .filter(|key| !held.contains(key.name.as_str()))
        .map(|key| key.name.clone())
        .collect()
}

/// A key list that only removes keys yet changes the multi-user status.
const REMOVAL_ONLY: &str = "this change to auth.api_keys would change whether the gateway is \
     multi-user, which a running gateway never does.";

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
            cause: FaultCause::KeyTable,
        };
    }
    if let Some(reason) = crate::gateway::next_start_refusal(candidate) {
        return Waiting::Faulty {
            reason,
            cause: FaultCause::Start,
        };
    }
    let keys = waiting_names(published, candidate);
    if keys.is_empty() {
        // A change that only removes keys: its own sentence, never the
        // rule's, which would say the change applies at a restart.
        Waiting::Faulty {
            reason: REMOVAL_ONLY.to_owned(),
            cause: FaultCause::RemovalOnly,
        }
    } else {
        Waiting::Yes { keys, status }
    }
}

/// The waiting keys of a restart-pending answer. Built only in this module,
/// by [`restart_pending_decision`] and [`restart_pending_guard`], so every
/// such answer names the keys the file holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WaitingKeys(Vec<String>);

impl WaitingKeys {
    /// The names, in file order.
    #[cfg_attr(
        not(any(test, feature = "webui")),
        expect(dead_code, reason = "read by the web UI's shared 409")
    )]
    pub(crate) fn names(&self) -> &[String] {
        &self.0
    }
}

/// What the shared decision answers for a write that does not hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Decision {
    /// Refused as restart pending, naming the file's waiting keys.
    Pending(WaitingKeys),
    /// Refused as invalid, for this reason.
    Invalid(KeyListRefusal),
    /// Not this decision's case: the caller goes on.
    Continue,
}

/// A key list refused for a reason this module states in its own fixed
/// sentence, which a route may show as it is: it names no value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyListRefusal {
    /// It only removes keys, yet changes whether the gateway is multi-user.
    RemovalOnly,
    /// It brings in an API key on a file in which none waits.
    OnlyCreateAdds,
}

impl KeyListRefusal {
    /// The fixed sentence for this reason.
    pub(crate) fn sentence(self) -> &'static str {
        match self {
            Self::RemovalOnly => REMOVAL_ONLY,
            Self::OnlyCreateAdds => ONLY_THE_CREATE_ADDS,
        }
    }
}

/// A candidate that would bring in an API key, on a file in which none
/// waits: only the create may write such a key.
const ONLY_THE_CREATE_ADDS: &str = "this change would add an API key that makes the gateway \
     multi-user, which only creating the key can do; nothing was written";

/// The shared decision on a candidate written without a hold, from the
/// question's answer on it and the file's waiting keys as read under the
/// config lock. A `Yes` on a file whose keys wait is restart pending naming
/// those keys: nothing was written, so they are what still waits. A `Yes` on
/// a file with none is no restart-pending answer, since those bytes were
/// never written. Every other answer is the caller's.
pub(crate) fn restart_pending_decision(candidate: &Waiting, file_waiting: Vec<String>) -> Decision {
    match candidate {
        Waiting::Yes { .. } if file_waiting.is_empty() => {
            Decision::Invalid(KeyListRefusal::OnlyCreateAdds)
        }
        Waiting::Yes { .. } => Decision::Pending(WaitingKeys(file_waiting)),
        Waiting::No | Waiting::Faulty { .. } => Decision::Continue,
    }
}

/// The create's guard, asked of the file as read rather than of the file
/// with the new key: restart pending when a key already waits in it, even in
/// a file a later hand edit broke. A file whose answer is `No` is never
/// pending, whatever names it holds: a key added by hand to a multi-user
/// gateway is no first key.
#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(dead_code, reason = "asked by the web UI's key create")
)]
pub(crate) fn restart_pending_guard(
    file: &Waiting,
    file_waiting: Vec<String>,
) -> Option<WaitingKeys> {
    match file {
        Waiting::Yes { .. } => Some(WaitingKeys(file_waiting)),
        Waiting::Faulty { .. } if !file_waiting.is_empty() => Some(WaitingKeys(file_waiting)),
        Waiting::No | Waiting::Faulty { .. } => None,
    }
}

/// The reload's refusal of a file whose only fault is a first key: the keys
/// by name, and that a running gateway never changes its multi-user status.
/// No restart claim: a later edit could stop the file from starting.
pub(crate) fn held_refusal(keys: &[String]) -> String {
    format!(
        "{} the API keys listed in auth.api_keys ({}) would switch this gateway between \
         single-user and multi-user, and a gateway never switches while it runs; nothing \
         was published",
        super::POSTURE_REFUSED_PREFIX,
        keys.join(", ")
    )
}

/// Why a `Refuse` write was stopped by the shared decision: the waiting keys
/// by name, and that nothing was written.
pub(crate) fn pending_reason(waiting: &WaitingKeys) -> String {
    format!(
        "gateway.yaml holds waiting API keys ({}); nothing was written",
        waiting.0.join(", ")
    )
}
