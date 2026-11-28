// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What one call's gates note for the web UI's counters, and the
//! meta writer's counting step, which runs beside its "counted before the log
//! check" step so a gateway with no audit log counts the same calls.

use serde_json::Value;

use super::{DispatchNotes, note};
use crate::counters::Outcome;
use crate::gateway::meta_mcp::MetaMcp;
use crate::security::audit::{AuditOutcome, AuditWho};

/// The gates' notes for the counters.
#[derive(Debug, Default)]
pub(super) struct CountNotes {
    /// An idempotency replay of an answer its first call delivered.
    replay: bool,
    /// Answered by the gateway's response cache.
    cache_hit: bool,
    /// Refused by the request firewall.
    request_firewall: bool,
}

/// This call replays an answer its first call delivered.
pub(crate) fn note_replay() {
    note(|notes| notes.counting.replay = true);
}

/// This call is answered by the gateway's response cache.
pub(crate) fn note_cache_hit() {
    note(|notes| notes.counting.cache_hit = true);
}

/// This call is refused by the request firewall.
#[cfg(feature = "firewall")]
pub(crate) fn note_request_firewall() {
    note(|notes| notes.counting.request_firewall = true);
}

impl DispatchNotes {
    /// How this call moves the counters, given the outcome its record carries
    /// and whether a firewall refused it.
    pub(crate) const fn counted(&self, outcome: AuditOutcome, firewall: bool) -> Outcome {
        if self.counting.replay {
            return Outcome::Replay;
        }
        Outcome::Audited {
            outcome,
            firewall: firewall || self.counting.request_firewall,
            cache_hit: self.counting.cache_hit,
        }
    }
}

impl MetaMcp {
    /// Count the call `args` names, made by `caller`; `firewall`: a firewall refused its answer.
    /// `class` is the outcome its record carries; `None` counts nothing.
    pub(super) fn count_invocation(
        &self,
        args: &Value,
        caller: &AuditWho,
        firewall: bool,
        notes: &DispatchNotes,
        class: Option<AuditOutcome>,
    ) {
        let Some(outcome) = class else {
            return;
        };
        self.count_call(
            args.get("server")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            args.get("tool").and_then(Value::as_str),
            caller,
            notes.counted(outcome, firewall),
            notes.backend_sample(),
        );
    }
}
