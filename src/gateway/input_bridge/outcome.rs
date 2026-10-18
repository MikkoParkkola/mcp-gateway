// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How a bridged call ends: its errors, its dispatch outcome, its bounds and
//! the observation it emits.

use serde_json::Value;

use super::DeliveryError;

/// Why the whole bridged call failed.
///
/// `Debug` is written by hand (module `debug`): the last round carries the
/// backend's raw `requestState`.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BridgeError {
    /// An entry could not be put to this client at all, and nothing was sent.
    Refused {
        /// The backend's own key for the entry.
        key: String,
        /// Which refusal this is.
        reason: crate::protocol::mrtr::Refusal,
    },
    /// A request was sent and did not come back as an answer.
    Delivery {
        /// The backend's own key for the entry.
        key: String,
        /// What went wrong with it.
        error: DeliveryError,
    },
    /// The backend kept asking past the retry bound.
    ///
    /// Carries the backend's last interim body, the round the caller can still
    /// resume: its questions and its `requestState` belong together, and the
    /// first round's would replay prompts already answered (#569). `None` when
    /// no round ran, so there is nothing newer than the interim the caller holds.
    ///
    /// The round has passed the session declaration, the per-request slice
    /// and the challenge gate; an undeclared one is [`BridgeError::Undeclared`]
    /// instead (#2173).
    RoundsExhausted {
        /// The last interim result the backend returned, whole.
        last: Option<Box<Value>>,
    },
    /// The last round asks for input the session never declared.
    ///
    /// Raised instead of [`BridgeError::RoundsExhausted`], so the round is
    /// never handed to a caller that would have to check it (#2173). The
    /// fields are what an MRTR.9 refusal names.
    #[non_exhaustive]
    Undeclared {
        /// The backend's own key for the entry.
        key: String,
        /// The method the entry asked with; empty when it carried none.
        method: String,
        /// Which refusal this is.
        reason: crate::protocol::mrtr::Refusal,
    },
    /// A retry round claimed `input_required` in a shape the gateway cannot carry.
    ///
    /// Not a completed call: the backend said it stopped to ask, so nothing
    /// here proves it acted, and settling the key as completed would serve the
    /// broken body to every retry. It leaves the key on its release default,
    /// like the other refusals that end an unanswered question.
    MalformedInterim,
    /// The backend asked for more requests in total than the bound allows.
    RequestBudgetExhausted,
    /// The aggregate wall-clock budget for the call ran out.
    Deadline,
    /// A bridged retry round was refused before anything was dispatched.
    ///
    /// Kept apart from [`BridgeError::BackendFailed`] because the two settle
    /// differently: nothing ran, so the round carries no side effect to
    /// protect and the caller may retry once the refusal lifts.
    NotAdmitted {
        /// Why the round was refused, as reported by the invoker.
        message: String,
    },
    /// The round's client-visible batch was refused by policy before it was sent.
    ///
    /// Carries no message on purpose: the caller restores it to
    /// [`crate::Error::ResponseFirewallRefused`], whose typed arm builds the
    /// delivery-refusal projection. Flattening a policy refusal into a generic
    /// bridge failure loses that projection and reports it as an ordinary
    /// client-attributable error instead.
    ChallengeRefused {
        /// Whether any round of this call already reached the backend.
        ///
        /// A refusal on round one ends a call that never dispatched, so its
        /// idempotency key releases. From round two on the backend has already
        /// run the tool at least once, and releasing the key would readmit a
        /// retry of a side effect that may have taken effect (ADR-012
        /// consequence 1), so the key settles instead.
        dispatched: bool,
    },
    /// A bridged retry round reached the backend and did not come back.
    ///
    /// Carries the reason as text rather than the error itself: this type is
    /// `Clone + PartialEq` so tests can assert on it, and `crate::Error` is
    /// neither. `dispatch` survives that flattening, because whether the round
    /// reached the backend decides whether its idempotency key may be reused.
    BackendFailed {
        /// What went wrong, as reported by the invoker.
        message: String,
        /// Whether the backend could have acted on this round.
        dispatch: Dispatch,
    },
}

/// How far a bridged round got before it failed.
///
/// A refusal raised before the request left the gateway — no backend, no tool,
/// an open circuit, a transport that never connected — proves the backend did
/// not act. Anything else may have acted and been lost on the way back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dispatch {
    /// The request provably never reached the backend.
    NeverReached,
    /// The backend may have received the request and acted on it.
    MayHaveActed,
}

/// The bounds on what a backend can make the gateway ask a client.
///
/// Each is on the original call rather than on a round. Capping rounds alone
/// does not cap prompts: one interim result may carry an arbitrary number of
/// entries, so a single round reaches the same abuse with a larger array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BridgeBounds {
    /// Retries after the first call, so at most `rounds + 1` backend
    /// invocations.
    pub rounds: u32,
    /// Requests in total across the call, counting every entry whatever
    /// variant it projects into.
    pub requests: u32,
    /// Wall-clock budget for the whole call.
    pub aggregate: std::time::Duration,
    /// Ceiling on one prompt's wait. The actual wait is the lesser of this and
    /// what is left of `aggregate`.
    pub per_prompt: std::time::Duration,
}

impl BridgeBounds {
    /// The shipped values.
    ///
    /// `per_prompt` is deliberately not the 120-second elicitation constant in
    /// `destructive_confirmation`, which is the same number as the aggregate:
    /// reusing it would let one unanswered prompt consume the entire budget, so
    /// the bound that exists to cap a sequence would never bind until the
    /// sequence was already over.
    pub const DEFAULT: Self = Self {
        rounds: 3,
        requests: 8,
        aggregate: std::time::Duration::from_secs(120),
        per_prompt: std::time::Duration::from_secs(30),
    };
}

/// One observation the bridge emits.
///
/// The labels are an open map because the counter contract is a label set, not
/// a struct: what must be asserted is that `phase` is present and that nothing
/// a person typed ever is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeRecord {
    /// Which counter this increments.
    pub counter: String,
    /// The label set it carries.
    pub labels: std::collections::BTreeMap<String, String>,
}
