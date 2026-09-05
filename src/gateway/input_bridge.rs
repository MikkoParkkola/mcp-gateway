// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The bridge that puts a modern backend's questions to a legacy client.
//!
//! A backend speaking the 2026 multi-round tool-result protocol answers a call
//! with questions instead of a result. A client that never declared the
//! protocol cannot be handed those questions as they stand — it has no place to
//! put them. The bridge relays each one as the ordinary server-to-client
//! request the client already understands, collects the answers, and retries
//! the backend with them.
//!
//! What travels is a closed set. The gateway relays `sampling/createMessage`,
//! `elicitation/create` and `roots/list` and refuses everything else, because a
//! request the gateway cannot classify is one the client was never given the
//! chance to withhold consent for.

use serde_json::Value;

use crate::protocol::{ElicitationCreateParams, SamplingCreateMessageParams};

/// Which of the three server-to-client requests an entry projects into.
///
/// Separate from [`ServerRequest`] because this is the half that can be
/// enumerated: a variant carrying deserialized params cannot form a `const`
/// array, and the ingress gate needs the set of prefixes as data rather than as
/// a second list written beside the first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerRequestKind {
    /// `sampling/createMessage`
    Sampling,
    /// `elicitation/create`
    Elicitation,
    /// `roots/list`
    Roots,
}

impl ServerRequestKind {
    /// Every kind the gateway relays.
    ///
    /// The ingress gate is built from this, so a variant added here is admitted
    /// on the way back without a second edit. A kind minted on the outbound
    /// side and missing on the inbound side fails as a caller timeout, which
    /// names neither the missing prefix nor the request it stranded.
    pub const ALL: [Self; 3] = [Self::Sampling, Self::Elicitation, Self::Roots];

    /// The JSON-RPC method this kind is sent as.
    #[must_use]
    pub const fn method(self) -> &'static str {
        match self {
            Self::Sampling => "sampling/createMessage",
            Self::Elicitation => "elicitation/create",
            Self::Roots => "roots/list",
        }
    }

    /// The prefix every pending id of this kind carries.
    ///
    /// The trailing hyphen is part of the prefix: without it `sampling` would
    /// also admit an id a different subsystem happened to start with the same
    /// letters.
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Sampling => "sampling-",
            Self::Elicitation => "elicitation-",
            Self::Roots => "roots-",
        }
    }
}

/// One request the gateway will put to a client, with its params already read.
///
/// A closed type rather than a method string and an opaque body. The params are
/// deserialized on the way in, so a backend cannot post an arbitrary method
/// through the bridge by naming it, and cannot smuggle a shape the client will
/// be asked to render.
#[derive(Debug, Clone)]
pub enum ServerRequest {
    /// Ask the client's model.
    Sampling(SamplingCreateMessageParams),
    /// Ask the client's user.
    Elicitation(ElicitationCreateParams),
    /// Ask the client what roots it exposes. Carries no params.
    Roots,
}

impl ServerRequest {
    /// Which kind this is.
    #[must_use]
    pub const fn kind(&self) -> ServerRequestKind {
        match self {
            Self::Sampling(_) => ServerRequestKind::Sampling,
            Self::Elicitation(_) => ServerRequestKind::Elicitation,
            Self::Roots => ServerRequestKind::Roots,
        }
    }

    /// The JSON-RPC method this request is sent as.
    #[must_use]
    pub const fn method(&self) -> &'static str {
        self.kind().method()
    }

    /// The prefix of the pending id this request is sent under.
    #[must_use]
    pub const fn prefix(&self) -> &'static str {
        self.kind().prefix()
    }

    /// The params to put on the wire, re-serialized from what was read.
    ///
    /// Re-serialized rather than forwarded verbatim so that what the client
    /// sees is what the gateway understood. A field the gateway cannot name is
    /// a field it cannot have checked.
    #[must_use]
    pub fn params(&self) -> Option<Value> {
        match self {
            Self::Sampling(params) => serde_json::to_value(params).ok(),
            Self::Elicitation(params) => serde_json::to_value(params).ok(),
            Self::Roots => None,
        }
    }
}

/// Whether an inbound POST-back id belongs to a request the bridge sent.
///
/// The ingress gate on the HTTP path calls this rather than testing prefixes
/// inline, so that the admitted set and the minted set can become one list.
/// Two lists written from the same knowledge drift apart the moment a variant
/// is added to one of them, and the drift fails as a caller timeout that names
/// neither the missing prefix nor the request it stranded.
///
/// The body is still the pair of literals lifted out of `handlers.rs`: this
/// commit moves the condition without changing what it admits, so the move is
/// reviewable as a move.
#[must_use]
pub fn is_bridge_reply_id(id: &str) -> bool {
    id.starts_with("sampling-") || id.starts_with("elicitation-")
}

/// Why one relayed request did not produce an answer.
///
/// Several cases rather than one, because the bridge's job is to say which of
/// them happened: a person who declined, a client that refused, a client that
/// answered something unreadable and a client that never answered are four
/// different facts, and a single "failed" collapses the distinction the
/// `NFR.OBS.4` counters exist to keep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryError {
    /// The client answered, and the answer was a refusal by the person at it.
    /// Carries the action verbatim so `decline` and `cancel` stay distinct.
    Declined {
        /// The `action` the client sent.
        action: String,
    },
    /// The client answered with an `action` outside the declared set. Not a
    /// refusal — nobody said no, the reply is unreadable.
    UnknownAction {
        /// The unrecognised `action`.
        action: String,
    },
    /// The client answered with a JSON-RPC `error` member.
    ClientRefused {
        /// The client's own error code.
        code: i64,
        /// The client's own message.
        message: String,
    },
    /// The client accepted and the accepted body is unusable.
    Malformed,
    /// The reply carried neither a `result` nor an `error` member.
    NoReplyMember,
    /// There is no client session to reach.
    NoSession,
    /// Nothing came back inside the per-prompt wait.
    TimedOut,
}

/// Why the whole bridged call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    RoundsExhausted,
    /// The backend asked for more requests in total than the bound allows.
    RequestBudgetExhausted,
    /// The aggregate wall-clock budget for the call ran out.
    Deadline,
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

/// The client end of the bridge: one request out, one answer back.
///
/// A whole JSON-RPC envelope comes back rather than a projected answer, because
/// projecting it is the bridge's own job and the cases that matter most are the
/// ones where the envelope is not what the projection expects.
#[async_trait::async_trait]
pub trait ClientChannel: Send + Sync {
    /// Put one request on the client's own connection and wait for its reply.
    async fn send_request(
        &self,
        session_id: &str,
        id: &str,
        method: &str,
        params: Option<Value>,
    ) -> Result<Value, DeliveryError>;
}

/// The backend end: re-invoke the tool call with the answers collected so far.
#[async_trait::async_trait]
pub trait BackendInvoker: Send + Sync {
    /// Retry the original call with these params, yielding its raw result.
    async fn invoke(&self, retry_params: Value) -> Value;
}

/// Where the bridge's counters go.
///
/// A seam rather than a metrics call because the requirement is about what the
/// records contain — the label set, and the absence of any answer body — and
/// that is assertable only against captured records.
pub trait BridgeObserver: Send + Sync {
    /// Record one counter increment.
    fn record(&self, record: BridgeRecord);
}

/// One bridged call: a backend's questions, put to one legacy client.
pub struct InputBridge<'a> {
    /// The client to ask.
    pub channel: &'a dyn ClientChannel,
    /// The backend to retry.
    pub backend: &'a dyn BackendInvoker,
    /// Where the counters go.
    pub observer: &'a dyn BridgeObserver,
    /// The bounds this call runs under.
    pub bounds: BridgeBounds,
}

impl InputBridge<'_> {
    /// Collect answers for `first`, retrying the backend until it completes.
    ///
    /// `declared` is the session store's value and is authoritative; `slice` is
    /// the per-request capability slice, which may only narrow it, and `None`
    /// means the request said nothing rather than that the client can do
    /// nothing.
    ///
    /// # Errors
    ///
    /// Returns the reason the bridged call failed: a refused entry, a delivery
    /// that produced no answer, or a bound the call ran past.
    // The stub awaits nothing yet; the async signature is the contract the
    // acceptance rows drive. Delete this allowance by hand once a real await
    // lands: `allow` stays silent when it becomes redundant, so nothing else
    // will point it out. Spelled the way the rest of this crate spells it,
    // because `unused_async_trait_impl` exists only on newer clippy.
    #[allow(unknown_lints, clippy::unused_async, clippy::unused_async_trait_impl)]
    pub async fn run(
        &self,
        session_id: &str,
        declared: crate::protocol::meta::Declared,
        slice: Option<&[String]>,
        first: &crate::protocol::mrtr::InputRequired,
    ) -> Result<Value, BridgeError> {
        let _ = (session_id, declared, slice, first);
        let _ = (self.channel, self.backend, self.observer, self.bounds);
        Err(BridgeError::Delivery {
            key: String::new(),
            error: DeliveryError::NoSession,
        })
    }
}
