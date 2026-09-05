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
