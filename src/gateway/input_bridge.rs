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

    /// The kind a JSON-RPC method names, or `None` when the gateway relays no
    /// such request.
    #[must_use]
    pub fn from_method(method: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.method() == method)
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
/// The body reads [`ServerRequestKind::ALL`] rather than naming prefixes, so
/// the admitted set is the minted set by construction. A kind added to the
/// enum is admitted on the way back with no second edit.
#[must_use]
pub fn is_bridge_reply_id(id: &str) -> bool {
    ServerRequestKind::ALL
        .iter()
        .any(|kind| id.starts_with(kind.prefix()))
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
    /// `Some(&[])` is not `None`: an empty slice is a request declaring an
    /// empty set, and it narrows to nothing, so no entry is asked. The two are
    /// spelled out separately because the fail-open reading — treating an
    /// explicit empty declaration as "no narrowing requested" — is the one that
    /// keeps every other row passing.
    ///
    /// # Errors
    ///
    /// Returns the reason the bridged call failed: a refused entry, a delivery
    /// that produced no answer, or a bound the call ran past.
    pub async fn run(
        &self,
        session_id: &str,
        declared: crate::protocol::meta::Declared,
        slice: Option<&[String]>,
        first: &crate::protocol::mrtr::InputRequired,
    ) -> Result<Value, BridgeError> {
        let started = std::time::Instant::now();
        let mut interim = first.clone();
        let mut spent = 0_u32;
        for _ in 0..self.bounds.rounds {
            if started.elapsed() >= self.bounds.aggregate {
                return Err(BridgeError::Deadline);
            }
            let prompts = Self::plan(&interim, declared, slice)?;
            spent = spent.saturating_add(u32::try_from(prompts.len()).unwrap_or(u32::MAX));
            if spent > self.bounds.requests {
                return Err(BridgeError::RequestBudgetExhausted);
            }
            self.observe(&interim);
            let answers = self.ask(session_id, prompts, started).await?;
            let retry = crate::protocol::mrtr::Bridge::retry_params(&interim, answers);
            let result = self.backend.invoke(retry).await;
            match crate::protocol::mrtr::InputRequired::from_result(&result) {
                Some(next) => interim = next,
                None => return Ok(result),
            }
        }
        Err(BridgeError::RoundsExhausted)
    }

    /// Gate one interim result, whole, before a single frame leaves.
    ///
    /// Whole-batch and pre-send because a refusal is about the batch the
    /// backend composed: asking the half a client can answer and refusing the
    /// rest would put a question to a person on the strength of a request the
    /// gateway had already decided it could not carry.
    fn plan(
        interim: &crate::protocol::mrtr::InputRequired,
        declared: crate::protocol::meta::Declared,
        slice: Option<&[String]>,
    ) -> Result<Vec<Prompt>, BridgeError> {
        if let Some(bad) = interim.undeclared(declared) {
            return Err(BridgeError::Refused {
                key: bad.key.to_string(),
                reason: bad.reason,
            });
        }
        interim
            .requests
            .iter()
            .map(|(key, request)| Self::prompt(key, request, slice))
            .collect()
    }

    /// Project one entry into the request it will be sent as.
    ///
    /// The slice narrows and may only narrow: the session's declaration is the
    /// ceiling and is checked by the caller, so an absent slice asks for
    /// everything declared and an empty one asks for nothing.
    fn prompt(key: &str, request: &Value, slice: Option<&[String]>) -> Result<Prompt, BridgeError> {
        let refused = |reason| BridgeError::Refused {
            key: key.to_string(),
            reason,
        };
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let (Some(kind), Some(capability)) = (
            ServerRequestKind::from_method(method),
            crate::protocol::meta::required_capability(method),
        ) else {
            return Err(refused(crate::protocol::mrtr::Refusal::UnrecognisedMethod));
        };
        if slice.is_some_and(|names| !names.iter().any(|name| name == capability)) {
            return Err(refused(crate::protocol::mrtr::Refusal::Capability(
                capability,
            )));
        }
        Ok(Prompt {
            key: key.to_string(),
            kind,
            params: request.get("params").cloned(),
        })
    }

    /// Put one round's prompts to the client and collect what came back.
    ///
    /// A prompt that outlives its wait is dropped rather than failing the
    /// call: the bound exists so one silent client cannot hold the exchange
    /// open, and the backend is still owed the round it asked for. A client
    /// that *answered* something unusable is the other case, and that one ends
    /// the call, because an answer the gateway cannot read is not silence.
    async fn ask(
        &self,
        session_id: &str,
        prompts: Vec<Prompt>,
        started: std::time::Instant,
    ) -> Result<Vec<(String, Value)>, BridgeError> {
        let mut answers = Vec::with_capacity(prompts.len());
        for prompt in prompts {
            let id = format!("{}{}", prompt.kind.prefix(), uuid::Uuid::new_v4());
            let left = self.bounds.aggregate.saturating_sub(started.elapsed());
            let sent =
                self.channel
                    .send_request(session_id, &id, prompt.kind.method(), prompt.params);
            let Ok(reply) = tokio::time::timeout(self.bounds.per_prompt.min(left), sent).await
            else {
                continue;
            };
            let answer = reply
                .and_then(|reply| Self::project(&reply))
                .map_err(|error| BridgeError::Delivery {
                    key: prompt.key.clone(),
                    error,
                })?;
            answers.push((prompt.key, answer));
        }
        Ok(answers)
    }

    /// Read one client reply as the answer to file, or say why it is not one.
    ///
    /// A `result` carrying no `action` is filed whole: `roots/list` and
    /// `sampling/createMessage` answer with their own shapes and never accept
    /// or decline, so demanding an `action` of them would refuse every valid
    /// reply of two of the three relayed kinds.
    fn project(reply: &Value) -> Result<Value, DeliveryError> {
        if let Some(error) = reply.get("error") {
            return Err(DeliveryError::ClientRefused {
                code: error
                    .get("code")
                    .and_then(Value::as_i64)
                    .unwrap_or_default(),
                message: error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            });
        }
        let Some(result) = reply.get("result") else {
            return Err(DeliveryError::NoReplyMember);
        };
        let Some(action) = result.get("action").and_then(Value::as_str) else {
            return Ok(result.clone());
        };
        match action {
            "accept" => result
                .get("content")
                .filter(|content| content.is_object())
                .cloned()
                .ok_or(DeliveryError::Malformed),
            "decline" | "cancel" => Err(DeliveryError::Declined {
                action: action.to_string(),
            }),
            _ => Err(DeliveryError::UnknownAction {
                action: action.to_string(),
            }),
        }
    }

    /// Emit this round's observation.
    ///
    /// Counted per round rather than per prompt, and labelled with nothing a
    /// person typed: the label set says that a bridged round happened and how
    /// wide it was, and the answers themselves never reach a counter.
    fn observe(&self, interim: &crate::protocol::mrtr::InputRequired) {
        let mut labels = std::collections::BTreeMap::new();
        labels.insert("phase".to_string(), "bridge".to_string());
        labels.insert("requests".to_string(), interim.requests.len().to_string());
        self.observer.record(BridgeRecord {
            counter: "mrtr_bridge_rounds_total".to_string(),
            labels,
        });
    }
}

/// One gated entry, ready to be put on the client's connection.
///
/// The params travel as the backend wrote them: the client is answering the
/// backend's question, and a re-spelling of it is a different question.
struct Prompt {
    /// The backend's own key, which the answer must be filed under.
    key: String,
    /// Which relayed request this is.
    kind: ServerRequestKind,
    /// The params to send, absent for a request that carries none.
    params: Option<Value>,
}
