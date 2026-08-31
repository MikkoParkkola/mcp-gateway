// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: MIT

//! Multi-round-trip requests: the fields a retry carries.
//!
//! MCP 2026-07-28 replaced server-initiated requests. Instead of a server
//! asking the client something mid-call, it returns an `InputRequiredResult`
//! naming what it needs, and the client **retries the original request** with
//! the answers attached:
//!
//! ```json
//! {
//!   "name": "book_flight",
//!   "arguments": { … },
//!   "inputResponses": { "confirm": { "action": "accept", … } },
//!   "requestState": "opaque, meaningful only to the server"
//! }
//! ```
//!
//! Those two fields are siblings of `name` and `arguments`, and the gateway's
//! extraction returned only the latter pair — so both were dropped in silence.
//! A modern client's elicitation never completed, and the confirmation gate on
//! a destructive tool ran without the answer it exists to collect.

use serde_json::Value;

/// The `params._meta` key carrying a client's idempotency key.
///
/// Reverse-DNS-ish and gateway-scoped, as the specification requires of any
/// `_meta` key an implementation invents: an unprefixed `idempotency-key` would
/// be claimed by the next implementation to want one.
pub const IDEMPOTENCY_KEY_META: &str = "io.mcp-gateway/idempotency-key";

/// The out-of-band fields of a `tools/call` — the retry pair, and the
/// idempotency key.
///
/// Separate from `(name, arguments)` rather than folded into it: the existing
/// extraction is called from four places, and widening its return type would
/// have every caller silently ignore the new half. A caller that wants the
/// retry fields asks for them, and one that does not is unchanged.
///
/// Widened beyond the retry pair deliberately (SUB.4): this type is the only
/// value derived from the whole params object that reaches the invoke funnel,
/// so a sibling of `arguments` — which `_meta` is — has no other way in. The
/// alternative was a new field on the caller context, which is a wider change
/// to a type every call site constructs.
#[derive(Debug, Default, Clone)]
pub struct RetryFields {
    /// The client's answers to what the server asked for, keyed by the
    /// server-assigned identifiers it used.
    pub input_responses: Option<Value>,
    /// The server's own opaque state, echoed back verbatim.
    ///
    /// Verbatim is the contract: clients **MUST NOT** inspect, parse, modify or
    /// assume anything about it. For this gateway it is its own sealed
    /// envelope, which is why nothing here tries to read it.
    pub request_state: Option<String>,
    /// The client's idempotency key, from `params._meta`.
    ///
    /// `_meta` and not an argument: an argument of that name would collide with
    /// a backend parameter and would be forwarded upstream. Spec-native, and it
    /// reaches a stdio client, which an HTTP header cannot.
    pub idempotency_key: Option<String>,
    /// Fields that were present and unusable, named so a caller can refuse.
    ///
    /// Without this the two fields failed differently for the same mistake: a
    /// malformed `inputResponses` was carried through as a retry, while a
    /// malformed `requestState` vanished and the call became a fresh one. A
    /// retry that silently becomes a fresh call is how one side effect becomes
    /// two. An unusable idempotency key is named here for the same reason: run
    /// unprotected, it is the duplicate the client asked to be spared.
    pub malformed: Vec<&'static str>,
}

/// The absence of any retry fields.
///
/// A `static` rather than `Default::default()` so a borrowing caller context
/// can hold it for `'static`: the overwhelming majority of call sites are fresh
/// calls, and `Vec::new()` has a destructor, so a `const` would only ever be a
/// temporary that dies at the end of the statement that names it.
pub static NO_RETRY: RetryFields = RetryFields {
    input_responses: None,
    request_state: None,
    idempotency_key: None,
    malformed: Vec::new(),
};

impl RetryFields {
    /// Read the retry fields from a `tools/call` params object.
    #[must_use]
    pub fn from_params(params: Option<&Value>) -> Self {
        let Some(params) = params else {
            return Self::default();
        };
        let mut malformed = Vec::new();

        // An object keyed by the identifiers the server asked with. Anything
        // else is a client that did not answer the question it was asked.
        let input_responses = match params.get("inputResponses") {
            None => None,
            Some(value) if value.is_object() => Some(value.clone()),
            Some(_) => {
                malformed.push("inputResponses");
                None
            }
        };
        if params
            .get("requestState")
            .is_some_and(|value| !value.is_string())
        {
            malformed.push("requestState");
        }

        // A non-string key is refused rather than ignored: ignoring it runs the
        // call unprotected, which is the outcome the client asked to prevent.
        let idempotency_key = match params.get("_meta").and_then(|m| m.get(IDEMPOTENCY_KEY_META)) {
            None => None,
            Some(Value::String(key)) if !key.is_empty() => Some(key.clone()),
            Some(_) => {
                malformed.push(IDEMPOTENCY_KEY_META);
                None
            }
        };

        Self {
            input_responses,
            // Only a string. A client sending an object has not echoed the
            // state it was given, and coercing it would put a shape the gateway
            // invented where the backend's own opaque value belongs.
            request_state: params
                .get("requestState")
                .and_then(Value::as_str)
                .map(str::to_string),
            idempotency_key,
            malformed,
        }
    }

    /// Whether the call carried a retry field it could not use.
    ///
    /// Distinct from `is_retry`: a malformed retry is not a fresh call, and
    /// treating it as one repeats whatever the first attempt already did.
    #[must_use]
    pub fn is_malformed(&self) -> bool {
        !self.malformed.is_empty()
    }

    /// Whether this call continues an earlier one.
    ///
    /// Either field alone is enough. The specification requires a server to
    /// include **at least one** of `inputRequests` or `requestState`, so a
    /// retry may legitimately carry back only one — and demanding both would
    /// drop the state-only retry, which is what a server sends when it needs no
    /// further input from the user.
    #[must_use]
    pub const fn is_retry(&self) -> bool {
        self.input_responses.is_some() || self.request_state.is_some()
    }
}

/// A backend's interim result: it needs something before it can finish.
#[derive(Debug, Clone)]
pub struct InputRequired {
    /// What the server asked for, keyed by the identifiers it assigned.
    ///
    /// Its keys, not ours. The server will look for exactly these again on the
    /// retry, so an answer returned under a different key is lost as surely as
    /// one that was never collected.
    pub requests: Vec<(String, Value)>,
    /// The server's opaque state, to be echoed back untouched.
    pub request_state: Option<String>,
}

impl InputRequired {
    /// Read an interim result, or `None` if the result is a completed one.
    ///
    /// `resultType` is the discriminator. A result omitting it is complete by
    /// the client rule, which is what every pre-2026 backend sends — so an
    /// ordinary legacy answer must never be mistaken for a question.
    #[must_use]
    pub fn from_result(result: &Value) -> Option<Self> {
        if result.get("resultType").and_then(Value::as_str)? != "input_required" {
            return None;
        }
        let requests = result
            .get("inputRequests")
            .and_then(Value::as_object)
            .map(|map| {
                map.iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect()
            })
            .unwrap_or_default();
        Some(Self {
            requests,
            request_state: result
                .get("requestState")
                .and_then(Value::as_str)
                .map(str::to_string),
        })
    }
}

/// One question, translated for a client that expects to be asked directly.
#[derive(Debug, Clone)]
pub struct OutboundRequest {
    /// The server's identifier for this question, carried so the answer can be
    /// returned under it.
    pub key: String,
    /// The legacy server-initiated method, e.g. `elicitation/create`.
    pub method: String,
    /// Its params, verbatim.
    pub params: Value,
}

/// Translating between the two generations of asking a question.
///
/// A **modern** server returns an interim result and waits to be retried. A
/// **legacy** client expects the server to ask it something mid-call. Neither
/// can be changed, so the gateway sits between them: it holds the backend's
/// continuation, asks the client the way that client understands, and retries
/// the backend with what comes back. The client never learns a retry happened.
///
/// This is the likelier direction in practice — backends adopt a revision
/// before every client does — which is why it gets a contract of its own rather
/// than being called mechanical.
pub struct Bridge;

impl Bridge {
    /// The questions to put to a legacy client, in the shape it expects.
    #[must_use]
    pub fn to_legacy_client(interim: &InputRequired) -> Vec<OutboundRequest> {
        interim
            .requests
            .iter()
            .map(|(key, request)| OutboundRequest {
                key: key.clone(),
                method: request
                    .get("method")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                params: request.get("params").cloned().unwrap_or(Value::Null),
            })
            .collect()
    }

    /// The params for retrying the backend, once the client has answered.
    ///
    /// The state is echoed verbatim and the answers go back under the server's
    /// own keys. When nothing was asked, nothing is sent: an empty
    /// `inputResponses` would tell the server it received answers to questions
    /// it never posed.
    #[must_use]
    pub fn retry_params(interim: &InputRequired, answers: Vec<(String, Value)>) -> Value {
        let mut params = serde_json::Map::new();
        if let Some(ref state) = interim.request_state {
            params.insert("requestState".to_string(), Value::String(state.clone()));
        }
        if !answers.is_empty() {
            let mut responses = serde_json::Map::new();
            for (key, answer) in answers {
                responses.insert(key, answer);
            }
            params.insert("inputResponses".to_string(), Value::Object(responses));
        }
        Value::Object(params)
    }
}
