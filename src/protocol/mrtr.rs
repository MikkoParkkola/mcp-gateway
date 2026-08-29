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

/// The multi-round-trip fields of a `tools/call`.
///
/// Separate from `(name, arguments)` rather than folded into it: the existing
/// extraction is called from four places, and widening its return type would
/// have every caller silently ignore the new half. A caller that wants the
/// retry fields asks for them, and one that does not is unchanged.
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
}

impl RetryFields {
    /// Read the retry fields from a `tools/call` params object.
    #[must_use]
    pub fn from_params(params: Option<&Value>) -> Self {
        let Some(params) = params else {
            return Self::default();
        };
        Self {
            input_responses: params.get("inputResponses").cloned(),
            // Only a string. A client sending an object has not echoed the
            // state it was given, and coercing it would put a shape the gateway
            // invented where the backend's own opaque value belongs.
            request_state: params
                .get("requestState")
                .and_then(Value::as_str)
                .map(str::to_string),
        }
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
