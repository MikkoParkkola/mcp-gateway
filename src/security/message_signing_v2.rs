// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! RFC 8785 response MAC binding for the final JSON-RPC delivery envelope.

use std::borrow::Cow;

use serde::Serialize;
use serde_json::{Map, Value, json};

use super::{MessageSigner, build_signature_block, compute_hmac_hex};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::{Error, Result};

const MAX_EXACT_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Serialize)]
struct TypedRequestId<'a> {
    kind: &'static str,
    value: Cow<'a, str>,
}

impl<'a> From<&'a RequestId> for TypedRequestId<'a> {
    fn from(id: &'a RequestId) -> Self {
        match id {
            RequestId::String(value) => Self {
                kind: "string",
                value: Cow::Borrowed(value),
            },
            RequestId::Number(value) => Self {
                kind: "number",
                value: Cow::Owned(value.to_string()),
            },
        }
    }
}

#[derive(Serialize)]
struct MacInput<'a> {
    domain: &'static str,
    body: &'a Map<String, Value>,
    request_id: Option<TypedRequestId<'a>>,
    alg: &'static str,
    version: u8,
    nonce: Option<&'a str>,
    ts: u64,
    key_id: &'a str,
}

impl MessageSigner {
    /// Authenticate the final result and its original typed request ID.
    ///
    /// Errors are unsigned. This primitive neither filters the result nor
    /// admits a request nonce; the shared delivery boundary owns those stages.
    /// The explicit timestamp enables independent deterministic MAC vectors.
    pub(crate) fn sign_json_rpc_response_at(
        &self,
        response: &mut JsonRpcResponse,
        nonce: Option<&str>,
        timestamp: u64,
    ) -> Result<()> {
        if response.error.is_some() || response.result.is_none() {
            return Ok(());
        }
        if nonce.is_some_and(|value| value.is_empty() || value.len() > 256) {
            return Err(signing_error("Invalid signing nonce"));
        }
        let body = response
            .result
            .as_mut()
            .and_then(Value::as_object_mut)
            .ok_or_else(|| signing_error("Signing requires an object result"))?;

        // Only this reserved top-level member is replaced. Nested members of
        // the same name are ordinary authenticated payload data.
        body.remove("_signature");
        if !body.values().all(has_interoperable_numbers) {
            return Err(signing_error("Signing result contains an unsafe integer"));
        }
        let input = MacInput {
            domain: "mcp-gateway-response-v2",
            body,
            request_id: response.id.as_ref().map(TypedRequestId::from),
            alg: "hmac-sha256",
            version: 2,
            nonce,
            ts: timestamp,
            key_id: &self.key_id,
        };
        // Borrow the existing result rather than cloning large tool payloads.
        let canonical = serde_json_canonicalizer::to_vec(&input)
            .map_err(|_| signing_error("Signing result cannot be canonicalized"))?;
        let mac = compute_hmac_hex(&self.secret, &canonical);
        let mut signature = build_signature_block(&mac, nonce, timestamp, &self.key_id);
        signature["version"] = json!(2);
        body.insert("_signature".to_owned(), signature);
        Ok(())
    }
}

fn has_interoperable_numbers(value: &Value) -> bool {
    match value {
        Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                integer.unsigned_abs() <= MAX_EXACT_INTEGER
            } else if let Some(integer) = number.as_u64() {
                integer <= MAX_EXACT_INTEGER
            } else {
                // serde_json stores finite IEEE-754 floats here; JCS supplies
                // their ECMAScript spelling. Strings containing JSON stay opaque.
                true
            }
        }
        Value::Array(values) => values.iter().all(has_interoperable_numbers),
        Value::Object(values) => values.values().all(has_interoperable_numbers),
        Value::Null | Value::Bool(_) | Value::String(_) => true,
    }
}

fn signing_error(message: &'static str) -> Error {
    // The signing boundary counts this failure once; the common finalizer
    // replaces the internal diagnostic with its fixed safe wire refusal.
    Error::json_rpc(-32603, message)
}
