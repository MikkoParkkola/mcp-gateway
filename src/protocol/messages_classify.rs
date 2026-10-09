// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Classifying one JSON-RPC line read from a backend (MIK-8014 PERF.1a).
//!
//! The derived, untagged `JsonRpcMessage` buffers the whole line into serde's
//! `Content` tree and then tries `Request`, `Notification` and `Response` in
//! turn. This reads the line once: each member a variant uses is kept as its
//! first occurrence, a repeat is skipped and remembered, and each member is
//! typed only in the branch that uses it. The outcome is the one that order
//! gives, duplicated keys included:
//! - `method` a string, `id` a valid id, neither `id` nor `params` repeated: a
//!   request.
//! - `method` a string otherwise, `params` not repeated: a notification, which
//!   ignores `id` (absent, null, of another type, or repeated).
//! - `method` repeated, not a string (null included), or a method frame with
//!   `params` repeated: no variant accepts it, so an error. MIK-8019 holds: a
//!   frame carrying `method` is never a response.
//! - no `method`: a response, read as `JsonRpcResponse`'s own deserializer
//!   reads it (`"result": null` kept unless beside an error); a repeated
//!   `id`, `result` or `error` refuses it, a repeated `params` does not.
//! - `jsonrpc` missing, not a string, or repeated: an error in every variant.
//!
//! Members a variant does not have are ignored in it, as the derive ignores
//! unknown fields.

use serde::Deserialize;
use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde_json::Value;

use super::{
    JsonRpcError, JsonRpcMessage, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, RequestId,
};

/// The members any variant reads; anything else is skipped.
#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "lowercase")]
enum Member {
    Jsonrpc,
    Id,
    Method,
    Params,
    Result,
    Error,
    #[serde(other)]
    Other,
}

/// A member's first occurrence, and whether it came again.
struct Slot<T> {
    value: Option<T>,
    repeated: bool,
}

impl<T> Default for Slot<T> {
    fn default() -> Self {
        Self {
            value: None,
            repeated: false,
        }
    }
}

impl<T> Slot<T> {
    /// Keep the first occurrence; a repeat is skipped without being built.
    fn take<'de, A: MapAccess<'de>>(&mut self, map: &mut A) -> Result<(), A::Error>
    where
        T: Deserialize<'de>,
    {
        if self.value.is_some() || self.repeated {
            self.repeated = true;
            map.next_value::<IgnoredAny>()?;
        } else {
            self.value = Some(map.next_value()?);
        }
        Ok(())
    }

    /// The value if it came exactly once.
    fn once(self) -> Option<T> {
        if self.repeated { None } else { self.value }
    }
}

#[derive(Default)]
struct Frame {
    jsonrpc: Slot<String>,
    id: Slot<Value>,
    method: Slot<Value>,
    params: Slot<Value>,
    result: Slot<Value>,
    error: Slot<Value>,
}

impl<'de> Deserialize<'de> for Frame {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct FrameVisitor;
        impl<'de> Visitor<'de> for FrameVisitor {
            type Value = Frame;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON-RPC message object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Frame, A::Error> {
                let mut frame = Frame::default();
                while let Some(member) = map.next_key::<Member>()? {
                    match member {
                        Member::Jsonrpc => frame.jsonrpc.take(&mut map)?,
                        Member::Id => frame.id.take(&mut map)?,
                        Member::Method => frame.method.take(&mut map)?,
                        Member::Params => frame.params.take(&mut map)?,
                        Member::Result => frame.result.take(&mut map)?,
                        Member::Error => frame.error.take(&mut map)?,
                        Member::Other => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(frame)
            }
        }
        deserializer.deserialize_map(FrameVisitor)
    }
}

/// `None` for an absent or `null` member, else the member as `T`.
fn optional<T: serde::de::DeserializeOwned>(
    member: Option<Value>,
) -> serde_json::Result<Option<T>> {
    match member {
        None | Some(Value::Null) => Ok(None),
        Some(value) => T::deserialize(value).map(Some),
    }
}

fn refuse(why: &str) -> serde_json::Error {
    serde::de::Error::custom(why)
}

impl JsonRpcMessage {
    /// One line from a backend, as a request, a notification or a response,
    /// deserialized once.
    pub(crate) fn from_line(line: &str) -> serde_json::Result<Self> {
        let frame: Frame = serde_json::from_str(line)?;
        let jsonrpc = frame
            .jsonrpc
            .once()
            .ok_or_else(|| refuse("`jsonrpc` missing or repeated"))?;
        if frame.method.repeated {
            return Err(refuse("`method` repeated"));
        }
        match frame.method.value {
            Some(Value::String(method)) => {
                if frame.params.repeated {
                    return Err(refuse("`params` repeated"));
                }
                // `params: null` is no params, as the derive reads it.
                let params = frame.params.value.filter(|p| !p.is_null());
                let id = frame
                    .id
                    .once()
                    .and_then(|id| RequestId::deserialize(id).ok());
                Ok(match id {
                    Some(id) => Self::Request(JsonRpcRequest {
                        jsonrpc,
                        id,
                        method,
                        params,
                    }),
                    None => Self::Notification(JsonRpcNotification {
                        jsonrpc,
                        method,
                        params,
                    }),
                })
            }
            Some(_) => Err(refuse("frame carries a `method` that is not a string")),
            None => {
                if frame.id.repeated || frame.result.repeated || frame.error.repeated {
                    return Err(refuse("a response member is repeated"));
                }
                let id = optional::<RequestId>(frame.id.value)?;
                let error = optional::<JsonRpcError>(frame.error.value)?;
                // A `null` beside an error is the peer spelling "no result".
                let result = match (frame.result.value, &error) {
                    (Some(Value::Null), Some(_)) => None,
                    (result, _) => result,
                };
                Ok(Self::Response(JsonRpcResponse {
                    jsonrpc,
                    ..JsonRpcResponse::envelope(id, result, error)
                }))
            }
        }
    }
}

#[cfg(test)]
#[path = "messages_classify_tests.rs"]
mod tests;
