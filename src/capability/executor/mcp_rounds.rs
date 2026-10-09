// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The prepare round and how a later round's error is reported once an
//! earlier one reached the backend. Included by `#[path]` from `mcp.rs`.

use serde_json::{Map, Value};

use super::{arguments, call_tool};
use crate::backend::Backend;
use crate::{Error, Result};

/// The optional prepare round: call it, then bind the named fields of its
/// object result into `args`.
pub(super) async fn run_prepare(
    backend: &Backend,
    prepare: &crate::capability::definition::PrepareCall,
    params: &Value,
    args: &mut Map<String, Value>,
) -> Result<()> {
    let first = call_tool(
        backend,
        &prepare.tool,
        arguments(prepare.arguments.as_ref(), params)?,
    )
    .await?;
    let object = prepare_object(first).ok_or_else(|| {
        Error::Protocol(format!(
            "prepare tool '{}' returned no object",
            prepare.tool
        ))
    })?;
    for (arg, field) in &prepare.bind {
        let value = object.get(field).cloned().ok_or_else(|| {
            Error::Protocol(format!(
                "prepare tool '{}' returned no '{field}'",
                prepare.tool
            ))
        })?;
        args.insert(arg.clone(), value);
    }
    Ok(())
}

/// A later round's error once an earlier round reached the backend
/// (MIK-7923, design M9). A pre-dispatch refusal (the backend retired between
/// rounds, a connect error, a missing backend) would tell the caller nothing
/// was sent and free its key, but the earlier round already ran: it is
/// reported as a transport failure, which settles uncertain.
pub(super) fn after_dispatch(error: Error, dispatched: bool) -> Error {
    if dispatched && error.is_pre_dispatch() {
        Error::Transport(format!(
            "after an earlier round reached the backend: {error}"
        ))
    } else {
        error
    }
}

/// A prepare result as an object: `structuredContent` as is, or the first
/// text content block parsed as JSON.
fn prepare_object(result: Value) -> Option<Map<String, Value>> {
    match result {
        Value::Object(map) => Some(map),
        Value::Array(blocks) => blocks
            .first()
            .and_then(|b| b.get("text"))
            .and_then(Value::as_str)
            .and_then(|t| serde_json::from_str::<Value>(t).ok())
            .and_then(|v| match v {
                Value::Object(map) => Some(map),
                _ => None,
            }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, after_dispatch};

    /// MIK-7923 M9 (design T8): every pre-dispatch refusal a later round can
    /// meet is reported as a transport failure once a round was dispatched,
    /// and left alone before any was.
    #[test]
    fn a_refusal_after_a_dispatched_round_is_never_pre_dispatch() {
        let refusals = || {
            [
                Error::BackendNotFound("retired".to_string()),
                Error::TransportConnect("Not connected".to_string()),
                Error::BackendUnavailable("stopping".to_string()),
            ]
        };
        for refusal in refusals() {
            assert!(refusal.is_pre_dispatch(), "premise: {refusal}");
            let mapped = after_dispatch(refusal, true);
            assert!(!mapped.is_pre_dispatch(), "{mapped} still reads as unsent");
            assert!(matches!(mapped, Error::Transport(_)), "{mapped}");
        }
        for refusal in refusals() {
            assert!(after_dispatch(refusal, false).is_pre_dispatch());
        }
    }
}
