// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The typed account refusal a dispatch site may turn into a connect offer
//! (MIK-6745 design §9.1-§9.2), carried in the existing `Error::JsonRpc` so
//! the public `Error` enum gains nothing.
//!
//! LIFECYCLE. The shared credential resolver [`mark`]s a refusal. Every
//! dispatch site either attaches an offer or [`unmark`]s it back to the
//! `Error::Config` it always was, so an undecorated refusal reads byte for
//! byte as before; the catalogue swallows it unread. A marked error is only
//! ever built here, from a resolver refusal, never from a backend's reply.
//!
//! PROVENANCE (ADR-008: only gateway-built connect URLs reach a client). A
//! backend's `Error::JsonRpc` can carry any code and any `data`, so neither
//! can prove an offer is ours. An offer built by [`offer_error`] carries a
//! per-process secret seal; [`offer_data`] forwards the §9.1 keys only under
//! that seal and strips it, so the seal never leaves the process and a
//! backend cannot produce data that passes.

use std::sync::LazyLock;

use serde_json::{Value, json};

use crate::Error;
use crate::identity_propagation::PropagationError;

/// Why a managed account refused a dispatch, as the §9.1 envelope names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AccountState {
    NotConnected,
    ReconnectRequired,
}

impl AccountState {
    /// The `accounts.v1` error code.
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::NotConnected => "account_not_connected",
            Self::ReconnectRequired => "reconnect_required",
        }
    }

    fn from_code(code: &str) -> Option<Self> {
        [Self::NotConnected, Self::ReconnectRequired]
            .into_iter()
            .find(|state| state.code() == code)
    }
}

/// The §9.1 `data` keys, forwarded only from a sealed offer.
const ACCOUNT_DATA_KEYS: [&str; 5] = [
    "schema_version",
    "error",
    "account_id",
    "connect_url",
    "retry_after",
];

/// Where the seal rides inside an offer's `data`; never forwarded.
const SEAL_KEY: &str = "gateway_offer_seal";

/// The per-process seal. `None` when no randomness was available, and then
/// nothing is forwarded: an offer without provenance fails closed.
static SEAL: LazyLock<Option<String>> = LazyLock::new(|| super::storage::random_hex().ok());

/// The marked code: the `Config` code, so a refusal nobody decorates still
/// reports it.
const MARKED: i32 = -32603;

/// A marked refusal as a dispatch site reads it.
pub(crate) struct Marked<'a> {
    /// The `Error::Config` text it was marked from.
    pub(crate) message: &'a str,
    pub(crate) account_id: &'a str,
    pub(crate) state: AccountState,
}

/// Mark `refused` (an `Error::Config`) when `cause` is a state a connect
/// journey remedies and the backend names its account; otherwise unchanged.
pub(crate) fn mark(refused: Error, cause: &PropagationError, account_id: Option<&str>) -> Error {
    let state = match cause {
        PropagationError::AccountNotConnected(_) => AccountState::NotConnected,
        PropagationError::AccountReconnectRequired(_) => AccountState::ReconnectRequired,
        _ => return refused,
    };
    match (refused, account_id) {
        (Error::Config(message), Some(account_id)) => Error::JsonRpc {
            code: MARKED,
            message,
            data: Some(
                json!({"schema_version": "accounts.v1", "account_id": account_id,
                              "error": {"code": state.code()}}),
            ),
        },
        (other, _) => other,
    }
}

/// The recovery codes the one mapping answers with (A11-c′). Crate-internal:
/// they reach a caller only as the `error_code` string of a recovery hint.
pub(crate) const UPSTREAM_AUTH_REJECTED: &str = "UPSTREAM_AUTH_REJECTED";
pub(crate) const UPSTREAM_AUTH_REJECTED_PERSISTENT: &str = "UPSTREAM_AUTH_REJECTED_PERSISTENT";

/// Where a rejection rides inside a sealed error's `data`.
const REJECTION_KEY: &str = "upstream_rejection";

/// A11-b′: an upstream 401 against a managed account, as a dispatch site
/// reads it: the recovery code and whether retrying the same call can help.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UpstreamRejection {
    pub(crate) error_code: &'static str,
    pub(crate) retry: bool,
}

impl UpstreamRejection {
    /// What leaves the gateway: the code and the retry flag, never the seal.
    pub(crate) fn data(self) -> Value {
        json!({"error_code": self.error_code, "retry": self.retry})
    }
}

/// The ONE mapping from a forced refresh's outcome to what the caller is told
/// (A11-c′). `AlreadyForced` is persistent and not retryable: the backend
/// refused a token that was already force-tried, so the problem is scope or
/// permission. Every other outcome means the next call presents a newer or
/// different token. The mark is sealed like an offer, so a backend's own
/// JSON-RPC error carrying the same keys is never read as one.
pub(crate) fn mark_rejection(outcome: super::RejectionOutcome, refused: &Error) -> Error {
    use super::RejectionOutcome::{AlreadyForced, Rotated, Stale, Unavailable};
    let (error_code, retry) = match outcome {
        AlreadyForced => (UPSTREAM_AUTH_REJECTED_PERSISTENT, false),
        Rotated | Stale | Unavailable => (UPSTREAM_AUTH_REJECTED, true),
    };
    let mut data = json!({ REJECTION_KEY: {"error_code": error_code, "retry": retry} });
    if let Some(seal) = SEAL.as_ref() {
        data[SEAL_KEY] = Value::String(seal.clone());
    }
    Error::JsonRpc {
        code: refused.to_rpc_code(),
        message: refused.to_string(),
        data: Some(data),
    }
}

/// The one retryable answer for a transient custody / unsettled view
/// (MIK-8392 Busy parity): -32603, one neutral message, `retryable` data,
/// and `retry_after_ms` only while a lease runs. Sealed like an offer, so
/// only a gateway-built one is forwarded as such; a live call and a stored
/// read both build through here and therefore answer byte-equal errors.
///
/// PRE-SEND SITES ONLY (MIK-8428): `Error::is_pre_dispatch` reads the seal,
/// so this answer frees an idempotency key. Build it only where nothing has
/// reached the backend yet. Today's sites, each pre-send, held to this list
/// by `error_pre_send_scan_tests`:
/// - a mint's resolve or refresh admission, via `transient_mint_refusal`
///   (capability `resolve`; the per-user mint in `invoke/propagation.rs`);
/// - the lease recheck in `revalidate`, from its three callers before the
///   send: `CapabilityBackend`, the executor's `prepare_account_context`
///   (before the cache read) and `inject_auth` (before the wire);
/// - the caller verdict's view Busy (`invoke/caller_verdict.rs`);
/// - the task intake answer (`call_dispatch/task_intake.rs`): no task, nothing sent;
/// - a stored task read (`task_replay.rs`): no dispatch at all.
pub(crate) fn transient_retry_error(after: Option<std::time::Duration>) -> Error {
    let mut data = json!({ "retryable": true });
    if let Some(after) = after {
        data["retry_after_ms"] = json!(u64::try_from(after.as_millis()).unwrap_or(u64::MAX));
    }
    if let Some(seal) = SEAL.as_ref() {
        data[SEAL_KEY] = Value::String(seal.clone());
    }
    Error::JsonRpc {
        code: -32603,
        message: "temporarily unavailable, retry".to_owned(),
        data: Some(data),
    }
}

/// The retryable data of a sealed, gateway-built transient answer, seal
/// removed; `None` for every other error, a backend's included.
pub(crate) fn transient_data(error: &Error) -> Option<Value> {
    let Error::JsonRpc {
        data: Some(data), ..
    } = error
    else {
        return None;
    };
    let seal = SEAL.as_ref()?;
    (data.get(SEAL_KEY).and_then(Value::as_str) == Some(seal.as_str())).then_some(())?;
    (data.get("retryable").and_then(Value::as_bool) == Some(true)).then_some(())?;
    let forwarded: serde_json::Map<String, Value> = ["retryable", "retry_after_ms"]
        .into_iter()
        .filter_map(|key| Some((key.to_owned(), data.get(key)?.clone())))
        .collect();
    Some(Value::Object(forwarded))
}

/// The gateway-built rejection mark inside `error`, if it is one.
pub(crate) fn upstream_rejection(error: &Error) -> Option<UpstreamRejection> {
    let Error::JsonRpc {
        data: Some(data), ..
    } = error
    else {
        return None;
    };
    let seal = SEAL.as_ref()?;
    (data.get(SEAL_KEY).and_then(Value::as_str) == Some(seal.as_str())).then_some(())?;
    let rejection = data.get(REJECTION_KEY)?;
    let error_code = [UPSTREAM_AUTH_REJECTED, UPSTREAM_AUTH_REJECTED_PERSISTENT]
        .into_iter()
        .find(|code| rejection["error_code"].as_str() == Some(code))?;
    Some(UpstreamRejection {
        error_code,
        retry: rejection["retry"].as_bool()?,
    })
}

#[cfg(test)]
#[path = "refusal_rejection_tests.rs"]
mod rejection_tests;

/// The marked refusal inside `error`, if it is one.
pub(crate) fn marked(error: &Error) -> Option<Marked<'_>> {
    let Error::JsonRpc {
        code: MARKED,
        message,
        data: Some(data),
    } = error
    else {
        return None;
    };
    (data["schema_version"] == "accounts.v1").then_some(())?;
    Some(Marked {
        message,
        account_id: data["account_id"].as_str()?,
        state: AccountState::from_code(data["error"]["code"].as_str()?)?,
    })
}

/// A marked refusal back to the `Error::Config` it was; anything else as is.
pub(crate) fn unmark(error: Error) -> Error {
    if marked(&error).is_none() {
        return error;
    }
    match error {
        Error::JsonRpc { message, .. } => Error::Config(message),
        other => other,
    }
}

/// The text a caller reads for `error`: a marked refusal's `Config` text.
pub(crate) fn refusal_text(error: &Error) -> String {
    marked(error).map_or_else(
        || error.to_string(),
        |marked| Error::Config(marked.message.to_owned()).to_string(),
    )
}

/// A gateway-built offer: `envelope` sealed so [`offer_data`] will forward it.
pub(crate) fn offer_error(code: i32, message: String, mut envelope: Value) -> Error {
    if let (Some(seal), Some(map)) = (SEAL.as_ref(), envelope.as_object_mut()) {
        map.insert(SEAL_KEY.to_owned(), Value::String(seal.clone()));
    }
    Error::JsonRpc {
        code,
        message,
        data: Some(envelope),
    }
}

/// The §9.1 keys of a sealed, gateway-built offer, seal removed; `None` for
/// every other error, a backend's included, whatever its code or keys.
pub(crate) fn offer_data(error: &Error) -> Option<Value> {
    let Error::JsonRpc {
        data: Some(data), ..
    } = error
    else {
        return None;
    };
    let seal = SEAL.as_ref()?;
    (data.get(SEAL_KEY).and_then(Value::as_str) == Some(seal.as_str())).then_some(())?;
    let forwarded: serde_json::Map<String, Value> = ACCOUNT_DATA_KEYS
        .into_iter()
        .filter_map(|key| Some((key.to_owned(), data.get(key)?.clone())))
        .collect();
    Some(Value::Object(forwarded))
}
