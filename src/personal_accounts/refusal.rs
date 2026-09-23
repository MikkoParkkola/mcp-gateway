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

use serde_json::json;

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

/// The §9.1 `data` keys, forwarded to the client by name like every other
/// gateway-authored key.
pub(crate) const ACCOUNT_DATA_KEYS: [&str; 5] = [
    "schema_version",
    "error",
    "account_id",
    "connect_url",
    "retry_after",
];

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
