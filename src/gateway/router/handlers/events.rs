// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The HTTP arms of `events/list`, `events/subscribe` and
//! `events/unsubscribe` (MIK-7630). Never proxied to a backend: the gateway
//! answers these itself, from its own catalogue (design §7.8).

use serde_json::Value;

use crate::events::{Caller, EventsHub, RpcError};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::audit::CredentialKind;

/// The events principal: the task owner key (`route_task_owner`), the one
/// stable caller identity both eras share, so a task-settled event can be
/// matched to its owner (I4). `None` when authentication is off or the
/// caller presented no credential: webhook mode needs a principal.
pub(super) fn principal(owner: &str, auth_enabled: bool) -> Option<String> {
    (auth_enabled && !owner.is_empty()).then(|| owner.to_owned())
}

/// The credential `client` presented, as events keep it.
pub(super) fn credential(
    client: Option<&crate::gateway::auth::AuthenticatedClient>,
) -> crate::events::Credential {
    crate::events::Credential {
        kind: CredentialKind::of(client),
        api_key: api_key(client),
    }
}

/// The API key `client` presented, if it presented one. Key-server tokens,
/// the static bearer and the other credentials have no `api_keys` entry for
/// the live re-check to read (design §3.7).
fn api_key(
    client: Option<&crate::gateway::auth::AuthenticatedClient>,
) -> Option<crate::events::ApiKeyRef> {
    client
        .filter(|c| c.authenticated && c.credential_kind == CredentialKind::ApiKey)
        .map(|c| crate::events::ApiKeyRef {
            name: c.name.clone(),
            principal: c.principal.clone(),
        })
}

/// Answer one `events/*` request.
pub(super) async fn answer(
    hub: &std::sync::Arc<EventsHub>,
    id: RequestId,
    method: &str,
    params: Option<&Value>,
    caller: &Caller,
) -> JsonRpcResponse {
    let result = match method {
        "events/list" => hub.list(caller, params),
        "events/subscribe" => hub.subscribe(caller, params).await,
        "events/unsubscribe" => hub.unsubscribe(caller, params).await,
        _ => Err(RpcError::method_not_found()),
    };
    match result {
        Ok(value) => JsonRpcResponse::success(id, value),
        Err(RpcError {
            code,
            message,
            data: Some(data),
        }) => JsonRpcResponse::error_with_data(Some(id), code, message, data),
        Err(RpcError { code, message, .. }) => JsonRpcResponse::error(Some(id), code, message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::auth::AuthenticatedClient;

    fn client(kind: CredentialKind, authenticated: bool) -> AuthenticatedClient {
        AuthenticatedClient {
            name: "alice".to_owned(),
            rate_limit: 0,
            backends: vec!["*".to_owned()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
            principal: "0123456789ab".to_owned(),
            quota_principal: None,
            authenticated,
            credential_kind: kind,
        }
    }

    /// Only a configured API key has an `api_keys` entry to re-check
    /// against; a key-server token or the static bearer carries none.
    #[test]
    fn only_an_authenticated_api_key_is_kept_for_the_live_re_check() {
        let key = api_key(Some(&client(CredentialKind::ApiKey, true))).expect("an API key");
        assert_eq!(
            (key.name.as_str(), key.principal.as_str()),
            ("alice", "0123456789ab")
        );
        for kind in [
            CredentialKind::KeyServerToken,
            CredentialKind::OidcBearer,
            CredentialKind::StaticBearer,
        ] {
            assert_eq!(api_key(Some(&client(kind, true))), None, "{kind:?}");
        }
        assert_eq!(api_key(Some(&client(CredentialKind::ApiKey, false))), None);
        assert_eq!(api_key(None), None);
    }
}
