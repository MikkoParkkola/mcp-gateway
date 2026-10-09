// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The HTTP arms of `events/list`, `events/subscribe` and
//! `events/unsubscribe` (MIK-7630). Never proxied to a backend: the gateway
//! answers these itself, from its own catalogue (design §7.8).

use serde_json::Value;

use crate::events::{Caller, EventsHub, LiveBinding, RpcError};
use crate::gateway::auth::live::CredentialFacts;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::audit::CredentialKind;

/// The events principal: the task owner key (`route_task_owner`), the one
/// stable caller identity both eras share, so a task-settled event can be
/// matched to its owner (I4). `None` when authentication is off or the
/// caller presented no credential: webhook mode needs a principal.
pub(super) fn principal(owner: &str, auth_enabled: bool) -> Option<String> {
    (auth_enabled && !owner.is_empty()).then(|| owner.to_owned())
}

/// What a request presented beyond its client, captured before the body is
/// read: the key-server facts, the verified identity and the dashboard
/// session's digest (MIK-7769). Never a secret.
pub(super) struct Presented {
    facts: Option<CredentialFacts>,
    identity: Option<crate::key_server::oidc::VerifiedIdentity>,
    session_sha256: Option<String>,
    /// The static bearer's full digest (MIK-7889); the principal is 48 bits.
    bearer_sha256: Option<String>,
}

impl Presented {
    pub(super) fn capture(request: &axum::http::Request<axum::body::Body>) -> Self {
        let extensions = request.extensions();
        Self {
            facts: extensions.get::<CredentialFacts>().cloned(),
            identity: extensions.get().cloned(),
            session_sha256: crate::gateway::auth::session_cookie_value(request.headers())
                .map(|handle| crate::hashing::sha256_hex(handle.as_bytes())),
            bearer_sha256: crate::gateway::auth::presented_bearer_sha256(request.headers()),
        }
    }

    /// The static bearer's binding: its full digest. With no bearer header to
    /// hash there is no binding, and a bound kind without its binding is
    /// refused at the re-check (fail closed), never kept on the 12-hex
    /// fingerprint.
    fn static_bearer_binding(&self) -> Option<LiveBinding> {
        self.bearer_sha256
            .clone()
            .map(|bearer_sha256| LiveBinding::StaticBearerSha256 { bearer_sha256 })
    }

    /// The credential `client` presented, as events keep it. A key-server or
    /// delegated-bearer credential ends at its own expiry; a dashboard
    /// session at most one idle timeout from now, since activity alone
    /// extends it. Each kind but an API key carries the binding every
    /// delivery attempt re-checks (design F9).
    pub(super) fn credential(
        &self,
        client: Option<&crate::gateway::auth::AuthenticatedClient>,
        state: &super::super::AppState,
    ) -> crate::events::Credential {
        let kind = CredentialKind::of(client);
        let facts = self.facts.clone().unwrap_or(CredentialFacts {
            expires_at: None,
            jti: None,
            issued_at: None,
            provider_sha256: None,
        });
        let expires_at = match kind {
            CredentialKind::DashboardSession => {
                let config = state.live_config.get();
                let idle = config.auth.dashboard_session.idle_timeout_secs;
                let idle = chrono::Duration::seconds(i64::try_from(idle).unwrap_or(i64::MAX));
                chrono::Utc::now().checked_add_signed(idle)
            }
            _ => facts.expires_at,
        };
        let binding = match kind {
            CredentialKind::KeyServerToken => {
                facts.jti.map(|jti| LiveBinding::KeyServerToken { jti })
            }
            CredentialKind::OidcBearer => {
                self.identity.as_ref().map(|id| LiveBinding::OidcBearer {
                    issuer: id.issuer.clone(),
                    subject: id.subject.clone(),
                    email: id.email.clone(),
                    groups: id.groups.clone(),
                    issued_at: facts.issued_at,
                    provider_sha256: facts.provider_sha256.clone(),
                })
            }
            CredentialKind::StaticBearer => self.static_bearer_binding(),
            CredentialKind::DashboardSession => self
                .session_sha256
                .clone()
                .map(|session_sha256| LiveBinding::DashboardSession { session_sha256 }),
            CredentialKind::None | CredentialKind::LocalTransport | CredentialKind::ApiKey => None,
        };
        crate::events::Credential {
            kind,
            principal: client.map(|c| c.principal.clone()).unwrap_or_default(),
            api_key: api_key(client),
            expires_at,
            binding,
        }
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
#[path = "events_cov_tests.rs"]
mod cov_tests;

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
            principal: crate::gateway::auth::principal_of("secret"),
            quota_principal: None,
            authenticated,
            credential_kind: kind,
        }
    }

    /// MIK-7889 (#2695): a subscription made with the static bearer binds the
    /// bearer's full digest, taken from the request's own header.
    #[test]
    fn a_static_bearer_subscription_binds_the_full_digest() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer tok".parse().unwrap(),
        );
        let digest = crate::gateway::auth::presented_bearer_sha256(&headers);
        assert_eq!(digest, Some(crate::hashing::sha256_hex(b"tok")));
        let with = Presented {
            facts: None,
            identity: None,
            session_sha256: None,
            bearer_sha256: digest.clone(),
        };
        assert_eq!(
            with.static_bearer_binding(),
            Some(LiveBinding::StaticBearerSha256 {
                bearer_sha256: digest.unwrap()
            })
        );
        let without = Presented {
            bearer_sha256: None,
            ..with
        };
        assert_eq!(without.static_bearer_binding(), None, "fail closed");
        assert_eq!(
            crate::gateway::auth::presented_bearer_sha256(&axum::http::HeaderMap::new()),
            None
        );
    }

    /// Only a configured API key has an `api_keys` entry to re-check
    /// against; a key-server token or the static bearer carries none.
    #[test]
    fn only_an_authenticated_api_key_is_kept_for_the_live_re_check() {
        let key = api_key(Some(&client(CredentialKind::ApiKey, true))).expect("an API key");
        assert_eq!(key.name, "alice");
        assert_eq!(key.principal, crate::gateway::auth::principal_of("secret"));
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
