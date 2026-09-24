// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The caller behind a held credential, as authorization sees it now.
//!
//! A session outlives the request that opened it, so anything delivered to it
//! later must ask the authorizer again: a snapshot taken at session start keeps
//! granting access after the token behind it is revoked or expires.

use super::{AuthState, AuthenticatedClient, anonymous_client, key_server_credential};

/// A bearer credential kept for re-validation. `Debug` never prints it.
#[derive(Clone)]
pub(crate) struct HeldCredential(String);

impl std::fmt::Debug for HeldCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HeldCredential(<redacted>)")
    }
}

/// The bearer credential `headers` present, held for later re-validation.
pub(crate) fn held_credential(headers: &axum::http::HeaderMap) -> Option<HeldCredential> {
    super::presented_credential(headers).map(HeldCredential)
}

/// The client `credential` authenticates as right now.
///
/// Mirrors the middleware's credential order (static keys, then the key
/// server) but not its public-path fallback: a credential that no longer
/// validates yields `None`, never the public identity. With authentication on,
/// a session that presented no credential yields `None` as well.
pub(crate) async fn current_client(
    state: &AuthState,
    credential: Option<&HeldCredential>,
) -> Option<AuthenticatedClient> {
    if !state.auth_config.enabled {
        return Some(anonymous_client());
    }
    let token = credential?.0.as_str();
    if let Some((client, _)) = state.auth_config.validate_token_with_origin(token) {
        return Some(client);
    }
    key_server_credential(state, token)
        .await
        .map(|(client, _, _)| client)
}
