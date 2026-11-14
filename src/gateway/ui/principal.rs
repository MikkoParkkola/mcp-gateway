// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The per-session principal a caller-bound token or confirmation binds to.
//! One definition, so two bindings cannot disagree on who the same caller is.
//!
//! Permitted callers: only code that binds a token or a confirmation to the
//! caller's per-session principal. Today that is exactly two: the sealed page
//! token of `activity::key_lookup` and the restart confirmation. A third
//! caller needs its own design note saying why.

use crate::gateway::auth::AuthenticatedClient;

/// The digest a token binds to; `None` when the caller has nothing to bind to,
/// in which case no token is minted or opened. One function for both, so they
/// cannot disagree.
///
/// A bearer or API key binds to its credential principal. Every dashboard
/// session carries the same constant principal, so a session binds to its own
/// cookie handle instead (hashed, never sent anywhere): two browser sessions
/// cannot open each other's tokens.
pub(super) fn cursor_principal(
    client: Option<&AuthenticatedClient>,
    headers: &axum::http::HeaderMap,
) -> Option<String> {
    use crate::security::audit::CredentialKind;
    let client = client?;
    let principal = client.credential_principal()?;
    let digest = |tag: &str, material: &str| {
        crate::hashing::sha256_hex(format!("{tag}\0{material}").as_bytes())
    };
    match client.credential_kind {
        // Every dashboard session carries the same principal: its own cookie
        // handle is what tells two sessions apart. An empty handle is no
        // session.
        CredentialKind::DashboardSession => {
            let handle = crate::gateway::auth::session_cookie_value(headers)?;
            (!handle.is_empty()).then(|| digest("dashboard-session", &handle))
        }
        // A digest of the one secret the caller presented.
        CredentialKind::StaticBearer
        | CredentialKind::ApiKey
        | CredentialKind::KeyServerToken
        | CredentialKind::OidcBearer => {
            Some(digest("credential-principal", principal.storage_form()))
        }
        // Nothing to bind a token to: no token is minted or opened.
        CredentialKind::None | CredentialKind::LocalTransport => None,
    }
}
