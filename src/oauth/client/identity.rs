// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Client identity: registration body, issuer check and credential keying.

/// Provenance of a `client_id` (MIK-6750 r7, Defect 2).
///
/// `purge_client_id_if_invalid` must never clear a [`Configured`](Self::Configured)
/// id: it is operator-supplied config (Slack, Figma, …) and erasing it on an
/// `invalid_client` rejection would delete valid configuration and guarantee
/// every subsequent attempt also fails, using a generated/DCR id the operator
/// never intended. Only a [`Registered`](Self::Registered) id — obtained via
/// Dynamic Client Registration, generated as a DCR fallback, or loaded from a
/// prior registration's persisted record — is safe to purge and re-register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ClientIdSource {
    /// Came from `OAuthClientConfig.client_id`. Never purgeable.
    Configured,
    /// Obtained via Dynamic Client Registration, a generated fallback, or a
    /// load of a previously dynamically-registered id from storage.
    Registered,
}

/// The Dynamic Client Registration body this gateway sends.
///
/// A free function so it can be asserted without a live authorization server:
/// these fields are what every server the gateway registers with sees, and they
/// were previously observable only by running one.
///
/// `application_type` is required by MCP 2026-07-28 and is not cosmetic.
/// `OpenID` Connect defaults an unstated value to `web`, which constrains
/// redirect URIs to https and forbids a literal loopback address — exactly what
/// a locally-running gateway registers. Saying `native` makes the registration
/// describe this client.
#[must_use]
pub fn registration_body(backend_name: &str, redirect_uri: &str) -> serde_json::Value {
    serde_json::json!({
        "client_name": format!("MCP Gateway - {backend_name}"),
        "application_type": "native",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none"
    })
}

/// Check the `iss` an authorization server returned against the one recorded.
///
/// MCP 2026-07-28, adopting RFC 9207: authorization servers **SHOULD** include
/// `iss` in the authorization response, and MCP clients **MUST** validate a
/// present `iss` against the recorded issuer before redeeming the code.
///
/// The attack is mix-up. A client that talks to several authorization servers
/// receives codes at one redirect endpoint and cannot otherwise tell which
/// server sent one; an attacker who controls a server it trusts can obtain a
/// code from a different one and have the client redeem it at the wrong token
/// endpoint. `state` does not close this — the attacker's own flow carries a
/// state the client itself issued.
///
/// Absence is allowed, deliberately. The specification makes including `iss` a
/// SHOULD and validating a **present** one a MUST; refusing its absence would
/// be a stricter rule than the specification states, imposed on servers this
/// gateway does not control and many of which have not adopted RFC 9207.
///
/// # Errors
///
/// Returns the mismatch when a present `iss` is not the recorded issuer.
pub fn validate_issuer(returned: Option<&str>, recorded: &str) -> std::result::Result<(), String> {
    match returned {
        None => Ok(()),
        // Exact string comparison, as issuer identifiers are defined. A
        // trailing slash, a case change or an explicit default port makes a
        // different identifier, and normalising any of them would reopen the
        // mix-up through a URL that merely looks the same.
        Some(iss) if iss == recorded => Ok(()),
        Some(iss) => Err(format!(
            "authorization response came from issuer '{iss}', not the recorded '{recorded}'; \
             the code was not redeemed"
        )),
    }
}

/// The storage key for a credential, keyed by the issuer that granted it.
///
/// MCP 2026-07-28: a client **MUST** key persisted credentials by the issuer
/// identifier, **MUST NOT** reuse them with a different authorization server,
/// and **MUST** re-register when the authorization server changes.
///
/// Keyed by backend alone, moving a backend from one authorization server to
/// another silently reuses a client id the new server never issued — and the
/// failure surfaces as a confusing rejection later rather than as the
/// re-registration it should have been.
#[must_use]
pub fn storage_key(backend_name: &str, issuer: &str) -> String {
    format!("{backend_name}\u{0}{issuer}")
}
