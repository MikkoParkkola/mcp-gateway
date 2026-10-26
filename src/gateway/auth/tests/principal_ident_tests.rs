// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-6704.IDENT.1a rows, moved from `tests/mik_6704_acs.rs` when
//! `AuthenticatedClient.principal` became crate-private (MIK-8697).

// ===========================================================================
// MIK-6704.IDENT.1a — authorization derives from the authenticated credential.
//
// `AuthenticatedClient::name` is operator-chosen text. `principal` is a digest
// of the secret that was actually validated. The distinction is the whole
// control: two API keys may be given the same name, and if authorization keyed
// on the name they could attach to each other's sessions.
//
// The naive assertion — "the principal is not the name" — passes on the broken
// code too, because a digest of the name is also not the name. So the rows
// below assert the two things a name-derived principal cannot do: separate two
// keys that share a name, and survive a rename.
// ===========================================================================

use crate::config::{ApiKeyConfig, AuthConfig};
use crate::gateway::auth::{ResolvedAuthConfig, anonymous_client};

fn key(name: &str, secret: &str) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(secret.as_bytes())),
        expires_at: None,
        name: name.to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        kind: crate::config::ApiKeyKind::Shared,
        ..Default::default()
    }
}

fn resolved(bearer: Option<&str>, keys: Vec<ApiKeyConfig>) -> ResolvedAuthConfig {
    ResolvedAuthConfig::from_config(
        &AuthConfig {
            enabled: true,
            bearer_token: bearer.map(str::to_string),
            api_keys: keys,
            public_paths: vec![],
            client_circuit_breaker: None,
            single_user: false,
            dashboard_session: crate::config::DashboardSessionConfig::default(),
        },
        crate::gateway::record_principal::TEST_RECORD_KEY,
    )
}

#[test]
fn ac_ident_1a_two_api_keys_sharing_a_name_are_not_the_same_principal() {
    // Both entries named "ops". Config load refuses this since 4.0.0 (a
    // name is a grant subject), but the principal must not lean on that
    // check: built here without it. If the principal came from the
    // name, these two holders would be one principal, and a session opened
    // by one would be attachable by the other.
    let cfg = resolved(
        None,
        vec![key("ops", "secret-alpha"), key("ops", "secret-beta")],
    );

    let alpha = cfg.validate_token("secret-alpha").expect("alpha is valid");
    let beta = cfg.validate_token("secret-beta").expect("beta is valid");

    assert_eq!(alpha.name, beta.name, "the shared name is the premise");
    assert_ne!(
        alpha.principal, beta.principal,
        "two holders of different secrets are two principals, however they \
         are labelled — a principal derived from the display name would \
         make these one, and either could attach to the other's session"
    );
}

#[test]
fn ac_ident_1a_renaming_a_key_does_not_move_the_principal() {
    // The other direction. The credential did not change, so the identity
    // behind it did not change. A principal that tracked the operator's
    // label would silently re-key every session on a rename.
    let before = resolved(None, vec![key("ops", "secret-alpha")])
        .validate_token("secret-alpha")
        .expect("valid");
    let after = resolved(None, vec![key("ops-renamed", "secret-alpha")])
        .validate_token("secret-alpha")
        .expect("valid");

    assert_ne!(before.name, after.name, "the rename is the premise");
    assert_eq!(
        before.principal, after.principal,
        "the same secret is the same principal; the label is presentation"
    );
}

#[test]
fn ac_ident_1a_two_bearer_tokens_are_not_the_same_principal() {
    // The static bearer arm hardcodes the name "bearer", so a name-derived
    // principal would collapse every deployment onto one identifier and
    // make the audit log unable to say which token was in use.
    let first = resolved(Some("token-one"), vec![])
        .validate_token("token-one")
        .expect("valid");
    let second = resolved(Some("token-two"), vec![])
        .validate_token("token-two")
        .expect("valid");

    assert_eq!(first.name, second.name, "the arm names itself the same way");
    assert_ne!(first.principal, second.principal);
}

#[test]
fn ac_ident_1a_an_identity_that_presented_no_credential_carries_no_principal() {
    // The boundary. No credential was validated, so there is nothing to
    // derive from, and the identity says both things: empty principal and
    // `authenticated` false. Authorization tests the flag, never the name.
    let anon = anonymous_client();
    assert!(!anon.authenticated);
    assert!(
        anon.principal.is_empty(),
        "an unauthenticated identity must not borrow a principal from its \
         name, or a rule written against a principal would admit it"
    );
}

#[test]
fn ac_ident_1a_a_credentialled_principal_is_not_the_credential() {
    // Derived, not carried. The field ends up in logs and audit records;
    // if it were the secret itself, every log line would be a credential
    // (CWE-532).
    let client = resolved(None, vec![key("ops", "secret-alpha")])
        .validate_token("secret-alpha")
        .expect("valid");
    assert!(!client.principal.is_empty());
    assert!(!client.principal.storage_form().contains("secret-alpha"));
}
