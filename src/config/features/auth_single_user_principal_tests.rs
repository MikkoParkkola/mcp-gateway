// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Whether exactly one human is proven to be behind the auth configuration.

use super::*;

pub(super) fn api_key(name: &str) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(super::super::api_key::api_key_digest_spec(
            format!("k-{name}").as_bytes(),
        )),
        expires_at: None,
        name: name.to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        kind: crate::config::ApiKeyKind::Shared,
    }
}

/// The population this exists for: a 3.x personal gateway that took the
/// upgrade advice at `commands/upgrade.rs:144` and set `single_user: true`.
pub(super) fn solo() -> AuthConfig {
    AuthConfig {
        enabled: true,
        bearer_token: Some("the-operator's-own-token".to_string()),
        single_user: true,
        ..AuthConfig::default()
    }
}

#[test]
fn asserted_solo_gateway_may_mint_the_principal() {
    assert!(
        solo().grants_single_user_principal(false),
        "enabled auth + the operator's explicit assertion + no second credential is the \
             whole positive case"
    );
}

#[test]
fn one_api_key_still_mints_the_principal() {
    // `<= 1`, not `== 1`: a bearer-only gateway and a one-key gateway are
    // the same deployment shape, and the operator asserted both are one
    // person. Neither has a second credential to hand to anyone.
    let cfg = AuthConfig {
        bearer_token: None,
        api_keys: vec![api_key("me")],
        ..solo()
    };
    assert!(cfg.grants_single_user_principal(false));
    assert!(!cfg.implies_multi_user(false));
}

/// THE SECURITY CASE. This is the defect §4.1a of the design doc records:
/// `implies_multi_user` returns `false` when auth is switched off, because
/// with no auth boundary the per-user isolation question is moot. Its
/// negation therefore reads "one user is present", which is the opposite of
/// what an unauthenticated gateway means. Minting here would hand the stored
/// OAuth grants to any anonymous caller that can reach the port.
#[test]
fn disabled_auth_never_mints_the_principal() {
    let cfg = AuthConfig {
        enabled: false,
        ..solo()
    };
    assert!(
        !cfg.grants_single_user_principal(false),
        "absence of authentication is not the presence of one user"
    );
    assert!(
        !AuthConfig::default().grants_single_user_principal(false),
        "the shipped default mints nothing"
    );
}

#[test]
fn two_api_keys_never_mint_the_principal() {
    let cfg = AuthConfig {
        api_keys: vec![api_key("laptop"), api_key("phone")],
        ..solo()
    };
    assert!(
        !cfg.grants_single_user_principal(false),
        "a second credential can be handed to a second human; the assertion is overridden"
    );
}

#[test]
fn any_identity_provider_never_mints_the_principal() {
    assert!(
        !solo().grants_single_user_principal(true),
        "an IdP means real per-user principals exist and the assertion is overridden"
    );
}

/// Without the operator saying so, nothing is asserted and nothing is minted
/// — the same fail-closed default `single_user` already carries (ADR-008
/// INV-2).
#[test]
fn unasserted_auth_never_mints_the_principal() {
    let cfg = AuthConfig {
        single_user: false,
        ..solo()
    };
    assert!(!cfg.grants_single_user_principal(false));
}

/// An OIDC issuer is the only authority a real `VerifiedIdentity` can carry
/// (`key_server/oidc.rs`), and this predicate is false whenever one is
/// configured. So the sole-operator authority and the OIDC issuer namespace
/// never coexist in one deployment.
///
/// Structural, not enforced: nothing validates that `principal_authority` is
/// a URL (design doc §3), so this is a consequence of the configuration
/// rather than a rule the code checks. Recorded as such rather than
/// presented as a boundary.
#[test]
fn the_two_authority_namespaces_never_coexist() {
    for enabled in [true, false] {
        for single_user in [true, false] {
            for keys in 0..3 {
                let cfg = AuthConfig {
                    enabled,
                    single_user,
                    api_keys: (0..keys).map(|i| api_key(&i.to_string())).collect(),
                    ..AuthConfig::default()
                };
                assert!(
                    !cfg.grants_single_user_principal(true),
                    "no configuration with an IdP may also mint the sole-operator principal"
                );
            }
        }
    }
}
