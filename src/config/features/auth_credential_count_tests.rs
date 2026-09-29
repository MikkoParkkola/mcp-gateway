// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2241: the bearer token counts as a credential beside the API keys, in
//! both the sole-operator grant and the multi-user (ADR-008 INV-2) predicate.

use super::AuthConfig;
use super::single_user_principal_tests::{api_key, solo};

#[test]
fn bearer_only_still_mints_the_principal() {
    assert!(solo().grants_single_user_principal(false));
    assert!(!solo().implies_multi_user(false));
}

/// #2241: the bearer token and an API key are two credentials, so two
/// callers, whatever `single_user` asserts. Every spelling of a configured
/// bearer counts: `auto` is generated at load and `env:` is resolved or
/// the load fails, so each is a live second credential.
#[test]
fn bearer_plus_one_api_key_is_two_credentials() {
    for bearer in ["the-operator's-own-token", "auto", "env:GATEWAY_BEARER"] {
        let cfg = AuthConfig {
            bearer_token: Some(bearer.to_string()),
            api_keys: vec![api_key("client")],
            ..solo()
        };
        assert!(
            !cfg.grants_single_user_principal(false),
            "bearer `{bearer}` plus a key must not mint the sole operator"
        );
        assert!(
            cfg.implies_multi_user(false),
            "bearer `{bearer}` plus a key must arm the per-user isolation guard"
        );
    }
}

#[test]
fn bearer_plus_key_without_the_assertion_stays_multi_user() {
    let cfg = AuthConfig {
        api_keys: vec![api_key("client")],
        single_user: false,
        ..solo()
    };
    assert!(!cfg.grants_single_user_principal(false));
    assert!(cfg.implies_multi_user(false));
}

#[test]
fn bearer_plus_key_with_auth_off_grants_nothing() {
    let cfg = AuthConfig {
        enabled: false,
        api_keys: vec![api_key("client")],
        ..solo()
    };
    assert!(!cfg.grants_single_user_principal(false));
    assert!(!cfg.implies_multi_user(false));
}
