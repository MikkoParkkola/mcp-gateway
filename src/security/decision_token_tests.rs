// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which callers' decisions carry a token reference and when its absence is marked.

use super::token_on_decision;
#[cfg(debug_assertions)]
use super::{Decided, Noted, Refused};
use crate::security::audit::CredentialKind;
use crate::security::transparency_log::issuance::{IssuanceRow, TokenOnCall};

/// A key server caller with no token scope marks the reference unavailable.
#[test]
fn a_key_server_call_without_a_token_scope_is_marked_unavailable() {
    assert_eq!(
        token_on_decision(CredentialKind::KeyServerToken, None),
        (None, true)
    );
}

/// A key server caller keeps the literal token reference from its scope.
#[test]
fn a_key_server_call_in_a_token_scope_carries_that_token() {
    let literal = TokenOnCall {
        jti: "jti-literal".into(),
        issuance_row: Some(IssuanceRow {
            counter: 7,
            entry_hash: "sha256:literal".into(),
        }),
    };
    assert_eq!(
        token_on_decision(CredentialKind::KeyServerToken, Some(literal.clone())),
        (Some(literal), false)
    );
}

/// Other caller kinds omit both the token and the unavailable marker.
#[test]
fn other_callers_never_carry_or_mark_a_token() {
    for kind in [
        CredentialKind::ApiKey,
        CredentialKind::LocalTransport,
        CredentialKind::StaticBearer,
        CredentialKind::None,
    ] {
        assert_eq!(token_on_decision(kind, None), (None, false), "{kind:?}");
    }
}

/// Building a key server decision without a token scope panics in debug tests.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "no token on this call")]
fn building_a_key_server_decision_outside_a_token_scope_fails_in_tests() {
    Noted::default().decision(
        Decided::Fresh,
        Refused::No,
        None,
        CredentialKind::KeyServerToken,
    );
}
