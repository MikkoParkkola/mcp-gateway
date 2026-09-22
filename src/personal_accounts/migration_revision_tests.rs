// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-6744.STORE.1 §7.3 — the descriptor fingerprint.
//!
//! The shape tests are cheap; the ones that matter are the sensitivity tests,
//! and they are written as PAIRS. A fingerprint that never changes passes every
//! "same input, same output" test ever written, so each field that must move
//! the value has a case, and the two fields that must NOT move it have one too.

use super::descriptor_revision;
use crate::personal_accounts::config::{AccountDescriptor, DescriptorMode};

fn base() -> AccountDescriptor {
    AccountDescriptor {
        mode: DescriptorMode::PersonalManaged,
        provider: "google".to_owned(),
        resource: Some("https://www.googleapis.com/drive/v3".to_owned()),
        issuer: Some("https://accounts.google.com".to_owned()),
        authorization_endpoint: None,
        token_endpoint: None,
        revocation_endpoint: None,
        client_id: Some("client-abc".to_owned()),
        client_secret_ref: Some("env:GOOGLE_SECRET".to_owned()),
        redirect_uri: None,
        scopes: Some(vec!["drive.readonly".to_owned()]),
        send_resource_parameter: Some(true),
        external_strategy: None,
    }
}

fn rev(descriptor: &AccountDescriptor) -> String {
    descriptor_revision(descriptor).expect("a valid descriptor must fingerprint")
}

/// The format `validate_record` demands: 64 lowercase hex, by construction.
#[test]
fn the_revision_is_64_lowercase_hex() {
    let value = rev(&base());
    assert_eq!(value.len(), 64, "storage.rs:135 demands exactly 64");
    assert!(
        value
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "lowercase hex only: {value}"
    );
}

/// Deterministic over unchanged inputs, or the fence would fire on every start.
#[test]
fn the_same_descriptor_fingerprints_the_same_twice() {
    assert_eq!(rev(&base()), rev(&base()));
}

/// THE SECURITY-CRITICAL SENSITIVITY. A widened scope must move the value.
///
/// This is the case §7.3's worked example is about: the `AccountKey` is
/// unchanged, so every stored grant still resolves, and without this the
/// fingerprint is blind to a user keeping a narrower token than the
/// configuration claims.
#[test]
fn widening_scopes_moves_the_revision() {
    let mut widened = base();
    widened.scopes = Some(vec!["drive.readonly".to_owned(), "drive.file".to_owned()]);
    assert_ne!(rev(&base()), rev(&widened));
}

/// Scope ORDER must not move it: the same grant declared in another order is
/// the same grant, and a fingerprint that fired on reordering would ask every
/// user to reconnect over a cosmetic config edit.
#[test]
fn reordering_scopes_does_not_move_the_revision() {
    let mut a = base();
    a.scopes = Some(vec!["b".to_owned(), "a".to_owned()]);
    let mut b = base();
    b.scopes = Some(vec!["a".to_owned(), "b".to_owned()]);
    assert_eq!(
        rev(&a),
        rev(&b),
        "scope order is not semantic, so the fingerprint canonicalises before \
         hashing; firing on a reorder would ask every user to reconnect over a \
         cosmetic config edit"
    );
}

/// Every other field the key cannot see moves the value.
///
/// One case per field, because a fingerprint that silently drops a field is
/// exactly the defect the first version of §7.3 shipped.
#[test]
fn every_key_invisible_field_moves_the_revision() {
    let baseline = rev(&base());
    let mut cases: Vec<(&str, AccountDescriptor)> = Vec::new();

    let mut d = base();
    d.provider = "microsoft".to_owned();
    cases.push(("provider", d));

    let mut d = base();
    d.mode = DescriptorMode::Shared;
    cases.push(("mode", d));

    let mut d = base();
    d.client_id = Some("client-xyz".to_owned());
    cases.push(("client_id", d));

    let mut d = base();
    d.client_secret_ref = Some("env:OTHER_SECRET".to_owned());
    cases.push(("client_secret_ref", d));

    let mut d = base();
    d.token_endpoint = Some("https://oauth2.example/token".to_owned());
    cases.push(("token_endpoint", d));

    let mut d = base();
    d.authorization_endpoint = Some("https://oauth2.example/auth".to_owned());
    cases.push(("authorization_endpoint", d));

    let mut d = base();
    d.revocation_endpoint = Some("https://oauth2.example/revoke".to_owned());
    cases.push(("revocation_endpoint", d));

    let mut d = base();
    d.redirect_uri = Some("http://127.0.0.1:7777/cb".to_owned());
    cases.push(("redirect_uri", d));

    let mut d = base();
    d.send_resource_parameter = Some(false);
    cases.push(("send_resource_parameter true->false", d));

    let mut d = base();
    d.send_resource_parameter = None;
    cases.push(("send_resource_parameter declared->absent", d));

    for (field, descriptor) in cases {
        assert_ne!(
            baseline,
            rev(&descriptor),
            "changing {field} must move the descriptor revision"
        );
    }
}

/// `resource` and `issuer` must NOT move it, because `AccountKey` already
/// discriminates them.
///
/// Hashing them would duplicate the key: a change to either moves the key, the
/// old record is never found, and no fence is needed. This is the other
/// direction of the field-set decision and it is what stops the fingerprint
/// being redefined as "hash everything" by a later edit.
#[test]
fn the_two_fields_already_in_the_account_key_do_not_move_the_revision() {
    let baseline = rev(&base());

    let mut moved_resource = base();
    moved_resource.resource = Some("https://www.googleapis.com/calendar/v3".to_owned());
    assert_eq!(
        baseline,
        rev(&moved_resource),
        "resource is in the AccountKey; hashing it here adds nothing the key \
         does not already do"
    );

    let mut moved_issuer = base();
    moved_issuer.issuer = Some("https://login.microsoftonline.com".to_owned());
    assert_eq!(baseline, rev(&moved_issuer), "and so is oauth_issuer");
}

/// A declared-empty `scopes` and an absent one fingerprint the same.
///
/// Recorded rather than asserted as correct: for `scopes` the two mean the same
/// thing operationally, which is why §7.2a(b) treats both as "the descriptor
/// declares none". `send_resource_parameter` is the field where the
/// distinction matters, and it is rendered as a tri-state for that reason --
/// covered by the pair above.
#[test]
fn an_empty_scope_list_and_an_absent_one_agree() {
    let mut empty = base();
    empty.scopes = Some(Vec::new());
    let mut absent = base();
    absent.scopes = None;
    assert_eq!(rev(&empty), rev(&absent));
}
