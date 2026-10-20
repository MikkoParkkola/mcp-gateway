// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit rows for the one binding judgement and the one binding token
//! (MIK-8407 design r2-r4, MIK-8440).

use super::{Refusal, binding_token, judge};
use crate::config::account_bindings::account_fingerprint;
use crate::identity_propagation::AccountStrategyRegistry;
use crate::personal_accounts::config::DescriptorMode;

fn step(binding: Option<&str>) -> (String, String, Option<String>) {
    (
        "srv".to_owned(),
        "read".to_owned(),
        binding.map(str::to_owned),
    )
}

fn now(binding: Option<&'static str>) -> impl Fn(&str, &str) -> Option<String> {
    move |_, _| binding.map(str::to_owned)
}

/// The refusal a mismatch answers with, word for word.
fn rebound() -> String {
    Refusal::Rebound.error("srv").to_string()
}

/// RB-unit-equal: the recorded binding is current: served.
#[test]
fn rb_unit_equal_binding_is_served() {
    assert!(judge(&[step(Some("a#1"))], now(Some("a#1"))).is_ok());
    assert!(judge(&[step(None)], now(None)).is_ok(), "none equals none");
    assert!(judge(&[], now(Some("a#1"))).is_ok(), "nothing recorded");
}

/// RB-unit-rebound (mutant M-judge): another account, or none on either
/// side, is refused with the one refusal.
#[test]
fn rb_unit_another_binding_is_refused() {
    for (recorded, current) in [
        (Some("a#1"), Some("b#1")),
        (Some("a#1"), None),
        (None, Some("b#1")),
    ] {
        let refused = judge(&[step(recorded)], now(current)).expect_err("refused");
        assert_eq!(
            refused.to_string(),
            rebound(),
            "{recorded:?} vs {current:?}"
        );
    }
}

/// RB-unit-twice: a step recorded under two bindings is refused whichever
/// one is current.
#[test]
fn rb_unit_a_step_recorded_twice_is_refused() {
    let twice = [step(Some("a#1")), step(Some("b#1"))];
    assert!(judge(&twice, now(Some("a#1"))).is_err());
    assert!(judge(&twice, now(Some("b#1"))).is_err());
}

/// RB-unit-legacy: the legacy refusal is its own text, naming the re-run.
#[test]
fn rb_unit_legacy_refusal_is_distinct() {
    let legacy = Refusal::Legacy.error("srv").to_string();
    assert_ne!(legacy, rebound());
    assert!(legacy.contains("predates credential binding"), "{legacy}");
    assert!(legacy.contains("new idempotency key"), "{legacy}");
}

/// The token of `descriptor` declared as `work`.
fn token_of(descriptor: &crate::personal_accounts::config::AccountDescriptor) -> String {
    let registry = AccountStrategyRegistry::default();
    registry.declare(
        "work",
        &descriptor.provider,
        DescriptorMode::PersonalManaged,
        &account_fingerprint(descriptor),
    );
    binding_token(&registry, "work")
}

/// RB-unit-issuer, RB-unit-resource, RB-unit-scope (gpt r1, grok r2): the
/// same descriptor id with another issuer, resource or scope set is another
/// binding.
#[test]
fn rb_unit_a_changed_descriptor_under_the_same_id_is_another_binding() {
    let base = crate::gateway::meta_mcp::account_rest_fixture::managed("work");
    let token = token_of(&base);
    assert_eq!(token, token_of(&base.clone()), "the token is stable");
    let mut issuer = base.clone();
    issuer.issuer = Some("https://other-issuer.invalid".to_owned());
    let mut resource = base.clone();
    resource.resource = Some("https://other-resource.invalid".to_owned());
    let mut scopes = base.clone();
    scopes.scopes = Some(vec!["narrow".to_owned()]);
    for (row, changed) in [
        ("issuer", issuer),
        ("resource", resource),
        ("scopes", scopes),
    ] {
        assert_ne!(token_of(&changed), token, "{row}: same token");
    }
}

/// RB-unit-undeclared: an id no descriptor declares never equals a declared
/// one's token.
#[test]
fn rb_unit_an_undeclared_id_matches_no_declared_token() {
    let base = crate::gateway::meta_mcp::account_rest_fixture::managed("work");
    let undeclared = binding_token(&AccountStrategyRegistry::default(), "work");
    assert_eq!(undeclared, "work#");
    assert_ne!(undeclared, token_of(&base));
}
