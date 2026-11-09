// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A prepared target's signing-time allow lives on its one invocation
//! context and is taken, never copied: the dispatch that skips its own check
//! reads it once, and nothing after it in the same context finds it again.

use super::SigningInvocationContext;
use crate::security::decision_record::{Allow, AllowRank};
use crate::security::rule_id::{RuleId, RuleKey};

/// ATTR.1, within one context. Signing keeps the grant that allowed the
/// prepared target; the first take returns it whole and a second take finds
/// nothing. Kills M12 (the allow not stored) and M13 (cloned, not taken).
#[test]
fn a_prepared_allow_is_taken_exactly_once() {
    let context = SigningInvocationContext::prepared_for_test("personal_caps", "calendar_read_day");
    let allow = Allow {
        rank: AllowRank::Grant,
        rule_id: Some(RuleId::of("grant", &RuleKey::from_derived([3; 32]), b"g-m")),
        grant_id: Some("g-m".to_owned()),
    };
    assert_eq!(
        context.take_prepared_allow(),
        None,
        "premise: none before signing"
    );
    context.store_prepared_allow(Some(allow.clone()));
    assert_eq!(
        context.take_prepared_allow(),
        Some(allow),
        "the dispatch takes what signing kept"
    );
    assert_eq!(
        context.take_prepared_allow(),
        None,
        "a second take in the same context inherits nothing"
    );
}
