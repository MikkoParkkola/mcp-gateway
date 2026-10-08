// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit rows for the reconcile decision (design r3 D1a, D2, D3, D4).

use std::collections::BTreeSet;

use super::*;

fn set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|n| (*n).to_owned()).collect()
}

fn fate(name: &str, expired: bool, present: &[&str], ineligible: &[&str], complete: bool) -> Fate {
    let (present, ineligible) = (set(present), set(ineligible));
    let view = BackendView {
        present: &present,
        ineligible: &ineligible,
        complete,
    };
    backend_fate(name, expired, &view).expect("a backend row")
}

#[test]
fn a_present_eligible_backends_rows_are_live() {
    for kind in [
        "tools_changed",
        "resources_changed",
        "resource_updated",
        "prompts_changed",
    ] {
        let name = format!("backend.b.{kind}");
        assert_eq!(fate(&name, false, &["b"], &[], true), Fate::Live, "{kind}");
    }
}

/// D1a: absent from a complete view, every kind is withdrawn.
#[test]
fn an_absent_backend_under_a_complete_view_is_withdrawn() {
    for kind in ["tools_changed", "resources_changed", "prompts_changed"] {
        let name = format!("backend.b.{kind}");
        assert_eq!(
            fate(&name, false, &[], &[], true),
            Fate::Withdrawn,
            "{kind}"
        );
    }
}

/// D2: absent from a partial view, the row is held, not withdrawn.
#[test]
fn an_absent_backend_under_a_partial_view_is_held() {
    assert_eq!(
        fate("backend.b.resources_changed", false, &[], &[], false),
        Fate::Held
    );
}

/// D3: ineligible withdraws the upstream kinds and keeps tool changes.
#[test]
fn an_ineligible_backend_keeps_only_tool_changes() {
    assert_eq!(
        fate("backend.b.tools_changed", false, &["b"], &["b"], true),
        Fate::Live
    );
    for kind in ["resources_changed", "resource_updated", "prompts_changed"] {
        let name = format!("backend.b.{kind}");
        assert_eq!(
            fate(&name, false, &["b"], &["b"], true),
            Fate::Withdrawn,
            "{kind}"
        );
    }
}

/// D4: expiry wins over every other judgement.
#[test]
fn an_expired_row_is_expired_whatever_the_view() {
    assert_eq!(
        fate("backend.b.tools_changed", true, &[], &[], true),
        Fate::Expired
    );
    assert_eq!(
        fate("backend.b.tools_changed", true, &["b"], &[], true),
        Fate::Expired
    );
}

#[test]
fn a_non_backend_row_is_left_to_its_source() {
    let (present, ineligible) = (set(&[]), set(&[]));
    let view = BackendView {
        present: &present,
        ineligible: &ineligible,
        complete: true,
    };
    assert_eq!(backend_fate("webhook.github.push", false, &view), None);
}
