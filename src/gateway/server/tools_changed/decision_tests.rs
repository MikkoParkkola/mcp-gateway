// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-8127`: one announcement per change of the tools discovery shows. Every
//! row counts announcements; none asks only whether one happened.

use super::{Announced, Seen, fingerprint};
use crate::backend::tools_nudge::NudgeKind::{Changed, Resolved};
use crate::protocol::Tool;

fn tool(name: &str, description: &str) -> Tool {
    serde_json::from_value(serde_json::json!({
        "name": name,
        "description": description,
        "inputSchema": { "type": "object" }
    }))
    .expect("tool")
}

/// Instance `instance` registered, holding `tools` if `Some`.
fn held(instance: u64, tools: Option<&[Tool]>) -> Seen {
    Seen::Registered {
        instance,
        stored: tools.map(fingerprint),
        populated: tools.is_some(),
    }
}

const A: &str = "alpha";

#[test]
fn the_fingerprint_ignores_order_and_sees_every_field() {
    let (x, y) = (tool("x", "one"), tool("y", "two"));
    assert_eq!(
        fingerprint(&[x.clone(), y.clone()]),
        fingerprint(&[y.clone(), x.clone()])
    );
    assert_ne!(
        fingerprint(&[x.clone(), y]),
        fingerprint(&[x, tool("y", "changed")])
    );
}

#[test]
fn registration_alone_announces_nothing() {
    let mut told = Announced::default();
    assert!(!told.backend(A, 1, Changed, &held(1, None)));
}

#[test]
fn each_distinct_list_is_announced_once_and_a_refill_never() {
    let mut told = Announced::default();
    let first = [tool("x", "one")];
    let second = [tool("x", "one"), tool("y", "two")];
    let mut count = 0;
    for list in [&first[..], &first[..], &second[..], &second[..]] {
        count += usize::from(told.backend(A, 1, Changed, &held(1, Some(list))));
    }
    assert_eq!(count, 2, "two distinct lists, two identical refills");
}

#[test]
fn a_stored_empty_list_is_no_change_from_nothing() {
    let mut told = Announced::default();
    assert!(!told.backend(A, 1, Changed, &held(1, Some(&[]))));
}

#[test]
fn a_replacement_with_the_same_tools_announces_nothing() {
    let mut told = Announced::default();
    let tools = [tool("x", "one")];
    assert!(told.backend(A, 1, Changed, &held(1, Some(&tools))));
    assert!(!told.backend(A, 2, Changed, &held(2, None)), "registration");
    assert!(
        !told.backend(A, 2, Changed, &held(2, Some(&tools))),
        "same fill"
    );
}

#[test]
fn a_replacement_with_other_tools_announces_once() {
    let mut told = Announced::default();
    assert!(told.backend(A, 1, Changed, &held(1, Some(&[tool("x", "one")]))));
    assert!(!told.backend(A, 2, Changed, &held(2, None)));
    assert!(told.backend(A, 2, Changed, &held(2, Some(&[tool("x", "two")]))));
}

#[test]
fn a_replacement_that_cannot_list_yet_announces_the_loss_then_the_return() {
    let mut told = Announced::default();
    let tools = [tool("x", "one")];
    assert!(told.backend(A, 1, Changed, &held(1, Some(&tools))));
    assert!(!told.backend(A, 2, Changed, &held(2, None)));
    // Its first attempt failed: discovery now shows nothing for it.
    assert!(told.backend(A, 2, Resolved, &held(2, None)));
    assert!(!told.backend(A, 2, Resolved, &held(2, None)), "said once");
    assert!(told.backend(A, 2, Changed, &held(2, Some(&tools))));
}

#[test]
fn a_list_stored_then_dropped_before_the_drain_looked_counts_as_nothing() {
    // The drain missed the store; the slot's memory that it stored one is
    // what keeps a failed refill from waiting forever as undecided.
    let mut told = Announced::default();
    assert!(told.backend(A, 1, Changed, &held(1, Some(&[tool("x", "one")]))));
    let dropped = Seen::Registered {
        instance: 2,
        stored: None,
        populated: true,
    };
    assert!(told.backend(A, 2, Changed, &dropped));
}

#[test]
fn a_late_nudge_from_a_replaced_instance_is_ignored() {
    let mut told = Announced::default();
    assert!(told.backend(A, 1, Changed, &held(1, Some(&[tool("x", "one")]))));
    assert!(!told.backend(A, 1, Resolved, &held(2, None)));
    assert!(!told.backend(A, 1, Changed, &held(2, None)));
}

#[test]
fn resolved_after_a_list_was_stored_changes_nothing() {
    let mut told = Announced::default();
    let tools = [tool("x", "one")];
    assert!(told.backend(A, 1, Changed, &held(1, Some(&tools))));
    assert!(!told.backend(A, 1, Resolved, &held(1, Some(&tools))));
}

#[test]
fn removal_announces_only_what_was_shown() {
    let mut told = Announced::default();
    assert!(told.backend(A, 1, Changed, &held(1, Some(&[tool("x", "one")]))));
    assert!(told.backend(A, 1, Changed, &Seen::Unregistered));
    assert!(!told.backend("never", 7, Changed, &held(7, None)));
    assert!(!told.backend("never", 7, Changed, &Seen::Unregistered));
}

#[test]
fn a_name_reused_after_removal_starts_clean() {
    let mut told = Announced::default();
    let tools = [tool("x", "one")];
    assert!(told.backend(A, 1, Changed, &held(1, Some(&tools))));
    assert!(told.backend(A, 1, Changed, &Seen::Unregistered));
    assert!(!told.backend(A, 3, Changed, &held(3, None)));
    assert!(told.backend(A, 3, Changed, &held(3, Some(&tools))));
}

#[test]
fn a_catalogue_announces_only_changes_from_nothing_onwards() {
    let mut told = Announced::default();
    let (one, none) = (fingerprint(&[tool("c", "one")]), fingerprint(&[]));
    assert!(!told.catalogue("caps", none), "an empty startup scan");
    assert!(told.catalogue("caps", one));
    assert!(!told.catalogue("caps", one), "an unchanged reload");
    assert!(told.catalogue("caps", none));
    let mut fresh = Announced::default();
    assert!(fresh.catalogue("caps", one), "a startup scan with tools");
}
