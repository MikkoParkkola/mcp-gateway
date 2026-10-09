// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-8148`: one hint per change of a per-user view. Every row counts.

use super::{SlotSeen, TOMBSTONE_CAP, Views};
use crate::gateway::server::tools_changed::fingerprint;
use crate::protocol::Tool;

fn tool(name: &str, description: &str) -> Tool {
    serde_json::from_value(serde_json::json!({
        "name": name,
        "description": description,
        "inputSchema": { "type": "object" }
    }))
    .expect("tool")
}

fn holds(tools: &[Tool]) -> SlotSeen {
    SlotSeen::Holds(fingerprint(tools))
}

/// An account binding as `vault.rs` `cache_binding` writes it.
fn acct(digest: &str, generation: &str, epoch: u64, revision: u64) -> String {
    format!(
        "acct:v1:{digest}:{}:{generation}:{epoch}:{revision}:64:{}",
        generation.len(),
        "0".repeat(64)
    )
}

const U1: &str = "idp:3:sub:3:aud";

#[test]
fn a_first_fill_announces_once_and_an_identical_refill_never() {
    let mut views = Views::new(1);
    let tools = [tool("x", "one")];
    assert!(
        !views.slot(U1, SlotSeen::Unfilled),
        "an open, unfilled slot"
    );
    assert!(views.slot(U1, holds(&tools)), "first fill after nothing");
    assert!(!views.slot(U1, holds(&tools)), "identical refill");
}

#[test]
fn an_empty_first_fill_is_no_change() {
    let mut views = Views::new(1);
    assert!(!views.slot(U1, holds(&[])));
}

#[test]
fn a_description_or_schema_change_announces_once() {
    let mut views = Views::new(1);
    assert!(views.slot(U1, holds(&[tool("x", "one")])));
    assert!(views.slot(U1, holds(&[tool("x", "two")])));
    assert!(!views.slot(U1, holds(&[tool("x", "two")])));
}

#[test]
fn a_token_refresh_with_the_same_tools_is_silent() {
    let mut views = Views::new(1);
    let tools = [tool("x", "one")];
    assert!(views.slot(&acct("d", "g", 1, 1), holds(&tools)));
    assert!(!views.slot(&acct("d", "g", 1, 2), holds(&tools)));
}

#[test]
fn a_late_store_into_an_old_revision_cannot_hide_the_current_change() {
    // K1: r1 {x}, r2 {y}, late r1 {z}, then r3 {z}.
    let mut views = Views::new(1);
    let (r1, r2, r3) = (
        acct("d", "g", 1, 1),
        acct("d", "g", 1, 2),
        acct("d", "g", 1, 3),
    );
    let (x, y, z) = ([tool("x", "")], [tool("y", "")], [tool("z", "")]);
    assert!(views.slot(&r1, holds(&x)));
    assert!(views.slot(&r2, holds(&y)));
    assert!(views.slot(&r1, holds(&z)), "an extra hint is allowed");
    assert!(
        views.slot(&r3, holds(&z)),
        "r3 inherits r2's {{y}}, not r1's {{z}}"
    );
}

#[test]
fn a_reconnect_starts_from_what_an_evicted_slot_showed() {
    let mut views = Views::new(1);
    let tools = [tool("x", "one")];
    let old = acct("d", "g1", 1, 1);
    assert!(views.slot(&old, holds(&tools)));
    assert!(!views.slot(&old, SlotSeen::Absent), "eviction alone");
    assert!(!views.slot(&acct("d", "g2", 1, 1), holds(&tools)));
}

#[test]
fn an_empty_refill_after_eviction_announces() {
    // K2: the evicted slot showed tools; the refill shows none.
    let mut views = Views::new(1);
    assert!(views.slot(U1, holds(&[tool("x", "one")])));
    assert!(!views.slot(U1, SlotSeen::Absent));
    assert!(views.slot(U1, holds(&[])));
}

#[test]
fn eviction_then_an_identical_refill_is_silent() {
    let mut views = Views::new(1);
    let tools = [tool("x", "one")];
    assert!(views.slot(U1, holds(&tools)));
    assert!(!views.slot(U1, SlotSeen::Absent));
    assert!(!views.slot(U1, holds(&tools)));
}

#[test]
fn removal_announces_when_only_a_tombstone_showed_tools() {
    let mut views = Views::new(1);
    assert!(!views.any_shown());
    assert!(views.slot(U1, holds(&[tool("x", "one")])));
    assert!(!views.slot(U1, SlotSeen::Absent));
    assert!(views.any_shown());
}

#[test]
fn a_tombstone_overflow_announces_instead_of_dropping_silently() {
    let mut views = Views::new(1);
    let tools = [tool("x", "one")];
    let mut announced = 0;
    for n in 0..=TOMBSTONE_CAP {
        let binding = format!("idp:1:{n}:0:");
        views.slot(&binding, holds(&tools));
        announced += usize::from(views.slot(&binding, SlotSeen::Absent));
    }
    assert_eq!(announced, 1, "one past the cap, one hint");
}

#[test]
fn a_recompute_sees_a_blocked_tool_and_an_evicted_slot() {
    let mut views = Views::new(1);
    let (x, xy) = ([tool("x", "")], [tool("x", ""), tool("y", "")]);
    assert!(views.slot(U1, holds(&xy)));
    assert!(views.slot("idp:1:b:0:", holds(&x)));
    // A verdict blocks y: U1's served view loses it; the other slot is gone.
    assert!(views.recompute(&[(U1.to_string(), holds(&x))]));
    assert!(
        !views.recompute(&[(U1.to_string(), holds(&x))]),
        "said once"
    );
}

#[test]
fn a_replacement_instance_compares_with_what_its_predecessor_showed() {
    let mut views = Views::new(1);
    let tools = [tool("x", "one")];
    assert!(views.slot(U1, holds(&tools)));
    assert!(!views.adopt(2));
    assert!(
        !views.slot(U1, holds(&tools)),
        "same tools after replacement"
    );
    assert!(views.slot(U1, holds(&[tool("x", "two")])));
}

#[test]
fn a_revoked_grant_announces_the_loss_once() {
    let mut views = Views::new(1);
    assert!(views.slot(U1, holds(&[tool("x", "one")])));
    assert!(views.revoked(U1), "the caller lost what it saw");
    assert!(!views.revoked(U1), "said once");
    assert!(!views.any_shown(), "no tombstone after a revocation");
}
