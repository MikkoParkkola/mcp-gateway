// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8205` (S4): a plan answer's run is attributed only when exactly one
//! receipt of its step keeps every piece whole. One step can hold receipts
//! of several sources (a nested plan); a piece two of them hold gets no
//! owner, so the run gets no subset seams. Deliberate fail-safe: it can only
//! withhold an excuse. Mutant p1 (#3726) took the first holder instead.

use std::cell::{Cell, RefCell};

use serde_json::{Value, json};

use crate::security::firewall::{
    CollusionAction, CollusionConfig, Firewall, FirewallConfig, RelayCaller, ScanType,
};

use super::super::super::{Kind, Receipt};
use super::{PLAN_MEMBERS, add_subset_seams};

fn observing() -> Firewall {
    Firewall::from_config(
        FirewallConfig {
            collusion: CollusionConfig {
                action: CollusionAction::Observe,
                sources: vec!["alpha:*".to_string(), "beta:*".to_string()],
                ..CollusionConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    )
    .keeping_every_kgram()
}

fn piece(k: usize) -> String {
    format!("piece{k}-").repeat(10).chars().take(47).collect()
}

/// A plan step's staged receipt from `server` for key-a.
fn step_receipt(fw: &Firewall, server: &str, value: &Value) -> Receipt {
    let staged = Cell::new(0);
    Receipt {
        key: "key-a".to_string(),
        keyed: true,
        server: server.to_string(),
        tool: "read".to_string(),
        digest: fw
            .receipt_digest(server, "read", value, Some(&staged))
            .expect("staged"),
        in_plan: true,
        pending_retain: false,
        step: Some(0),
        kind: Kind::Delivered,
    }
}

/// Whether key-a forwarding pieces 0 and 2 is reported, after a plan answer
/// of three labelled parts whose step staged one receipt from each of
/// `servers`, and key-c was delivered that join by alpha.
fn subset_reported(servers: &[&str]) -> bool {
    let fw = observing();
    let parts: Vec<Value> = (0..3)
        .map(|k| json!({"part": piece(k), "kind": "chunk"}))
        .collect();
    let answer = json!({ "parts": parts });
    let mut receipts: Vec<Receipt> = servers
        .iter()
        .map(|s| step_receipt(&fw, s, &answer))
        .collect();
    PLAN_MEMBERS.sync_scope(RefCell::new(vec![("/parts".to_string(), 0)]), || {
        add_subset_seams(&fw, &mut receipts, &answer);
    });
    for r in &receipts {
        fw.record_digest(RelayCaller::Keyed("key-a"), &r.server, &r.tool, &r.digest);
    }
    let joined = format!("{}{}", piece(0), piece(2));
    fw.record_delivery(
        RelayCaller::Keyed("key-c"),
        "alpha",
        "read",
        &json!({ "note": joined }),
    );
    let params = json!({"name": "send", "arguments": {"body": joined}});
    fw.check_relay(
        RelayCaller::Keyed("key-a"),
        "alpha",
        "send",
        &params,
        ("s", "key-a"),
    )
    .findings
    .iter()
    .any(|f| f.scan_type == ScanType::CollusionRelay)
}

#[test]
fn a_piece_two_receipts_of_one_step_hold_gets_no_subset_seams() {
    assert!(
        !subset_reported(&["alpha"]),
        "premise: one holder's run is excused"
    );
    assert!(
        subset_reported(&["alpha", "beta"]),
        "a run two receipts of one step hold was attributed"
    );
}
