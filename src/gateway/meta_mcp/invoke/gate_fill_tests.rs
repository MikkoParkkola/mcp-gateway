// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8361 (gpt delta r3): the gate's fill marks see a reload. A reload
//! replaces a backend's instance, and the old instance's fill counter cannot
//! see a fill on the new one, so a replacement counts as a fill and the nonce
//! stays spent.

use std::iter::once;
use std::sync::Arc;

use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::authz_tests::counted_backend;

#[test]
fn a_replaced_or_removed_backend_counts_as_a_fill() {
    let (registry, _) = counted_backend("alpha");
    let meta = MetaMcp::new(Arc::clone(&registry));
    let marks = meta.fill_marks(once("alpha"));
    assert!(
        !meta.filled_since(&marks, once("alpha")),
        "control: nothing changed"
    );

    let (reloaded, _) = counted_backend("alpha");
    let replacement = reloaded.get("alpha").expect("fixture backend");
    assert!(registry.register(replacement), "the reload's re-register");
    assert!(
        meta.filled_since(&marks, once("alpha")),
        "a replaced instance hides its fills from the old counter"
    );

    let marks = meta.fill_marks(once("alpha"));
    assert!(registry.remove("alpha"));
    assert!(
        meta.filled_since(&marks, once("alpha")),
        "a removed backend cannot prove it filled nothing"
    );
}
