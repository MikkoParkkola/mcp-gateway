// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Acceptance tests for MRTR.7 — bridging a modern backend's questions to a
//! legacy client.
//!
//! One test per row of the MRTR.7 block in
//! `docs/requirements/RELEASE-4.0.0-test-plan.md`. Each is named for the row it
//! proves and fails, before the bridge exists, on the assertion that names the
//! behaviour rather than on a missing symbol.

use mcp_gateway::gateway::input_bridge::{ServerRequestKind, is_bridge_reply_id};

/// Row 310 — the wire method and the pending-id prefix of every relayed
/// request, against literals written here, and the ingress gate admitting
/// exactly those prefixes.
///
/// The literals are spelled out rather than read back off the enum on purpose.
/// Two sets both derived from the type under test agree with each other however
/// that type drifts, so a test written that way cannot see the drift it exists
/// to catch: a kind minted on the outbound side and missing on the inbound side
/// fails as a caller timeout, far from the enum that caused it.
#[test]
fn ac_mrtr_7a_wire_methods_and_id_prefixes_match_the_admitted_set() {
    // Every kind, matched explicitly. A wildcard arm would let a fourth variant
    // arrive with no method and no prefix asserted at all.
    for kind in ServerRequestKind::ALL {
        let (method, prefix) = match kind {
            ServerRequestKind::Sampling => ("sampling/createMessage", "sampling-"),
            ServerRequestKind::Elicitation => ("elicitation/create", "elicitation-"),
            ServerRequestKind::Roots => ("roots/list", "roots-"),
        };
        assert_eq!(kind.method(), method, "wire method for {kind:?}");
        assert_eq!(kind.prefix(), prefix, "pending-id prefix for {kind:?}");
    }

    // The admitted set, against the same literals. `roots-` is the one that
    // fails today: the shipped ingress condition knows two prefixes and the
    // bridge mints three.
    for prefix in ["sampling-", "elicitation-", "roots-"] {
        assert!(
            is_bridge_reply_id(&format!("{prefix}7")),
            "ingress gate must admit a reply id under {prefix}"
        );
    }

    // And nothing else. An over-wide gate routes another subsystem's reply into
    // the bridge's pending map, where it resolves a request nobody asked.
    for foreign in ["", "sampling", "roots", "proxy-7", "elicitation"] {
        assert!(
            !is_bridge_reply_id(foreign),
            "ingress gate must not admit {foreign:?}"
        );
    }
}
