// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The catalogue witness fails closed as the meta one does: with neither a
//! pinned nor a published generation, a catalogue read carrying what
//! another caller was delivered is refused, naming the cause.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde_json::json;

use super::super::staging;
use super::CatalogueCaller;
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::RequestId;
use crate::security::firewall::CollusionAction;
use crate::security::firewall::collusion_live_rig::{Rig, config, plain};

const PROSE: &str = "The quarterly reconciliation for the northern depot closed with \
     three open variances, each traced to a late carrier manifest.";

/// With no live config published and no generation pinned, bob's
/// `prompts/get` carrying alice's delivery is refused with `-32002`, and the
/// message names the cause.
#[test]
fn an_unpublished_gateway_refuses_catalogue_relays_naming_the_cause() {
    let fired = staging::unpublished_allow::arm();
    let rig = Rig::new(config(CollusionAction::Block, &["alpha:read"], vec![]));
    let mut meta = MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()));
    meta.set_firewall(Some(Arc::clone(&rig.firewall)));
    rig.deliver("alice", ("alpha", "read"), &plain(PROSE), &rig.generation());
    let bob = CatalogueCaller {
        key: "bob".to_string(),
        keyed: true,
        name: "bob".to_string(),
        session: "s".to_string(),
        generation: None,
    };
    let params = json!({"name": "summary", "arguments": {"text": PROSE}});
    let refusal = meta.catalogue_refusal(
        Some(&bob),
        "alpha",
        "prompts/get",
        &params,
        &RequestId::Number(1),
    );
    let error = refusal
        .and_then(|response| response.error)
        .expect("the catalogue read is refused");
    assert_eq!(error.code, -32002, "the relay refusal's code");
    assert!(
        error.message.contains("no live config published"),
        "the refusal does not name the cause: {}",
        error.message
    );
    assert_eq!(fired.load(Ordering::SeqCst), 1, "the unpublished path ran");
}

/// The counterpart: once a live config is published, the same read with text
/// nobody was delivered is let through, so the refusal above is the missing
/// config's, not a catalogue path that refuses everything.
#[test]
fn a_published_gateway_lets_an_unrelayed_catalogue_read_through() {
    let rig = Rig::new(config(CollusionAction::Block, &["alpha:read"], vec![]));
    let mut meta = MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()));
    meta.set_firewall(Some(Arc::clone(&rig.firewall)));
    crate::security::firewall::collusion_live_rig::seed_meta(&meta, &rig.firewall);
    rig.deliver("alice", ("alpha", "read"), &plain(PROSE), &rig.generation());
    let bob = CatalogueCaller {
        key: "bob".to_string(),
        keyed: true,
        name: "bob".to_string(),
        session: "s".to_string(),
        generation: None,
    };
    let params = json!({"name": "summary", "arguments": {"text": "the north slope"}});
    let refusal = meta.catalogue_refusal(
        Some(&bob),
        "alpha",
        "prompts/get",
        &params,
        &RequestId::Number(1),
    );
    assert!(
        refusal.is_none(),
        "an unrelayed read was refused: {refusal:?}"
    );
}
