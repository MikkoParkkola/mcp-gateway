// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A Meta-MCP judging a relay before any live config is published fails
//! closed: the relay is refused, naming the cause, until one is. A test
//! build panics on that path unless the row opts in, so a fixture that
//! forgot to publish cannot pass a refusal row by it.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde_json::json;

use super::super::{Egress, OutboundRetry, RelayKey, staging};
use crate::gateway::meta_mcp::MetaMcp;
use crate::security::firewall::CollusionAction;
use crate::security::firewall::collusion_live_rig::{Rig, config, plain};

const PROSE: &str = "The quarterly reconciliation for the northern depot closed with \
     three open variances, each traced to a late carrier manifest.";

/// A Meta-MCP running `rig`'s firewall, with no live config published, and
/// alice's delivery of [`PROSE`] recorded.
fn unpublished(rig: &Rig) -> MetaMcp {
    let mut meta = MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()));
    meta.set_firewall(Some(Arc::clone(&rig.firewall)));
    rig.deliver("alice", ("alpha", "read"), &plain(PROSE), &rig.generation());
    meta
}

/// Bob relaying [`PROSE`] through `alpha:send`, as the meta route checks it.
fn bob_relays(meta: &MetaMcp) -> Option<crate::Error> {
    let arguments = json!({"text": PROSE});
    let retry = OutboundRetry::default();
    let egress = Egress {
        arguments: &arguments,
        backend: None,
        inbound_meta: None,
        prompt_cache_key: None,
        retry: &retry,
    };
    meta.relay_refusal(
        None,
        RelayKey::new("bob", true),
        ("s", "bob"),
        ("alpha", "send"),
        &egress,
    )
}

fn message(refusal: Option<crate::Error>) -> String {
    match refusal {
        Some(crate::Error::Forbidden { code, message, .. }) => {
            assert_eq!(code, -32002, "the relay refusal's code");
            message
        }
        other => panic!("not a relay refusal: {other:?}"),
    }
}

/// With no live config published, a relay is refused and the message names
/// the cause.
#[test]
fn an_unpublished_gateway_refuses_relays_naming_the_cause() {
    let fired = staging::unpublished_allow::arm();
    let rig = Rig::new(config(CollusionAction::Block, &["alpha:read"], vec![]));
    let meta = unpublished(&rig);
    let message = message(bob_relays(&meta));
    assert!(
        message.contains("no live config published"),
        "the refusal does not name the cause: {message}"
    );
    assert_eq!(fired.load(Ordering::SeqCst), 1, "the unpublished path ran");
}

/// The same rig, once a live config is published: the relay is judged
/// normally (refused as a relay, not for the missing config).
#[test]
fn publishing_a_live_config_lifts_the_unpublished_refusal() {
    let fired = staging::unpublished_allow::arm();
    let rig = Rig::new(config(CollusionAction::Block, &["alpha:read"], vec![]));
    let meta = unpublished(&rig);
    let before = message(bob_relays(&meta));
    assert!(
        before.contains("no live config published"),
        "premise: {before}"
    );
    meta.set_live_config(Arc::clone(&rig.live));
    let after = message(bob_relays(&meta));
    assert!(
        !after.contains("no live config published"),
        "still refused for the missing config: {after}"
    );
    assert_eq!(
        fired.load(Ordering::SeqCst),
        1,
        "only the first check was unpublished"
    );
}

/// Without the opt-in, a fixture that serves a relay with no live config
/// panics, telling its author to publish one.
#[test]
#[should_panic(expected = "publish one (set_live_config) before serving relays")]
fn an_unpublished_fixture_panics_without_the_opt_in() {
    let rig = Rig::new(config(CollusionAction::Block, &["alpha:read"], vec![]));
    let meta = unpublished(&rig);
    let _ = bob_relays(&meta);
}
