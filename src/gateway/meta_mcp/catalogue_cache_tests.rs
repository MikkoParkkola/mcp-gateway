// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7916 option (1b): the meta catalogue keyed by its inputs and shared by
//! identity. The key decides what a caller is shown, so these rows treat a
//! stale hit as an authorization leak, not a slow path.

use std::sync::Arc;

use serde_json::Value;

use super::{CATALOGUE_BUILDS, HELD_KEYS, MetaCatalogues, MetaListKey, build_catalogue};
use crate::backend::BackendRegistry;
use crate::config::WebhookConfig;
use crate::gateway::WebhookRegistry;
use crate::gateway::meta_mcp::{InvokeScope, MetaMcp};
use crate::gateway::meta_mcp_tool_defs::{MetaToolExposure, MetaToolGates, ToolTotal};
use crate::gateway::router::CallerStanding;
use crate::protocol::{JsonRpcResponse, RequestId};

fn builds() -> usize {
    CATALOGUE_BUILDS.with(std::cell::Cell::get)
}

fn base() -> MetaListKey {
    MetaListKey {
        code_mode: false,
        gates: MetaToolGates {
            stats: false,
            reload: false,
            cost_report: false,
            webhook_status: false,
            playbooks: false,
            profiles: false,
        },
        counts: (ToolTotal::AtLeast(40), 3),
        standing: CallerStanding::Admin,
        nonce: false,
    }
}

/// `base` with exactly one input changed, for every input the key carries.
fn one_input_changed() -> Vec<(&'static str, MetaListKey)> {
    // A field added to the key or to the gates fails to compile here until it
    // gets a row below: the rows are the proof that each input misses.
    let MetaListKey {
        code_mode: _,
        gates,
        counts: _,
        standing: _,
        nonce: _,
    } = base();
    let MetaToolGates {
        stats: _,
        reload: _,
        cost_report: _,
        webhook_status: _,
        playbooks: _,
        profiles: _,
    } = gates;
    let b = base();
    let gate = |set: fn(&mut MetaToolGates)| {
        let mut key = b;
        set(&mut key.gates);
        key
    };
    vec![
        (
            "code_mode",
            MetaListKey {
                code_mode: true,
                ..b
            },
        ),
        ("gates.stats", gate(|g| g.stats = true)),
        ("gates.reload", gate(|g| g.reload = true)),
        ("gates.cost_report", gate(|g| g.cost_report = true)),
        ("gates.webhook_status", gate(|g| g.webhook_status = true)),
        ("gates.playbooks", gate(|g| g.playbooks = true)),
        ("gates.profiles", gate(|g| g.profiles = true)),
        (
            "counts.tools",
            MetaListKey {
                counts: (ToolTotal::AtLeast(41), 3),
                ..b
            },
        ),
        (
            "counts.tools unknown",
            MetaListKey {
                counts: (ToolTotal::Unknown, 3),
                ..b
            },
        ),
        (
            "counts.tools exact at the same number",
            MetaListKey {
                counts: (ToolTotal::Exact(40), 3),
                ..b
            },
        ),
        (
            "counts.servers",
            MetaListKey {
                counts: (ToolTotal::AtLeast(40), 4),
                ..b
            },
        ),
        (
            "standing",
            MetaListKey {
                standing: CallerStanding::Standard,
                ..b
            },
        ),
        ("nonce", MetaListKey { nonce: true, ..b }),
    ]
}

#[test]
fn each_input_change_misses_and_is_served_its_own_list() {
    let exposure = MetaToolExposure::expose_all();
    for (input, changed) in one_input_changed() {
        assert_ne!(changed, base(), "{input}: the row must change the key");
        let cache = MetaCatalogues::default();
        let first = cache.get_or_build(base(), &exposure);
        let before = builds();
        let listed = cache.get_or_build(changed, &exposure);
        assert_eq!(builds() - before, 1, "{input}: a changed input must miss");
        assert!(
            !Arc::ptr_eq(&first, &listed),
            "{input}: served the held list"
        );
        assert_eq!(
            *listed,
            *build_catalogue(changed, &exposure),
            "{input}: the list must be the one its own key builds"
        );
    }
}

#[test]
fn a_repeat_key_is_served_the_held_list() {
    let exposure = MetaToolExposure::expose_all();
    let cache = MetaCatalogues::default();
    let first = cache.get_or_build(base(), &exposure);
    let before = builds();
    let again = cache.get_or_build(base(), &exposure);
    assert_eq!(builds() - before, 0);
    assert!(Arc::ptr_eq(&first, &again));
}

#[test]
fn past_the_bound_the_oldest_key_is_rebuilt_not_served_stale() {
    let exposure = MetaToolExposure::expose_all();
    let cache = MetaCatalogues::default();
    let first = cache.get_or_build(base(), &exposure);
    for servers in 0..HELD_KEYS {
        let key = MetaListKey {
            counts: (ToolTotal::AtLeast(1), servers),
            ..base()
        };
        cache.get_or_build(key, &exposure);
    }
    let before = builds();
    let again = cache.get_or_build(base(), &exposure);
    assert_eq!(
        builds() - before,
        1,
        "the oldest key was dropped, so it rebuilds"
    );
    assert_eq!(*again, *first, "and rebuilds the same list");
}

fn with_webhooks() -> MetaMcp {
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.set_webhook_registry(Arc::new(parking_lot::RwLock::new(WebhookRegistry::new(
        WebhookConfig::default(),
    ))));
    meta
}

fn names(response: &JsonRpcResponse) -> Vec<String> {
    response.result.as_ref().expect("a result")["tools"]
        .as_array()
        .expect("a tools array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("a name").to_string())
        .collect()
}

fn list_as(meta: &MetaMcp, standing: CallerStanding) -> Vec<String> {
    names(&meta.handle_tools_list_for_session(
        RequestId::Number(1),
        None,
        InvokeScope::unscoped(standing),
    ))
}

#[test]
fn interleaved_standings_each_get_their_own_list() {
    let meta = with_webhooks();
    let admin = list_as(&meta, CallerStanding::Admin);
    let standard = list_as(&meta, CallerStanding::Standard);
    assert!(admin.iter().any(|name| name == "gateway_webhook_status"));
    assert!(
        !standard.iter().any(|name| name == "gateway_webhook_status"),
        "a standard caller must never be listed an admin tool"
    );
    for _ in 0..3 {
        assert_eq!(list_as(&meta, CallerStanding::Standard), standard);
        assert_eq!(list_as(&meta, CallerStanding::Admin), admin);
    }
}

#[test]
fn a_gate_attached_after_a_list_reaches_the_next_list() {
    // The reload row: a webhook registry is attached at runtime, after a list
    // has been cached without it.
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    let before = list_as(&meta, CallerStanding::Admin);
    assert!(!before.iter().any(|name| name == "gateway_webhook_status"));
    meta.set_webhook_registry(Arc::new(parking_lot::RwLock::new(WebhookRegistry::new(
        WebhookConfig::default(),
    ))));
    let after = list_as(&meta, CallerStanding::Admin);
    assert!(
        after.iter().any(|name| name == "gateway_webhook_status"),
        "the gate change must miss the held list"
    );
}

fn tools_of(response: &JsonRpcResponse) -> Value {
    response.result.as_ref().expect("a result")["tools"].clone()
}

#[test]
fn a_repeat_list_builds_computes_and_compares_nothing() {
    let meta = with_webhooks();
    let first = meta.handle_tools_list(RequestId::Number(1));
    let (built, (cards, compares)) = (builds(), crate::trust::memo_counters());
    let second = meta.handle_tools_list(RequestId::Number(2));
    let (cards_after, compares_after) = crate::trust::memo_counters();
    assert_eq!(builds() - built, 0, "no catalogue build");
    assert_eq!(cards_after - cards, 0, "no trust card computed");
    assert_eq!(compares_after - compares, 0, "no tool compared");
    assert_eq!(tools_of(&second), tools_of(&first), "the same descriptors");
}

#[test]
fn a_list_no_longer_held_falls_back_to_the_exact_path() {
    use crate::trust::SharedProjections;
    // Its own server identity, so no other test's lists touch the per-tool
    // cards this row reads.
    let (id, name) = ("test:mik-7916-fallback", "fallback");
    let meta = with_webhooks();
    let tools = meta.meta_tools_for(CallerStanding::Admin, meta.backend_counts());
    let store = SharedProjections::default();
    let first = store.project(id, name, &tools);
    // The same content in other lists, enough to drop the first one.
    for _ in 0..SharedProjections::CAPACITY {
        let other: Arc<[crate::protocol::Tool]> = tools.to_vec().into();
        let _ = store.project(id, name, &other);
    }
    let (cards, compares) = crate::trust::memo_counters();
    let again = store.project(id, name, &tools);
    let (cards_after, compares_after) = crate::trust::memo_counters();
    assert_eq!(again, first, "the same descriptors");
    assert_eq!(cards_after - cards, 0, "unchanged tools recompute no card");
    assert!(
        compares_after > compares,
        "the fallback is the exact per-tool compare"
    );
}

/// A held list is recognised by address only under the server identity it
/// was projected for: the same list under another server is another card.
#[test]
fn a_held_list_matches_only_under_its_own_server_identity() {
    use crate::trust::SharedProjections;
    let meta = with_webhooks();
    let tools = meta.meta_tools_for(CallerStanding::Admin, meta.backend_counts());
    assert!(!tools.is_empty());
    let store = SharedProjections::default();
    let a = store.project("test:mik-7916-ident-a", "ident-a", &tools);
    let b = store.project("test:mik-7916-ident-b", "ident-b", &tools);
    assert_ne!(
        a[0]["trustCard"]["serverId"], b[0]["trustCard"]["serverId"],
        "the second server must not be served the first one's cards"
    );
}

#[test]
fn the_nonce_input_changes_what_is_listed() {
    // The nonce row above proves a miss; this one proves the miss matters:
    // with nonces required, `gateway_invoke` describes a different schema.
    let exposure = MetaToolExposure::expose_all();
    let plain = build_catalogue(base(), &exposure);
    let with_nonce = build_catalogue(
        MetaListKey {
            nonce: true,
            ..base()
        },
        &exposure,
    );
    assert_ne!(plain, with_nonce);
}

#[test]
fn a_builder_setter_after_a_list_is_honoured_by_the_next_list() {
    // Consuming setters run at construction, but nothing stops one from
    // running after a list: code mode is read into the key, and the exposure,
    // the one input outside it, clears the held lists when it is set.
    let meta = with_webhooks();
    let before = list_as(&meta, CallerStanding::Admin);
    assert!(before.iter().any(|name| name == "gateway_webhook_status"));

    let meta = meta.with_exposed_meta_tools(&["gateway_search_tools".to_string()]);
    let narrowed = list_as(&meta, CallerStanding::Admin);
    assert!(
        !narrowed.iter().any(|name| name == "gateway_webhook_status"),
        "a narrowed exposure must reach the next list: {narrowed:?}"
    );

    let meta = meta.with_exposed_meta_tools(&[]).with_code_mode(true);
    let code_mode = list_as(&meta, CallerStanding::Admin);
    assert_eq!(
        code_mode.len(),
        2,
        "code mode's two tools, not the held meta-tools: {code_mode:?}"
    );
}
