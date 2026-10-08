// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8057, MIK-8076: a webhook subscription whose type the routes no longer
//! offer, or no longer serve, is held, never withdrawn: its refresh is
//! accepted and says so, and it resumes when the route serves it again.

use std::sync::Arc;

use serde_json::{Value, json};

use super::{NAME, Probe, caller, seed_verified, services, url, whsec};
use crate::events::EventsHub;

const TYPE: &str = "webhook.beta.push.received";

/// Beta's capability: one push route mapping and filtering `ref` and `sha`.
fn full() -> String {
    "name: beta\ndescription: hooks\nschema:\n  input: { type: object, properties: {} }\n  \
     output: { type: object }\nproviders: {}\nwebhooks:\n  push:\n    path: /beta/push\n    \
     method: POST\n    transform:\n      event_type: \"beta.push\"\n      \
     data: { ref: \"{ref}\", sha: \"{sha}\" }\n    \
     event:\n      description: \"A push.\"\n      filters: [ref, sha]\n"
        .to_owned()
}

/// Beta with `ref` dropped from its fields and its filters: restoring the
/// full shape afterwards widens it again.
fn narrower() -> String {
    full()
        .replace("ref: \"{ref}\", ", "")
        .replace("filters: [ref, sha]", "filters: [sha]")
}

/// Beta with `tag` mapped beside `ref` and `sha`.
fn wider() -> String {
    full().replace("sha: \"{sha}\" }", "sha: \"{sha}\", tag: \"{tag}\" }")
}

/// Beta read mid-write: valid YAML, its webhook section not written yet.
fn mid_write() -> String {
    full()[..full().find("webhooks:").expect("section")].to_owned()
}

type Registry = Arc<parking_lot::RwLock<crate::gateway::WebhookRegistry>>;

/// A hub on `dir` (a restart reopens the same store), its webhook routes
/// refreshed from `yaml`, as the startup pass and every reload do.
fn hub_with(
    dir: &std::path::Path,
    yaml: &str,
    config: &crate::config::EventsConfig,
) -> (Arc<EventsHub>, Registry) {
    let hub = EventsHub::open(config, dir).expect("hub");
    let registry: Registry = Arc::new(parking_lot::RwLock::new(
        crate::gateway::WebhookRegistry::new(crate::config::WebhookConfig::default()),
    ));
    hub.set_webhook_registry(Arc::clone(&registry));
    let _ = hub.runtime.services.set(Arc::new(services()));
    refresh(&hub, &registry, yaml);
    (hub, registry)
}

/// Apply `yaml` as the catalogue (empty: beta absent).
fn refresh(hub: &EventsHub, registry: &Registry, yaml: &str) {
    let caps: Vec<_> = if yaml.is_empty() {
        Vec::new()
    } else {
        vec![crate::capability::parse_capability(yaml).expect("capability")]
    };
    let _gate = hub.catalogue_lock();
    let _ = hub.refresh_webhooks(registry, &caps);
}

/// `p`, seeing the backends the webhook routes are scoped to.
fn hooks_caller(hub: &EventsHub) -> crate::events::Caller {
    let mut caller = caller("p");
    caller.visible_backends = hub.scope_backends().into_iter().collect();
    caller
}

/// Subscribe (or refresh) `p` to beta with `arguments`.
async fn subscribe(hub: &Arc<EventsHub>, arguments: Value) -> Result<Value, String> {
    let params = json!({"name": TYPE, "arguments": arguments, "delivery": {
        "mode": "webhook", "url": url("p"), "secret": whsec()}});
    hub.subscribe(&hooks_caller(hub), Some(&params))
        .await
        .map_err(|e| format!("{e:?}"))
}

/// A first run that subscribed `p` to beta under the full shape, then a
/// restart that offers `yaml`.
async fn restarted(arguments: Value, yaml: &str) -> (tempfile::TempDir, Arc<EventsHub>, Registry) {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    {
        let (hub, _registry) = hub_with(dir.path(), &full(), &config);
        seed_verified(&hub, &config, "p");
        subscribe(&hub, arguments).await.expect("first subscribe");
    }
    let (hub, registry) = hub_with(dir.path(), yaml, &config);
    (dir, hub, registry)
}

/// MIK-8076 N1 + N1b: a filter key the restored route no longer serves holds
/// the subscription; its refresh is accepted and names the key; restoring
/// the full shape resumes it with no subscriber action.
#[tokio::test]
async fn a_filter_the_route_no_longer_serves_holds_then_resumes() {
    let (_dir, hub, registry) = restarted(json!({"ref": "main"}), &narrower()).await;
    let answer = subscribe(&hub, json!({"ref": "main"})).await;
    assert!(answer.is_ok(), "a held refresh is accepted: {answer:?}");
    let answer = answer.unwrap_or_default();
    assert_eq!(answer["held"]["key"], "ref", "{answer}");
    assert!(answer["held"]["until"].is_string(), "{answer}");
    refresh(&hub, &registry, &full());
    let resumed = subscribe(&hub, json!({"ref": "main"}))
        .await
        .expect("refresh");
    assert!(resumed.get("held").is_none(), "resumed: {resumed}");
}

/// MIK-8076 N14: an unfiltered subscription whose payload field `ref` the
/// restored route no longer carries is held, naming the field.
#[tokio::test]
async fn a_payload_field_the_route_no_longer_carries_holds() {
    let (_dir, hub, _registry) = restarted(json!({}), &narrower()).await;
    let answer = subscribe(&hub, json!({})).await.expect("refresh");
    assert_eq!(answer["held"]["key"], "ref", "{answer}");
}

/// MIK-8076 N15 (pin, SHAPE.2): a wider payload holds nothing.
#[tokio::test]
async fn a_wider_payload_holds_nothing() {
    let (_dir, hub, _registry) = restarted(json!({}), &wider()).await;
    let answer = subscribe(&hub, json!({})).await.expect("refresh");
    assert!(answer.get("held").is_none(), "{answer}");
}

/// MIK-8057 H1/H2 + MIK-8076 N18: beta read mid-write at a restart is not
/// offered; the subscription is held (its refresh accepted, not refused as
/// unoffered), stamped `unoffered_since`, and resumes when the complete
/// file is read.
#[tokio::test]
async fn a_type_read_mid_write_holds_then_resumes() {
    let (dir, hub, registry) = restarted(json!({"ref": "main"}), &mid_write()).await;
    let answer = subscribe(&hub, json!({"ref": "main"})).await;
    assert!(answer.is_ok(), "held, not refused as unoffered: {answer:?}");
    assert!(
        answer.unwrap_or_default()["held"]["reason"].is_string(),
        "the refresh says why"
    );
    assert!(stamped(dir.path()), "the held row is stamped");
    refresh(&hub, &registry, &full());
    let resumed = subscribe(&hub, json!({"ref": "main"}))
        .await
        .expect("refresh");
    assert!(resumed.get("held").is_none(), "resumed: {resumed}");
    assert!(!stamped(dir.path()), "the stamp clears when it resumes");
}

/// Whether beta's stored row carries `unoffered_since`.
fn stamped(dir: &std::path::Path) -> bool {
    std::fs::read_dir(dir.join("subs"))
        .expect("subs")
        .filter_map(|e| std::fs::read(e.ok()?.path()).ok())
        .filter_map(|b| serde_json::from_slice::<Value>(&b).ok())
        .any(|row| row["name"] == TYPE && !row["unoffered_since"].is_null())
}

/// MIK-8057 H4: a held row keeps its cap slot, and the cap refusal names
/// the caller's held types, so the subscriber can free the slot.
#[tokio::test]
async fn the_cap_refusal_names_held_rows() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig {
        max_subscriptions_per_principal: 2,
        ..crate::config::EventsConfig::default()
    };
    {
        let (hub, _registry) = hub_with(dir.path(), &full(), &config);
        seed_verified(&hub, &config, "p");
        subscribe(&hub, json!({"ref": "main"}))
            .await
            .expect("first");
    }
    // Restarted with beta unread: its row is held and still counts.
    let (hub, _registry) = hub_with(dir.path(), "", &config);
    hub.register_source(Arc::new(Probe::default()));
    let params = json!({"name": NAME, "arguments": {"k": "v"}, "delivery": {
        "mode": "webhook", "url": url("p"), "secret": whsec()}});
    let refused = hub
        .subscribe(&hooks_caller(&hub), Some(&params))
        .await
        .expect_err("at the per-principal cap");
    let refused = format!("{refused:?}");
    assert!(refused.contains("-32013"), "{refused}");
    assert!(
        refused.contains(TYPE),
        "the refusal names the held type: {refused}"
    );
}

/// Beta with `sha` no longer a filter: against the narrower routes, a
/// refresh that drops a filter is refused (T52).
fn narrowest() -> String {
    narrower().replace("filters: [sha]", "filters: []")
}

/// The id a subscribe answered with.
fn id_of(answer: &Value) -> String {
    answer["id"].as_str().expect("id").to_owned()
}

/// Review G2: an unsubscribe ends the hold with the row. The same key
/// subscribed again under the routes now offered is not held.
#[tokio::test]
async fn an_unsubscribed_held_row_leaves_no_hold_behind() {
    let (_dir, hub, _registry) = restarted(json!({}), &narrower()).await;
    let id = id_of(&subscribe(&hub, json!({})).await.expect("held refresh"));
    assert!(hub.store.held(&id).is_some(), "held first");
    let params = json!({"name": TYPE, "arguments": {}, "delivery": {"url": url("p")}});
    hub.unsubscribe(&hooks_caller(&hub), Some(&params))
        .await
        .expect("unsubscribed");
    let answer = subscribe(&hub, json!({})).await.expect("subscribed again");
    assert!(answer.get("held").is_none(), "{answer}");
    assert!(hub.store.held(&id).is_none(), "no hold outlives its row");
}

/// Review G3: a held refresh that waits on the commit while a reload
/// resumes the row commits the row as it is now: no stale hold stamp.
#[tokio::test]
async fn a_held_refresh_racing_a_resume_keeps_no_stale_stamp() {
    let (dir, hub, registry) = restarted(json!({"ref": "main"}), &narrower()).await;
    let started = hub.lifecycle.lock().await;
    // Polled first, the refresh runs until it waits on the commit's lock;
    // then the reload resumes the row and the lock is let go.
    let (path, hub_ref, routes) = (dir.path(), &hub, &registry);
    let resume = async move {
        refresh(hub_ref, routes, &full());
        assert!(!stamped(path), "the reload resumed the row");
        drop(started);
    };
    let (answer, ()) = tokio::join!(subscribe(&hub, json!({"ref": "main"})), resume);
    answer.expect("refresh");
    assert!(!stamped(dir.path()), "the refresh restored no stale stamp");
}

/// Review G9: an accepted held refresh reactivates a suspended row, as
/// every refresh does.
#[tokio::test]
async fn a_held_refresh_reactivates_a_suspended_row() {
    let (_dir, hub, _registry) = restarted(json!({}), &narrower()).await;
    let id = id_of(&subscribe(&hub, json!({})).await.expect("held refresh"));
    hub.store.suspend(&id).expect("io");
    subscribe(&hub, json!({})).await.expect("held refresh");
    assert!(hub.store.get(&id).expect("row").active, "reactivated");
}

/// Review G5: a refresh refused as a narrowing (T52) still judges the
/// stored rows against the routes left live, as at a startup whose scan
/// registered narrower routes than a row was committed with.
#[tokio::test]
async fn a_refused_refresh_still_holds_what_the_live_routes_do_not_carry() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    let id = {
        let (hub, _registry) = hub_with(dir.path(), &full(), &config);
        seed_verified(&hub, &config, "p");
        id_of(&subscribe(&hub, json!({})).await.expect("first subscribe"))
    };
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let registry: Registry = Arc::new(parking_lot::RwLock::new(
        crate::gateway::WebhookRegistry::new(crate::config::WebhookConfig::default()),
    ));
    // The capability scan registers its routes before the hub judges any.
    let scanned = crate::capability::parse_capability(&narrower()).expect("capability");
    registry.write().replace_capabilities(&[scanned]);
    hub.set_webhook_registry(Arc::clone(&registry));
    refresh(&hub, &registry, &narrowest());
    assert!(
        hub.store.held(&id).is_some(),
        "the live routes do not carry ref: held"
    );
}

/// Review G6: a hold stamp whose write fails still bounds the row in
/// memory, and the next refresh writes it.
#[cfg(unix)]
#[tokio::test]
async fn a_failed_stamp_write_still_bounds_the_row() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, hub, registry) = restarted(json!({}), &full()).await;
    let id = id_of(&subscribe(&hub, json!({})).await.expect("refresh"));
    let subs = dir.path().join("subs");
    let mode = |m| std::fs::set_permissions(&subs, std::fs::Permissions::from_mode(m));
    mode(0o500).expect("read-only");
    refresh(&hub, &registry, "");
    mode(0o700).expect("writable");
    let row = hub.store.get(&id).expect("row");
    assert!(row.held_until.is_some(), "bounded in memory");
    assert!(!stamped(dir.path()), "the write failed");
    refresh(&hub, &registry, "");
    assert!(stamped(dir.path()), "the next refresh wrote it");
}
