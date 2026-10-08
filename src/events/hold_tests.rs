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

/// Beta's capability: one push route mapping and filtering `ref`.
fn full() -> String {
    "name: beta\ndescription: hooks\nschema:\n  input: { type: object, properties: {} }\n  \
     output: { type: object }\nproviders: {}\nwebhooks:\n  push:\n    path: /beta/push\n    \
     method: POST\n    transform:\n      event_type: \"beta.push\"\n      data: { ref: \"{ref}\" }\n    \
     event:\n      description: \"A push.\"\n      filters: [ref]\n"
        .to_owned()
}

/// Beta with `ref` replaced by `sha`, in its fields and its filters.
fn narrower() -> String {
    full().replace("ref", "sha")
}

/// Beta with `sha` mapped beside `ref`.
fn wider() -> String {
    full().replace(
        "data: { ref: \"{ref}\" }",
        "data: { ref: \"{ref}\", sha: \"{sha}\" }",
    )
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
