// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A notification's originating backend is not named where it is screened.
//! It is judged as every registered backend could have sent it, so a rule
//! scoped to a backend still applies to it.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::JsonRpcNotification;
use crate::security::firewall::{Firewall, FirewallConfig};

/// The meta layer over backend `alpha`, its firewall built from `rules`.
fn meta_with(rules: &serde_json::Value) -> Arc<MetaMcp> {
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(Arc::new(Backend::new(
        "alpha",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ))));
    let config: FirewallConfig = serde_json::from_value(json!({
        "enabled": true,
        "scan_responses": true,
        "credential_redaction": true,
        "rules": rules,
    }))
    .expect("config deserializes");
    let mut meta = MetaMcp::new(registry);
    meta.set_firewall(Some(Arc::new(Firewall::from_config(config, None))));
    Arc::new(meta)
}

/// A progress notification carrying a planted credential.
fn progress() -> JsonRpcNotification {
    let key = ["AKIA", "IOSFODNN7", "EXAMPLE"].concat();
    JsonRpcNotification {
        jsonrpc: "2.0".to_string(),
        method: "notifications/progress".to_string(),
        params: Some(json!({"progressToken": "p1", "message": format!("AWS_ACCESS_KEY_ID={key}")})),
    }
}

/// E1: a `block` rule scoped to `alpha` applies to a notification of
/// unnamed origin, ahead of an unscoped `allow`.
#[test]
fn a_backend_scoped_block_applies_to_a_notification_of_unnamed_origin() {
    let meta = meta_with(&json!([
        {"match": "*", "scan": ["credentials"], "action": "block", "servers": ["alpha"]},
        {"match": "*", "scan": ["credentials"], "action": "allow"},
    ]));
    let screen = meta.notification_screen(("caller", "session"), None);
    assert!(
        !screen.admit(&mut progress()),
        "withheld: alpha could have sent it"
    );
}

/// Control: the same rule scoped to a backend that is not registered leaves
/// the `allow` to decide, so the redacted notification is admitted.
#[test]
fn a_block_scoped_to_an_unregistered_backend_does_not_apply() {
    let meta = meta_with(&json!([
        {"match": "*", "scan": ["credentials"], "action": "block", "servers": ["beta"]},
        {"match": "*", "scan": ["credentials"], "action": "allow"},
    ]));
    let screen = meta.notification_screen(("caller", "session"), None);
    assert!(screen.admit(&mut progress()), "admitted, redacted");
}

/// X1: backend and key both unnamed. Only the pair (`alpha`, `k1`) meets the
/// block rule, and that pair is among the candidates, so the notification is
/// withheld.
#[test]
fn the_backend_and_key_cross_product_reaches_a_notification() {
    let meta = meta_with(&json!([
        {"match": "*", "scan": ["credentials"], "action": "block",
         "servers": ["alpha"], "keys": ["k1"]},
        {"match": "*", "scan": ["credentials"], "action": "allow"},
    ]));
    let screen = meta.notification_screen(("caller", "session"), None);
    assert!(
        !screen.admit(&mut progress()),
        "withheld: (alpha, k1) could have sent it"
    );
}

/// E2: the capability provider is held apart from the registry, and a rule
/// scoped to its name still reaches an answer of unnamed origin.
#[test]
fn a_block_scoped_to_the_capability_backend_applies_to_a_notification() {
    let meta = meta_with(&json!([
        {"match": "*", "scan": ["credentials"], "action": "block", "servers": ["caps"]},
        {"match": "*", "scan": ["credentials"], "action": "allow"},
    ]));
    meta.set_capabilities(Arc::new(crate::capability::CapabilityBackend::new(
        "caps",
        Arc::new(crate::capability::CapabilityExecutor::new()),
    )));
    let screen = meta.notification_screen(("caller", "session"), None);
    assert!(
        !screen.admit(&mut progress()),
        "withheld: the capability backend could have sent it"
    );
}
