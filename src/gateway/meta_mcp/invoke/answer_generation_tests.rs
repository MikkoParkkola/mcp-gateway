// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! ADR-029 (amended), item 5, at the answer-side scans: an answer is judged
//! under the request's pinned generation (R) and the one published when its
//! scan starts (P); an answer no request is behind under P alone.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, Config, FailsafeConfig};
use crate::config_reload::LiveConfig;
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::JsonRpcNotification;
use crate::security::firewall::{Firewall, FirewallConfig};
use crate::security::response_policy::{ResponseCorrelation, ResponsePolicyTarget};

/// A gateway config whose firewall redacts or not, with `rules`.
fn config(redaction: bool, rules: &serde_json::Value) -> Config {
    let mut config = Config::default();
    config.security.firewall = serde_json::from_value::<FirewallConfig>(json!({
        "enabled": true,
        "scan_responses": true,
        "credential_redaction": redaction,
        "rules": rules,
    }))
    .expect("firewall config deserializes");
    config
}

/// The "remove credentials" pairing: redaction on, credentials warned.
fn redacting() -> Config {
    config(
        true,
        &json!([{"match": "*", "scan": ["credentials"], "action": "warn"}]),
    )
}

/// Redaction off, no rules.
fn plain() -> Config {
    config(false, &json!([]))
}

/// Credentials blocked outright.
fn blocking() -> Config {
    config(
        true,
        &json!([{"match": "*", "scan": ["credentials"], "action": "block"}]),
    )
}

/// The meta layer over backend `alpha`, with `published` as its live config.
fn meta_publishing(published: Config) -> (Arc<MetaMcp>, Arc<LiveConfig>) {
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(Arc::new(Backend::new(
        "alpha",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ))));
    let firewall = Firewall::from_config(published.security.firewall.clone(), None);
    let live = Arc::new(LiveConfig::new(published));
    let mut meta = MetaMcp::new(registry);
    meta.set_firewall(Some(Arc::new(firewall)));
    meta.set_live_config(Arc::clone(&live));
    (Arc::new(meta), live)
}

/// A planted credential, built at run time.
fn key() -> String {
    ["AKIA", "IOSFODNN7", "EXAMPLE"].concat()
}

fn progress() -> JsonRpcNotification {
    JsonRpcNotification {
        jsonrpc: "2.0".to_string(),
        method: "notifications/progress".to_string(),
        params: Some(
            json!({"progressToken": "p1", "message": format!("AWS_ACCESS_KEY_ID={}", key())}),
        ),
    }
}

fn carries_key(notification: &JsonRpcNotification) -> bool {
    notification
        .params
        .as_ref()
        .is_some_and(|p| p.to_string().contains(&key()))
}

/// The leak row, mid-call: a call admitted under a redacting generation
/// streams a progress notification after a reload turned redaction off. The
/// credential is redacted, never delivered raw. With the request's
/// generation ignored (P alone), it would go out raw.
#[test]
fn a_mid_call_notification_after_redaction_is_turned_off_is_redacted() {
    let pinned = LiveConfig::new(redacting()).generation();
    let (meta, _live) = meta_publishing(plain());
    let screen = meta.notification_screen(("caller", "session"), Some(pinned));
    let mut sent = progress();
    assert!(screen.admit(&mut sent), "delivered, redacted");
    assert!(!carries_key(&sent), "{sent:?}");
}

/// A stream: R stays the call's, P is read again for each notification. A
/// tightening reload between two notifications refuses the second.
#[test]
fn each_notification_reads_the_published_generation_anew() {
    let pinned = LiveConfig::new(redacting()).generation();
    let (meta, live) = meta_publishing(redacting());
    let screen = meta.notification_screen(("caller", "session"), Some(pinned));
    let mut first = progress();
    assert!(screen.admit(&mut first), "the first is delivered redacted");
    assert!(!carries_key(&first));
    live.set(blocking());
    assert!(
        !screen.admit(&mut progress()),
        "the reload reaches the next one"
    );
}

/// A notification no request is behind takes P alone: with redaction off
/// published, it is delivered as sent.
#[test]
fn a_requestless_notification_takes_the_published_generation_alone() {
    let (meta, _live) = meta_publishing(plain());
    let screen = meta.notification_screen(("caller", "session"), None);
    let mut sent = progress();
    assert!(screen.admit(&mut sent));
    assert!(carries_key(&sent), "P alone does not redact");
}

fn targets() -> [ResponsePolicyTarget; 1] {
    [ResponsePolicyTarget {
        server: "alpha".into(),
        tool: "read".into(),
        origin: crate::security::response_policy::TargetOrigin::Routed,
    }]
}

/// A task result read by a request takes the reader's R with P; the same
/// result as it settles takes P alone.
#[test]
fn a_read_task_result_takes_the_readers_generation_and_settlement_does_not() {
    let reader = LiveConfig::new(redacting()).generation();
    let (meta, _live) = meta_publishing(plain());
    let body =
        || json!({"content": [{"type": "text", "text": format!("AWS_ACCESS_KEY_ID={}", key())}]});
    let mut read = body();
    meta.inspect_task_result((&targets(), "t1"), Some(&reader), &mut read)
        .expect("delivered");
    assert!(
        !read.to_string().contains(&key()),
        "read under R and P: {read}"
    );
    let mut settled = body();
    meta.inspect_task_result((&targets(), "t1"), None, &mut settled)
        .expect("delivered");
    assert!(
        settled.to_string().contains(&key()),
        "settled under P alone: {settled}"
    );
}

/// An immutable challenge under a loosening reload is refused, not rewritten:
/// R redacts, so its protected member would change.
#[test]
fn an_immutable_challenge_under_a_loosening_reload_is_refused() {
    let pinned = LiveConfig::new(redacting()).generation();
    let (meta, _live) = meta_publishing(plain());
    let challenge = json!({"message": format!("AWS_ACCESS_KEY_ID={}", key())});
    let correlation = ResponseCorrelation {
        session_id: "s",
        caller: "c",
        external_server: "gateway",
        external_tool: "gateway_invoke",
        subject: None,
        trace_id: None,
        key: crate::security::response_policy::KeyOf::NoKey,
    };
    assert!(
        meta.enforce_firewall_challenge(&challenge, (&targets(), &correlation), None)
            .is_ok(),
        "premise: P alone passes it"
    );
    assert!(
        meta.enforce_firewall_challenge(&challenge, (&targets(), &correlation), Some(&pinned))
            .is_err()
    );
}
