// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F9: the empty id is never a session, and the session store's logs name
//! sessions by fingerprint only.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use crate::backend::BackendRegistry;
use crate::config::StreamingConfig;
use crate::gateway::destructive_confirmation::{
    ConfirmationOutcome, require_destructive_confirmation,
};
use crate::gateway::proxy::{ProxyManager, SamplingError};
use crate::gateway::session_id::log_capture::{assert_fingerprinted, capture_debug};
use crate::gateway::streaming::NotificationMultiplexer;
use crate::protocol::{ElicitationCreateParams, SamplingCreateMessageParams};

fn proxy() -> (Arc<NotificationMultiplexer>, ProxyManager) {
    let mux = Arc::new(NotificationMultiplexer::new(
        Arc::new(BackendRegistry::new()),
        StreamingConfig::default(),
    ));
    (Arc::clone(&mux), ProxyManager::new(mux))
}

fn elicitation() -> ElicitationCreateParams {
    serde_json::from_value(json!({"message": "Proceed?"})).unwrap()
}

fn sampling() -> SamplingCreateMessageParams {
    serde_json::from_value(json!({
        "messages": [{"role": "user", "content": {"type": "text", "text": "hi"}}],
        "maxTokens": 16
    }))
    .unwrap()
}

// F9-T5: even a live session named "" receives nothing
#[tokio::test]
async fn the_empty_id_reaches_no_session() {
    let (mux, proxy) = proxy();
    let mut rx = mux.seed_session("");
    let frame = || crate::gateway::streaming::TaggedNotification {
        source: "gateway".to_string(),
        event_type: "message".to_string(),
        data: json!({}),
        event_id: None,
    };
    assert!(!mux.send_to_session("", frame()), "\"\" is not a session");
    let forwarded = proxy
        .forward_elicitation_with_response("", &elicitation(), Duration::from_secs(1))
        .await;
    assert!(
        matches!(forwarded, Err(SamplingError::NoSession)),
        "{forwarded:?}"
    );
    let outcome = tokio::time::timeout(
        Duration::from_secs(2),
        require_destructive_confirmation(&proxy, "", "kill server 'payments'"),
    )
    .await
    .expect("an empty id has nobody to ask, so the gate does not wait");
    assert_eq!(outcome, ConfirmationOutcome::Unsupported);
    assert!(rx.try_recv().is_err(), "nothing was delivered to \"\"");
}

// F9-T7b
#[tokio::test]
async fn a_refused_post_back_logs_both_sessions_by_fingerprint() {
    let (_mux, proxy) = proxy();
    let owner = "gw-0b7e5a11-owner-session";
    let attempted = "gw-a77e3c7e-attempted-session";
    let _rx = proxy.register_pending("elicitation-1".to_string(), owner);
    let (captured, _guard) = capture_debug();
    assert!(!proxy.resolve_pending("elicitation-1", attempted, json!({})));
    let text = captured.text();
    let message = "Refused sampling/elicitation POST-back";
    assert_fingerprinted(&text, message, owner);
    assert_fingerprinted(&text, message, attempted);
}

// F9-T7c, proxy.rs: the prompt senders other than elicitation-with-response
#[tokio::test]
async fn every_prompt_sender_logs_the_session_by_fingerprint() {
    let (mux, proxy) = proxy();
    let (live, mut rx) = mux.get_or_create_session(None);
    let dead = "gw-dead0000-no-such-session";
    let (captured, _guard) = capture_debug();

    assert!(proxy.forward_elicitation(&live, &elicitation()));
    assert!(!proxy.forward_elicitation(dead, &elicitation()));
    assert!(proxy.forward_sampling(&live, &sampling()));
    assert!(!proxy.forward_sampling(dead, &sampling()));
    let short = Duration::from_millis(50);
    let _ = proxy
        .forward_sampling_with_response(&live, &sampling(), short)
        .await;
    let _ = proxy.forward_roots_list_with_response(&live, short).await;
    let _ = tokio::time::timeout(
        short,
        crate::gateway::input_bridge::ClientChannel::send_request(
            &proxy,
            &live,
            "elicitation-bridge-1",
            "elicitation/create",
            None,
        ),
    )
    .await;
    while rx.try_recv().is_ok() {}

    let text = captured.text();
    assert_fingerprinted(&text, "Forwarded elicitation/create to client", &live);
    assert_fingerprinted(&text, "Failed to forward elicitation/create", dead);
    assert_fingerprinted(&text, "Forwarded sampling/createMessage to client", &live);
    assert_fingerprinted(&text, "Failed to forward sampling/createMessage", dead);
    assert_fingerprinted(&text, "Sent sampling/createMessage to the originating", &live);
    assert_fingerprinted(&text, "Sent roots/list to the originating session", &live);
    assert_fingerprinted(&text, "Sent bridged request to the originating", &live);
}

// F9-T7c, streaming.rs: create, send failure, subscribe and its failure, removal
#[tokio::test]
async fn the_session_store_logs_sessions_by_fingerprint() {
    // One registered stub backend, so auto-subscribe takes both of its arms.
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(Arc::new(crate::backend::Backend::new(
        "stub",
        crate::config::BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ))));
    let mux = Arc::new(NotificationMultiplexer::new(
        registry,
        StreamingConfig {
            auto_subscribe: vec!["no-such-backend".to_string(), "stub".to_string()],
            ..StreamingConfig::default()
        },
    ));
    let proxy = ProxyManager::new(Arc::clone(&mux));
    let (captured, _guard) = capture_debug();
    let (id, rx) = mux.get_or_create_session(None);
    drop(rx);
    assert!(!proxy.forward_elicitation(&id, &elicitation()));
    mux.auto_subscribe(&id).await;
    mux.remove_session(&id);
    let text = captured.text();
    assert_fingerprinted(&text, "Created new streaming session", &id);
    assert_fingerprinted(&text, "Failed to send notification", &id);
    assert_fingerprinted(&text, "Failed to auto-subscribe to backend", &id);
    assert_fingerprinted(&text, "Subscribed to backend notifications", &id);
    assert_fingerprinted(&text, "Removed streaming session", &id);
}

// F9-T7c, session_lifecycle.rs: disconnect cleanup
#[test]
fn session_cleanup_logs_the_session_by_fingerprint() {
    let lifecycle = crate::gateway::session_lifecycle::SessionLifecycle::new();
    lifecycle.register("f9-probe", |_| {});
    let id = "gw-c1ea0000-cleanup-session";
    let (captured, guard) = capture_debug();
    lifecycle.on_disconnect(id);
    drop(guard);
    let text = captured.text();
    assert_fingerprinted(&text, "Session disconnect cleanup", id);
    assert_fingerprinted(&text, "Cleanup handler executed", id);
}

// F9-T7c, security/firewall/mod.rs: the anomaly-block warning
#[test]
fn an_anomaly_block_logs_the_session_by_fingerprint() {
    use crate::security::firewall::{Firewall, FirewallConfig};
    use crate::transition::TransitionTracker;
    let tracker = Arc::new(TransitionTracker::new());
    for _ in 0..10 {
        tracker.record_transition("train", "srv:tool_a");
        tracker.record_transition("train", "srv:tool_b");
    }
    let fw = Firewall::from_config(
        FirewallConfig {
            anomaly_detection: true,
            anomaly_threshold: 0.7,
            anomaly_block_threshold: Some(0.9),
            ..FirewallConfig::default()
        },
        Some(tracker),
    );
    let id = "gw-f1e0a110-anomalous-session";
    fw.check_request(id, "srv", "tool_a", &json!({}), "caller", id);
    let (captured, guard) = capture_debug();
    let verdict = fw.check_request(id, "srv", "never_seen_tool", &json!({}), "caller", id);
    drop(guard);
    assert!(!verdict.allowed, "the fixture must reach the block arm");
    assert_fingerprinted(&captured.text(), "rogue-agent anomaly blocked", id);
}

// F9-T7e: the durable audit copy holds the fingerprint; a lookup by the raw
// id still finds it, and so does a lookup of an entry written before F9.
#[test]
fn the_transparency_log_stores_a_session_fingerprint() {
    use crate::gateway::session_id::session_fp;
    use crate::security::transparency_log::{
        TransparencyLogConfig, TransparencyLogger, show_session_entries,
    };
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let logger = TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: tmp.path().to_string_lossy().to_string(),
        key_id: "test".to_string(),
        shared_secret: String::new(),
    }))
    .unwrap();
    let id = "gw-7e000000-audited-session";
    logger
        .log_invocation(id, "c", "srv", "tool", "sha256:rr", "sha256:pp")
        .unwrap();
    let written = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(!written.contains(id), "raw session id stored: {written}");
    assert!(written.contains(&session_fp(id)), "{written}");
    let found = show_session_entries(tmp.path(), id).unwrap();
    assert_eq!(found.len(), 1, "a lookup by the raw id finds the entry");
    assert_eq!(found[0]["session_id"], session_fp(id));
    // An entry written before F9 carries the raw id and stays findable by it.
    let legacy = "gw-1e9ac700-pre-upgrade-session";
    let mut file = std::fs::OpenOptions::new().append(true).open(tmp.path()).unwrap();
    std::io::Write::write_all(&mut file, format!("{{\"session_id\":\"{legacy}\"}}\n").as_bytes())
        .unwrap();
    assert_eq!(show_session_entries(tmp.path(), legacy).unwrap().len(), 1);
}
