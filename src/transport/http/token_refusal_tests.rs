// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The interactive token step (`detach_token_step`) and a lazy start's OAuth
//! handshake (`connect`) each run in a task of their own, so a destination
//! refusal raised inside cannot reach the calling delivery's task-local
//! record. The caller records it where it joins the task.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex as TokioMutex;

use crate::gateway::delivery_facts;
use crate::oauth::client::destination::client_with_refused_refresh;
use crate::oauth::login_gate::LoginGate;
use crate::oauth::{OAuthClient, OAuthClientConfig, TokenStorage};
use crate::security::ssrf::DestinationPolicy;
use crate::security::ssrf::is_ssrf_refusal;

/// A tool call whose detached token refresh is refused by the destination
/// policy records `refused` on that call's delivery.
#[tokio::test]
async fn a_refused_detached_refresh_records_refused_on_the_call() {
    let dir = tempfile::tempdir().unwrap();
    let gate = Arc::new(LoginGate::default());
    let client = client_with_refused_refresh(dir.path())
        .await
        .with_login_gate(Arc::clone(&gate));
    let set_out = gate.set_out_now();
    let oauth = Arc::new(TokioMutex::new(client));
    let (outcome, facts) = delivery_facts::scope(async {
        let outcome = tokio::time::timeout(
            Duration::from_secs(10),
            super::detach_token_step(oauth, gate, set_out, "listed-backend".to_owned()),
        )
        .await
        .expect("answered promptly");
        (outcome, delivery_facts::snapshot())
    })
    .await;
    let error = outcome.expect_err("a refused refresh must surface");
    // The classifier the join point keys on: a change to how this refusal
    // is built fails here. The cleartext refusals are pinned the same way
    // in `oauth/client/cleartext_tests.rs`.
    assert!(is_ssrf_refusal(&error), "{error}");
    // Read as the delivery record renders it.
    let mut fields = serde_json::Map::new();
    delivery_facts::record_fields(facts.as_ref(), false, &mut fields);
    assert_eq!(
        fields.get("response_effect"),
        Some(&"refused".into()),
        "{fields:?}"
    );
}

/// A transport whose OAuth discovery the destination policy refuses: the
/// resource is a loopback literal, which `Public` denies before any request.
fn transport_with_refused_discovery(dir: &std::path::Path) -> Arc<crate::transport::HttpTransport> {
    let base = "http://127.0.0.1:1/mcp";
    let client = OAuthClient::with_destination(
        DestinationPolicy::Public,
        crate::oauth::client::destination::http_client(DestinationPolicy::Public).unwrap(),
        "listed-backend".to_string(),
        base.to_string(),
        vec![],
        Arc::new(TokenStorage::new(dir.to_path_buf()).unwrap()),
        OAuthClientConfig::default(),
    );
    crate::transport::HttpTransport::new_with_oauth(
        base,
        std::collections::HashMap::new(),
        Duration::from_secs(5),
        true,
        Some(client),
        None,
    )
    .unwrap()
}

/// The `response_effect` a connect leaves on the delivery it runs in.
async fn effect_of_connect(
    transport: &crate::transport::HttpTransport,
    interactive: bool,
) -> Option<serde_json::Value> {
    let connect = async {
        let outcome = tokio::time::timeout(Duration::from_secs(10), transport.connect())
            .await
            .expect("answered promptly");
        let error = outcome.expect_err("a refused discovery must surface");
        assert!(is_ssrf_refusal(&error), "{error}");
        delivery_facts::snapshot()
    };
    let facts = if interactive {
        delivery_facts::scope(connect).await
    } else {
        delivery_facts::scope(crate::oauth::login_gate::non_interactive(connect)).await
    };
    let mut fields = serde_json::Map::new();
    delivery_facts::record_fields(facts.as_ref(), false, &mut fields);
    fields.get("response_effect").cloned()
}

/// A tool call that starts its backend, whose OAuth discovery the destination
/// policy refuses, records `refused` on that call's delivery.
#[tokio::test]
async fn a_lazy_start_refused_in_discovery_records_refused_on_the_call() {
    let dir = tempfile::tempdir().unwrap();
    let transport = transport_with_refused_discovery(dir.path());
    assert_eq!(
        effect_of_connect(&transport, true).await,
        Some("refused".into())
    );
}

/// A non-interactive start (the health probe, an upstream task query) turns
/// the error into an answer of its own, so it records no refusal.
#[tokio::test]
async fn a_non_interactive_start_refused_in_discovery_records_no_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let transport = transport_with_refused_discovery(dir.path());
    assert_eq!(
        effect_of_connect(&transport, false).await,
        Some("delivered".into())
    );
}

/// A non-interactive token step (the health probe, an upstream task query,
/// a close) reads its token in the caller's task, and every such caller turns
/// a refused refresh into an answer of its own: it records no refusal.
#[tokio::test]
async fn a_non_interactive_refused_refresh_records_no_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let client = client_with_refused_refresh(dir.path()).await;
    let transport = crate::transport::HttpTransport::new_with_oauth(
        "http://127.0.0.1:1/mcp",
        std::collections::HashMap::new(),
        Duration::from_secs(5),
        true,
        Some(client),
        None,
    )
    .unwrap();
    let facts = delivery_facts::scope(crate::oauth::login_gate::non_interactive(async {
        let outcome = tokio::time::timeout(Duration::from_secs(10), transport.get_oauth_token())
            .await
            .expect("answered promptly");
        let error = outcome.expect_err("a refused refresh must surface");
        assert!(is_ssrf_refusal(&error), "{error}");
        delivery_facts::snapshot()
    }))
    .await;
    let mut fields = serde_json::Map::new();
    delivery_facts::record_fields(facts.as_ref(), false, &mut fields);
    assert_eq!(
        fields.get("response_effect"),
        Some(&"delivered".into()),
        "{fields:?}"
    );
}
