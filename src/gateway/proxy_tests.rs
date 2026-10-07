// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;
use crate::backend::BackendRegistry;
use crate::config::StreamingConfig;
use crate::protocol::{Content, ModelHint, ModelPreferences, SamplingMessage, ToolChoice};

fn make_multiplexer() -> Arc<NotificationMultiplexer> {
    let backends = Arc::new(BackendRegistry::new());
    let config = StreamingConfig::default();
    Arc::new(NotificationMultiplexer::new(backends, config))
}

// ── ProxyManager construction ──────────────────────────────────────

#[test]
fn proxy_manager_initializes_with_empty_roots() {
    let mux = make_multiplexer();
    let proxy = ProxyManager::new(mux);
    assert!(proxy.cached_roots().is_empty());
}

// ── Pending sampling request map ───────────────────────────────────

#[tokio::test]
async fn register_and_resolve_pending_delivers_response() {
    // GIVEN: a fresh proxy manager
    let mux = make_multiplexer();
    let proxy = ProxyManager::new(mux);

    // WHEN: we register a pending request and immediately resolve it
    let rx = proxy.register_pending("sampling-abc".to_string(), "session-a");
    let response = json!({"result": "done"});
    let resolved = proxy.resolve_pending("sampling-abc", "session-a", response.clone());

    // THEN: resolve returns true and the receiver gets the value
    assert!(resolved);
    let received = rx.await.expect("receiver should not be dropped");
    assert_eq!(received, response);
}

#[test]
fn resolve_pending_unknown_id_returns_false() {
    // GIVEN: a proxy manager with no pending requests
    let mux = make_multiplexer();
    let proxy = ProxyManager::new(mux);

    // WHEN: we try to resolve an ID that was never registered
    let resolved = proxy.resolve_pending("sampling-unknown", "session-a", json!({}));

    // THEN: returns false — no waiting caller
    assert!(!resolved);
}

#[test]
fn cancel_pending_removes_entry() {
    // GIVEN: a registered pending request
    let mux = make_multiplexer();
    let proxy = ProxyManager::new(mux);
    let _rx = proxy.register_pending("sampling-xyz".to_string(), "session-a");

    // WHEN: we cancel it
    proxy.cancel_pending("sampling-xyz");

    // THEN: resolving after cancellation returns false (entry gone)
    let resolved = proxy.resolve_pending("sampling-xyz", "session-a", json!({}));
    assert!(!resolved);
}

#[tokio::test]
async fn resolve_pending_with_dropped_receiver_does_not_panic() {
    // GIVEN: a pending request where the receiver has been dropped
    let mux = make_multiplexer();
    let proxy = ProxyManager::new(mux);
    let rx = proxy.register_pending("sampling-dropped".to_string(), "session-a");
    drop(rx); // simulate timeout dropping the receiver

    // WHEN: the client posts back a response
    let resolved = proxy.resolve_pending("sampling-dropped", "session-a", json!({"ok": true}));

    // THEN: returns true (entry existed) but send fails silently — no panic
    assert!(resolved);
}

#[tokio::test]
async fn resolve_pending_from_other_session_is_refused_and_does_not_race() {
    let mux = make_multiplexer();
    let proxy = ProxyManager::new(mux);

    let rx = proxy.register_pending("sampling-owned".to_string(), "session-a");
    let interloper = json!({"result": "hijack"});
    assert!(
        !proxy.resolve_pending("sampling-owned", "session-b", interloper),
        "a POST-back from a session that was not prompted must be refused"
    );

    let genuine = json!({"result": "from-owner"});
    assert!(
        proxy.resolve_pending("sampling-owned", "session-a", genuine.clone()),
        "the originating session must still be able to answer after a refused interloper"
    );
    let received = rx.await.expect("owner reply must still be delivered");
    assert_eq!(received, genuine);
}

#[tokio::test]
async fn sampling_request_reaches_only_the_originating_session() {
    let mux = make_multiplexer();
    let (session_a, mut rx_a) = mux.get_or_create_session(Some("sess-a"));
    let (_session_b, mut rx_b) = mux.get_or_create_session(Some("sess-b"));
    let proxy = Arc::new(ProxyManager::new(Arc::clone(&mux)));

    let params = SamplingCreateMessageParams {
        messages: vec![SamplingMessage {
            role: "user".to_string(),
            content: Content::Text {
                text: "secret prompt".to_string(),
                annotations: None,
            },
        }],
        tools: None,
        tool_choice: None,
        model_preferences: None,
        system_prompt: None,
        max_tokens: 16,
    };

    let proxy_for_task = Arc::clone(&proxy);
    let origin = session_a.clone();
    let wait = tokio::spawn(async move {
        proxy_for_task
            .forward_sampling_with_response(&origin, &params, Duration::from_secs(2))
            .await
    });

    let delivered = tokio::time::timeout(Duration::from_millis(500), rx_a.recv())
        .await
        .expect("originating session must receive the sampling request")
        .expect("channel open");
    assert_eq!(delivered.data["method"], "sampling/createMessage");
    assert_eq!(
        delivered.data["params"]["messages"][0]["content"]["text"],
        "secret prompt"
    );

    assert!(
        rx_b.try_recv().is_err(),
        "the other session must see nothing of the prompt"
    );

    let request_id = delivered.data["id"]
        .as_str()
        .expect("sampling request carries an id")
        .to_string();
    assert!(proxy.resolve_pending(
        &request_id,
        &session_a,
        json!({"result": {"role": "assistant", "content": {"type": "text", "text": "ok"}}})
    ));
    wait.await
        .expect("forward task join")
        .expect("originating session answered");
}

// ── Roots caching ──────────────────────────────────────────────────

#[test]
fn update_and_retrieve_cached_roots() {
    let mux = make_multiplexer();
    let proxy = ProxyManager::new(mux);

    let roots = vec![
        Root {
            uri: "file:///home/user/project".to_string(),
            name: Some("project".to_string()),
        },
        Root {
            uri: "file:///tmp".to_string(),
            name: None,
        },
    ];

    proxy.update_cached_roots(roots.clone());
    let cached = proxy.cached_roots();
    assert_eq!(cached.len(), 2);
    assert_eq!(cached[0].uri, "file:///home/user/project");
    assert_eq!(cached[0].name.as_deref(), Some("project"));
    assert_eq!(cached[1].uri, "file:///tmp");
    assert!(cached[1].name.is_none());
}

#[test]
fn update_cached_roots_replaces_previous() {
    let mux = make_multiplexer();
    let proxy = ProxyManager::new(mux);

    proxy.update_cached_roots(vec![Root {
        uri: "file:///old".to_string(),
        name: None,
    }]);
    assert_eq!(proxy.cached_roots().len(), 1);

    proxy.update_cached_roots(vec![
        Root {
            uri: "file:///new1".to_string(),
            name: None,
        },
        Root {
            uri: "file:///new2".to_string(),
            name: None,
        },
    ]);
    assert_eq!(proxy.cached_roots().len(), 2);
    assert_eq!(proxy.cached_roots()[0].uri, "file:///new1");
}

// ── Elicitation forwarding ─────────────────────────────────────────

#[test]
fn forward_elicitation_to_nonexistent_session_returns_false() {
    let mux = make_multiplexer();
    let proxy = ProxyManager::new(mux);

    let params = ElicitationCreateParams {
        mode: None,
        message: "Please provide your API key".to_string(),
        requested_schema: Some(json!({
            "type": "object",
            "properties": {
                "api_key": { "type": "string" }
            }
        })),
        url: None,
    };

    assert!(!proxy.forward_elicitation("nonexistent-session", &params));
}

#[tokio::test]
async fn forward_elicitation_to_existing_session() {
    let mux = make_multiplexer();
    let (session_id, mut rx) = mux.get_or_create_session(Some("elicit-test"));
    let proxy = ProxyManager::new(Arc::clone(&mux));

    let params = ElicitationCreateParams {
        mode: None,
        message: "Enter name".to_string(),
        requested_schema: None,
        url: None,
    };

    assert!(proxy.forward_elicitation(&session_id, &params));

    let received = rx.recv().await.unwrap();
    assert_eq!(received.event_type, "proxy_request");
    assert_eq!(received.data["method"], "elicitation/create");
    assert_eq!(received.data["params"]["message"], "Enter name");
}

// ── Sampling forwarding ────────────────────────────────────────────

#[test]
fn forward_sampling_to_nonexistent_session_returns_false() {
    let mux = make_multiplexer();
    let proxy = ProxyManager::new(mux);

    let params = SamplingCreateMessageParams {
        messages: vec![SamplingMessage {
            role: "user".to_string(),
            content: Content::Text {
                text: "Hello".to_string(),
                annotations: None,
            },
        }],
        tools: None,
        tool_choice: None,
        model_preferences: None,
        system_prompt: None,
        max_tokens: 100,
    };

    assert!(!proxy.forward_sampling("nonexistent-session", &params));
}

#[tokio::test]
async fn forward_sampling_to_existing_session() {
    let mux = make_multiplexer();
    let (session_id, mut rx) = mux.get_or_create_session(Some("sample-test"));
    let proxy = ProxyManager::new(Arc::clone(&mux));

    let params = SamplingCreateMessageParams {
        messages: vec![SamplingMessage {
            role: "user".to_string(),
            content: Content::Text {
                text: "Summarize this".to_string(),
                annotations: None,
            },
        }],
        tools: None,
        tool_choice: Some(ToolChoice::Auto),
        model_preferences: Some(ModelPreferences {
            hints: vec![ModelHint {
                name: "claude-3-opus".to_string(),
            }],
            cost_priority: Some(0.3),
            speed_priority: Some(0.5),
            intelligence_priority: Some(0.8),
        }),
        system_prompt: Some("You are a helpful assistant.".to_string()),
        max_tokens: 1024,
    };

    assert!(proxy.forward_sampling(&session_id, &params));

    let received = rx.recv().await.unwrap();
    assert_eq!(received.event_type, "proxy_request");
    assert_eq!(received.data["method"], "sampling/createMessage");
    assert_eq!(received.data["params"]["maxTokens"], 1024);
}

// ── T2.8: tools/list_changed broadcast ────────────────────────────
// Scoped delivery reaches nobody without an authorizer; auth off keeps
// "every session" the meaning of these rows. Scope rows: proxy_scope_tests.

fn auth_off_multiplexer() -> Arc<NotificationMultiplexer> {
    let mux = make_multiplexer();
    let config = crate::config::AuthConfig::default();
    mux.set_authorizer(crate::gateway::auth::AuthState {
        auth_config: Arc::new(crate::gateway::auth::ResolvedAuthConfig::from_config(
            &config,
        )),
        key_server: None,
        dashboard_bootstrap: Arc::new(crate::gateway::auth::DashboardBootstrap::new()),
        tls_enabled: false,
        live_config: std::sync::Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
    });
    mux
}

#[tokio::test]
async fn broadcast_tools_list_changed_reaches_all_sessions() {
    // GIVEN: two connected sessions
    let mux = auth_off_multiplexer();
    let (_id1, mut rx1) = mux.get_or_create_session(Some("tools-session-a"));
    let (_id2, mut rx2) = mux.get_or_create_session(Some("tools-session-b"));
    let proxy = ProxyManager::new(Arc::clone(&mux));

    // WHEN: broadcasting tools/list_changed
    proxy.broadcast_tools_list_changed("alpha").await;

    // THEN: both sessions receive the correct MCP notification
    let r1 = rx1.recv().await.unwrap();
    let r2 = rx2.recv().await.unwrap();
    assert_eq!(r1.data["method"], "notifications/tools/list_changed");
    assert_eq!(r2.data["method"], "notifications/tools/list_changed");
}

#[tokio::test]
async fn broadcast_tools_list_changed_uses_the_mcp_message_event_type() {
    // GIVEN: one session
    let mux = auth_off_multiplexer();
    let (_id, mut rx) = mux.get_or_create_session(Some("tools-session-c"));
    let proxy = ProxyManager::new(Arc::clone(&mux));

    // WHEN: broadcasting
    proxy.broadcast_tools_list_changed("alpha").await;

    // THEN: event_type is "message", which the GET stream writes as bare
    // JSON-RPC; any other type is wrapped in an envelope no MCP client reads.
    let received = rx.recv().await.unwrap();
    assert_eq!(received.event_type, "message");
    assert_eq!(received.source, "gateway");
}

#[tokio::test]
async fn broadcast_tools_list_changed_no_op_when_no_sessions() {
    // GIVEN: no connected sessions
    let mux = auth_off_multiplexer();
    let proxy = ProxyManager::new(Arc::clone(&mux));

    // WHEN / THEN: no panic
    proxy.broadcast_tools_list_changed("alpha").await;
}

// ── Undeliverable prompts must not leak their pending entry ────────

#[tokio::test]
async fn undeliverable_sampling_leaves_no_pending_entry() {
    // GIVEN: a proxy with no connected sessions
    let mux = make_multiplexer();
    let proxy = ProxyManager::new(mux);
    let params = SamplingCreateMessageParams {
        messages: vec![SamplingMessage {
            role: "user".to_string(),
            content: Content::Text {
                text: "Hello".to_string(),
                annotations: None,
            },
        }],
        tools: None,
        tool_choice: None,
        model_preferences: None,
        system_prompt: None,
        max_tokens: 100,
    };

    // WHEN: delivery to a session that does not exist fails
    let result = proxy
        .forward_sampling_with_response("absent", &params, Duration::from_millis(50))
        .await;

    // THEN: the caller sees NoSession and nothing is left allocated
    assert!(matches!(result, Err(SamplingError::NoSession)));
    assert_eq!(
        proxy.pending_sampling.read().len(),
        0,
        "an undeliverable prompt must not leave a pending entry behind"
    );
}

#[tokio::test]
async fn undeliverable_elicitation_leaves_no_pending_entry() {
    // GIVEN: a proxy with no connected sessions
    let mux = make_multiplexer();
    let proxy = ProxyManager::new(mux);
    let params = ElicitationCreateParams {
        mode: None,
        message: "Confirm?".to_string(),
        requested_schema: Some(json!({"type": "object"})),
        url: None,
    };

    // WHEN: delivery to a session that does not exist fails
    let result = proxy
        .forward_elicitation_with_response("absent", &params, Duration::from_millis(50))
        .await;

    // THEN: the caller sees NoSession and nothing is left allocated
    assert!(matches!(result, Err(SamplingError::NoSession)));
    assert_eq!(
        proxy.pending_sampling.read().len(),
        0,
        "an undeliverable prompt must not leave a pending entry behind"
    );
}

// The WIRE.11 cancellation, MIK-7388 cross-exchange and minor-11a
// elicitation-id rows, kept in a file of their own to hold both files under
// the size ceiling.
#[path = "proxy_cancellation_tests.rs"]
mod cancellation;

// ── MIK-7887.RECEIPT.3: the bridged-request channel's commit point ──

fn counting_commit() -> (
    crate::gateway::input_bridge::DeliveryCommit,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    let runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = Arc::clone(&runs);
    let commit = crate::gateway::input_bridge::DeliveryCommit::new(move || {
        counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    });
    (commit, runs)
}

/// A request a stream of the session wrote commits before the reply, and
/// stays committed when the wait is abandoned (MIK-7939: written, not queued).
#[tokio::test]
async fn a_bridged_request_commits_once_the_session_stream_writes_it() {
    use crate::gateway::input_bridge::ClientChannel as _;
    use std::sync::atomic::Ordering;
    let mux = make_multiplexer();
    let (session, mut rx) = mux.get_or_create_session(Some("sess-c"));
    let proxy = ProxyManager::new(Arc::clone(&mux));
    let (commit, runs) = counting_commit();
    let outcome = tokio::time::timeout(
        Duration::from_millis(50),
        proxy.send_request_committing(&session, "b-1", "elicitation/create", None, Some(commit)),
    )
    .await;
    assert!(outcome.is_err(), "no reply came");
    let sent = rx
        .try_recv()
        .expect("the request reached the session stream");
    assert_eq!(sent.data["method"], "elicitation/create");
    assert_eq!(runs.load(Ordering::SeqCst), 0, "queued is not written");
    sent.written();
    assert_eq!(runs.load(Ordering::SeqCst), 1);
}

/// An unknown session reached nobody: no commit.
#[tokio::test]
async fn a_bridged_request_to_no_session_commits_nothing() {
    use crate::gateway::input_bridge::{ClientChannel as _, DeliveryError};
    use std::sync::atomic::Ordering;
    let proxy = ProxyManager::new(make_multiplexer());
    let (commit, runs) = counting_commit();
    let sent = proxy
        .send_request_committing(
            "no-such-session",
            "b-2",
            "elicitation/create",
            None,
            Some(commit),
        )
        .await;
    assert!(matches!(sent, Err(DeliveryError::NoSession)), "{sent:?}");
    assert_eq!(runs.load(Ordering::SeqCst), 0);
}

/// MIK-7939 D6.RELAY.5/.11: a bridged prompt's relay receipt commits when a
/// stream writes it, not when it is queued: a queued copy can still be
/// withheld by the stream's audit gate or dropped by a lagging subscriber.
#[tokio::test]
async fn a_bridged_prompt_commits_its_receipt_only_when_written() {
    use std::sync::atomic::Ordering;
    let mux = make_multiplexer();
    let (session, mut rx) = mux.get_or_create_session(Some("sess-commit"));
    let proxy = Arc::new(ProxyManager::new(Arc::clone(&mux)));
    let (commit, commits) = counting_commit();
    let (task_proxy, origin) = (Arc::clone(&proxy), session.clone());
    let wait = tokio::spawn(async move {
        task_proxy
            .send_request_committing(&origin, "rq-1", "elicitation/create", None, Some(commit))
            .await
    });
    let queued = tokio::time::timeout(Duration::from_millis(500), rx.recv())
        .await
        .expect("the session receives the prompt")
        .expect("channel open");
    assert_eq!(queued.data["id"], "rq-1");
    assert_eq!(
        commits.load(Ordering::SeqCst),
        0,
        "the receipt committed while the prompt was only queued"
    );
    // A second copy (another stream of the session) is the same frame.
    let copy = queued.clone();
    queued.written();
    assert_eq!(
        commits.load(Ordering::SeqCst),
        1,
        "a written prompt commits"
    );
    copy.written();
    assert_eq!(commits.load(Ordering::SeqCst), 1, "it commits once");
    wait.abort();
}

/// MIK-7939: a copy that is never written (dropped by a lagging subscriber,
/// or by a stream that closed) commits nothing.
#[tokio::test]
async fn an_unwritten_prompt_commits_nothing() {
    use std::sync::atomic::Ordering;
    let mux = make_multiplexer();
    let (session, mut rx) = mux.get_or_create_session(Some("sess-dropped"));
    let proxy = Arc::new(ProxyManager::new(Arc::clone(&mux)));
    let (commit, commits) = counting_commit();
    let (task_proxy, origin) = (Arc::clone(&proxy), session.clone());
    let wait = tokio::spawn(async move {
        task_proxy
            .send_request_committing(&origin, "rq-2", "elicitation/create", None, Some(commit))
            .await
    });
    let queued = tokio::time::timeout(Duration::from_millis(500), rx.recv())
        .await
        .expect("the session receives the prompt")
        .expect("channel open");
    drop(queued);
    drop(rx);
    wait.abort();
    let _ = wait.await;
    assert_eq!(commits.load(Ordering::SeqCst), 0);
}
