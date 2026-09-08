// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! WIRE.11 raw production channel and WIRE.18 private-writer controls.
//!
//! These tests use the actual ProxyManager pending map and selected request
//! queue. HTTP body-yield and stdio flush are separate transport-level cases.

mod sse_body_tests;

use super::*;
use crate::config::StreamingConfig;
use crate::gateway::input_bridge::{
    BackendInvoker, BridgeBounds, BridgeError, BridgeObserver, BridgeRecord, ClientChannel,
    DeliveryError, DeliveryProgress, InputBridge,
};
use crate::gateway::streaming::{QueuedRequest, RequestWriter};

const LIMIT: Duration = Duration::from_secs(5);
const BRIDGE_PROMPT_TIMEOUT: Duration = Duration::from_millis(100);

fn fixture() -> (Arc<NotificationMultiplexer>, Arc<ProxyManager>, String) {
    let mux = super::tests::make_multiplexer();
    let (session, _notifications) = mux.get_or_create_session(None);
    let proxy = Arc::new(ProxyManager::new(Arc::clone(&mux)));
    (mux, proxy, session)
}

fn start(
    proxy: &Arc<ProxyManager>,
    session: &str,
    id: &str,
    method: &str,
    params: Option<Value>,
) -> tokio::task::JoinHandle<Result<Value, DeliveryError>> {
    let proxy = Arc::clone(proxy);
    let session = session.to_string();
    let id = id.to_string();
    let method = method.to_string();
    tokio::spawn(async move {
        proxy
            .send_request(
                &session,
                &id,
                &method,
                params,
                Arc::new(DeliveryProgress::default()),
            )
            .await
    })
}

async fn receive(writer: &mut RequestWriter) -> QueuedRequest {
    tokio::time::timeout(LIMIT, writer.recv())
        .await
        .expect("the production channel must enqueue a request")
        .expect("the selected writer remains open")
}

async fn queued(writer: &RequestWriter, count: usize) {
    tokio::time::timeout(LIMIT, async {
        while writer.queued_count() != count {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the exact queue occupancy must be observed before proceeding");
}

async fn finish(
    wait: tokio::task::JoinHandle<Result<Value, DeliveryError>>,
) -> Result<Value, DeliveryError> {
    tokio::time::timeout(LIMIT, wait)
        .await
        .expect("the exchange must finish within its outer test bound")
        .expect("the exchange task must not panic")
}

fn pending(proxy: &ProxyManager, id: &str) -> bool {
    proxy.pending_sampling.read().contains_key(id)
}

#[tokio::test]
async fn mik_7388_channel_abort_after_register_cleans_pending() {
    let (mux, proxy, session) = fixture();
    let mut writer = mux.register_request_writer(&session).expect("live session");
    let id = "roots-abort-before-handoff";
    let wait = start(&proxy, &session, id, "roots/list", None);
    let frame = receive(&mut writer).await;
    assert!(
        pending(&proxy, id),
        "precondition: supplied ID is registered"
    );

    wait.abort();
    assert!(
        tokio::time::timeout(LIMIT, wait)
            .await
            .expect("cancelled task must be reaped within the test bound")
            .expect_err("abort must cancel the task")
            .is_cancelled()
    );

    assert!(
        !pending(&proxy, id),
        "cancellation must remove the exact pending ID"
    );
    assert!(
        !frame.delivery.mark_handed_off(),
        "a cancelled queued frame cannot later become a delivered prompt"
    );
    assert!(!proxy.resolve_pending(id, &session, json!({"jsonrpc":"2.0","id":id,"result":{}})));
}

#[tokio::test]
async fn mik_7388_channel_abort_awaiting_reply_cleans_pending() {
    let (mux, proxy, session) = fixture();
    let mut writer = mux.register_request_writer(&session).expect("live session");
    let id = "sampling-abort-after-handoff";
    let wait = start(
        &proxy,
        &session,
        id,
        "sampling/createMessage",
        Some(json!({})),
    );
    let frame = receive(&mut writer).await;
    assert!(frame.delivery.mark_handed_off());
    assert!(
        pending(&proxy, id),
        "precondition: handed-off prompt awaits a reply"
    );

    wait.abort();
    assert!(
        tokio::time::timeout(LIMIT, wait)
            .await
            .expect("cancelled task must be reaped within the test bound")
            .expect_err("abort must cancel the task")
            .is_cancelled()
    );

    assert!(
        !pending(&proxy, id),
        "the drop guard must remove a delivered waiter"
    );
    assert!(!proxy.resolve_pending(id, &session, json!({"jsonrpc":"2.0","id":id,"result":{}})));
}

#[tokio::test]
async fn mik_7388_channel_abort_before_queue_receive_suppresses_late_delivery() {
    let (mux, proxy, session) = fixture();
    let mut writer = mux.register_request_writer(&session).expect("writer");
    let id = "roots-abort-still-queued";
    let wait = start(&proxy, &session, id, "roots/list", None);
    queued(&writer, 1).await;
    assert!(
        pending(&proxy, id),
        "the request must still occupy the unreceived queue"
    );
    wait.abort();
    assert!(
        tokio::time::timeout(LIMIT, wait)
            .await
            .expect("bounded abort join")
            .expect_err("the task must be cancelled")
            .is_cancelled()
    );
    assert!(!pending(&proxy, id));
    match writer.try_recv() {
        Ok(frame) => {
            let request: Value = serde_json::from_str(&frame.json).expect("queued frame");
            assert_eq!(request["id"], id);
            assert!(
                !frame.delivery.mark_handed_off(),
                "unreceived cancelled work cannot become a live prompt"
            );
        }
        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
            panic!("cancelling one request must not close the live writer")
        }
    }
    assert!(!proxy.resolve_pending(
        id,
        &session,
        json!({"jsonrpc":"2.0","id":id,"result":{"roots":[]}})
    ));

    // The same writer must remain usable; closing it cannot masquerade as
    // successful cancellation cleanup or suppress all subsequent requests.
    let next_id = "roots-after-queued-cancel";
    let next = start(&proxy, &session, next_id, "roots/list", None);
    let frame = receive(&mut writer).await;
    let request: Value = serde_json::from_str(&frame.json).expect("new frame");
    assert_eq!(request["id"], next_id);
    assert!(frame.delivery.mark_handed_off());
    let reply = json!({"jsonrpc":"2.0","id":next_id,"result":{"roots":[]}});
    assert!(proxy.resolve_pending(next_id, &session, reply.clone()));
    assert_eq!(finish(next).await, Ok(reply));
    assert!(!pending(&proxy, next_id));
}

#[tokio::test]
async fn mik_7388_channel_no_request_writer_refuses_without_pending_state() {
    let (mux, proxy, session) = fixture();
    // A notification subscriber must not accidentally qualify as a request
    // writer: the old broadcast primitive would expose the prompt here.
    let (_, mut notifications) = mux.get_or_create_session(Some(&session));
    let id = "roots-no-writer";
    let result = finish(start(&proxy, &session, id, "roots/list", None)).await;
    assert_eq!(result, Err(DeliveryError::NoSession));
    assert!(!pending(&proxy, id));
    assert!(matches!(
        notifications.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
}

async fn exact_roundtrip(method: &str, id: &str, params: Option<Value>) {
    let (mux, proxy, session) = fixture();
    let mut writer = mux.register_request_writer(&session).expect("live session");
    let wait = start(&proxy, &session, id, method, params.clone());
    let frame = receive(&mut writer).await;
    let request: Value = serde_json::from_str(&frame.json).expect("complete JSON-RPC frame");
    assert_eq!(request["jsonrpc"], "2.0");
    assert_eq!(
        request["id"], id,
        "the bridge's supplied ID must not be replaced"
    );
    assert_eq!(request["method"], method);
    assert_eq!(
        request.get("params"),
        params.as_ref(),
        "raw params must survive"
    );
    assert!(pending(&proxy, id));
    assert!(frame.delivery.mark_handed_off());
    let mut result = match method {
        "sampling/createMessage" => {
            json!({"role":"assistant","content":{"type":"text","text":"done"},"model":"fixture","stopReason":"endTurn"})
        }
        "roots/list" => json!({"roots":[{"uri":"file:///repo","name":"repo"}]}),
        "elicitation/create"
            if params
                .as_ref()
                .and_then(|p| p.get("mode"))
                .and_then(Value::as_str)
                == Some("url") =>
        {
            json!({"action":"accept"})
        }
        "elicitation/create" => json!({"action":"accept","content":{"branch":"main"}}),
        _ => panic!("the fixture must name a supported method"),
    };
    result["extra"] = json!([7, {"opaque":true}]);
    let response = json!({"jsonrpc":"2.0", "id":id, "result":result});
    assert!(proxy.resolve_pending(id, &session, response.clone()));
    assert_eq!(
        finish(wait).await,
        Ok(response),
        "channel returns the whole envelope once"
    );
    assert!(!pending(&proxy, id));
    assert!(!proxy.resolve_pending(id, &session, json!({"result": "duplicate"})));
}

#[tokio::test]
async fn mik_7388_channel_sampling_preserves_raw_params_and_id() {
    exact_roundtrip(
        "sampling/createMessage",
        "sampling-raw-id",
        Some(json!({"messages":[{"role":"user","content":{"type":"text","text":"hello"}}],"maxTokens":2,"_meta":{"example.test/key":true},"future":[1,2]})),
    )
    .await;
}

#[tokio::test]
async fn mik_7388_channel_form_preserves_raw_params_and_id() {
    exact_roundtrip(
        "elicitation/create",
        "elicitation-raw-id",
        Some(json!({"message":"Pick","requestedSchema":{"type":"object","properties":{}},"future":{"x":true}})),
    )
    .await;
}

#[tokio::test]
async fn mik_7388_channel_explicit_form_preserves_raw_params_and_id() {
    exact_roundtrip(
        "elicitation/create",
        "elicitation-explicit-form-id",
        Some(json!({"mode":"form","message":"Pick","requestedSchema":{"type":"object","properties":{}},"future":{"x":true}})),
    )
    .await;
}

#[tokio::test]
async fn mik_7388_channel_roots_preserves_absent_params_and_id() {
    exact_roundtrip("roots/list", "roots-raw-id", None).await;
}

#[tokio::test]
async fn mik_7388_channel_url_inserts_only_missing_legacy_id() {
    let (mux, proxy, session) = fixture();
    let mut writer = mux.register_request_writer(&session).expect("live session");
    let id = "elicitation-url-bridge-id";
    let params = json!({"mode":"url","message":"Open","url":"https://example.test/a?q=1","future":{"x":true}});
    let wait = start(
        &proxy,
        &session,
        id,
        "elicitation/create",
        Some(params.clone()),
    );
    let frame = receive(&mut writer).await;
    let request: Value = serde_json::from_str(&frame.json).expect("complete JSON-RPC frame");
    let mut expected = params;
    expected["elicitationId"] = json!(id);
    assert_eq!(request["id"], id);
    assert_eq!(
        request["params"], expected,
        "one spec-required envelope addition only"
    );
    assert!(frame.delivery.mark_handed_off());
    let response = json!({"jsonrpc":"2.0","id":id,"result":{"action":"accept"}});
    assert!(proxy.resolve_pending(id, &session, response.clone()));
    assert_eq!(finish(wait).await, Ok(response));
}

#[tokio::test]
async fn mik_7388_channel_url_preserves_existing_legacy_id() {
    exact_roundtrip(
        "elicitation/create",
        "elicitation-url-existing",
        Some(json!({"mode":"url","message":"Open","url":"https://example.test/a","elicitationId":"backend-original","future":42})),
    )
    .await;
}

#[tokio::test]
async fn mik_7388_channel_client_error_is_a_raw_correlated_reply() {
    let (mux, proxy, session) = fixture();
    let mut writer = mux.register_request_writer(&session).expect("live session");
    let id = "roots-client-error";
    let wait = start(&proxy, &session, id, "roots/list", None);
    let frame = receive(&mut writer).await;
    let reply = json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"unsupported","data":{"kept":true}}});
    // A correlated reply itself proves delivery, even before a writer's
    // acknowledgement runs. The bridge, not the channel, interprets refusal.
    assert!(proxy.resolve_pending(id, &session, reply.clone()));
    assert!(
        !frame.delivery.mark_handed_off(),
        "a response-terminal exchange cannot be revived by a late writer acknowledgement"
    );
    assert_eq!(finish(wait).await, Ok(reply));
    assert!(!pending(&proxy, id));
}

#[tokio::test]
async fn mik_7388_channel_wrong_session_cannot_consume_the_reply() {
    let (mux, proxy, session) = fixture();
    let (other, _) = mux.get_or_create_session(None);
    let mut writer = mux.register_request_writer(&session).expect("live session");
    let id = "roots-owner-bound";
    let wait = start(&proxy, &session, id, "roots/list", None);
    let frame = receive(&mut writer).await;
    assert!(frame.delivery.mark_handed_off());
    assert!(!proxy.resolve_pending(
        id,
        &other,
        json!({"jsonrpc":"2.0","id":id,"result":{"roots":[]}})
    ));
    assert!(
        pending(&proxy, id),
        "wrong owner cannot consume or remove the entry"
    );
    let reply = json!({"jsonrpc":"2.0","id":id,"result":{"roots":[]}});
    assert!(proxy.resolve_pending(id, &session, reply.clone()));
    assert_eq!(finish(wait).await, Ok(reply));
    assert!(!pending(&proxy, id));
}

async fn disconnected_selected_writer(handed_off: bool) {
    let (mux, proxy, session) = fixture();
    let mut selected = mux.register_request_writer(&session).expect("first writer");
    let mut other = mux
        .register_request_writer(&session)
        .expect("second writer");
    let id = "roots-selected-disconnect";
    let wait = start(&proxy, &session, id, "roots/list", None);
    let frame = receive(&mut selected).await;
    assert!(
        pending(&proxy, id),
        "precondition: selected writer owns a real pending call"
    );
    if handed_off {
        assert!(frame.delivery.mark_handed_off());
    }
    drop(selected);
    assert_eq!(finish(wait).await, Err(DeliveryError::NoSession));
    assert!(!pending(&proxy, id));
    assert!(
        matches!(
            other.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ),
        "an uncertain question must not replay to the remaining writer"
    );
    assert!(
        !frame.delivery.mark_handed_off(),
        "a failed delivery cannot revive"
    );
}

#[tokio::test]
async fn mik_7388_channel_selected_writer_drop_before_handoff_refuses() {
    disconnected_selected_writer(false).await;
}

#[tokio::test]
async fn mik_7388_channel_selected_writer_drop_after_handoff_refuses() {
    disconnected_selected_writer(true).await;
}

#[tokio::test]
async fn mik_7388_channel_two_writers_receive_one_request_total() {
    let (mux, proxy, session) = fixture();
    let mut first = mux.register_request_writer(&session).expect("first writer");
    let mut second = mux
        .register_request_writer(&session)
        .expect("second writer");
    let id = "roots-single-recipient";
    let wait = start(&proxy, &session, id, "roots/list", None);
    let frame = receive(&mut first).await;
    assert!(matches!(
        second.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert!(frame.delivery.mark_handed_off());
    let reply = json!({"jsonrpc":"2.0","id":id,"result":{"roots":[]}});
    assert!(proxy.resolve_pending(id, &session, reply.clone()));
    assert_eq!(finish(wait).await, Ok(reply));
    assert!(matches!(
        second.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert!(!pending(&proxy, id));
}

#[tokio::test]
async fn mik_7388_channel_full_first_queue_selects_the_next_writer_once() {
    let mux = super::tests::make_multiplexer_with_config(StreamingConfig {
        buffer_size: 1,
        ..StreamingConfig::default()
    });
    let (session, _notifications) = mux.get_or_create_session(None);
    let proxy = Arc::new(ProxyManager::new(Arc::clone(&mux)));
    let mut first = mux.register_request_writer(&session).expect("first writer");
    let first_id = "roots-fill-first-queue";
    let first_wait = start(&proxy, &session, first_id, "roots/list", None);
    queued(&first, 1).await;
    assert!(pending(&proxy, first_id));

    let mut second = mux
        .register_request_writer(&session)
        .expect("second writer");
    let second_id = "roots-fallback-second-queue";
    let second_wait = start(&proxy, &session, second_id, "roots/list", None);
    queued(&second, 1).await;
    assert_eq!(
        first.queued_count(),
        1,
        "fallback must not overfill the first queue"
    );
    assert!(pending(&proxy, second_id));

    let refused_id = "roots-all-queues-full";
    assert_eq!(
        finish(start(&proxy, &session, refused_id, "roots/list", None)).await,
        Err(DeliveryError::NoSession)
    );
    assert!(!pending(&proxy, refused_id));
    assert_eq!(first.queued_count(), 1);
    assert_eq!(second.queued_count(), 1);

    for (writer, id, wait) in [
        (&mut first, first_id, first_wait),
        (&mut second, second_id, second_wait),
    ] {
        let frame = receive(writer).await;
        let request: Value = serde_json::from_str(&frame.json).expect("complete frame");
        assert_eq!(
            request["id"], id,
            "each selected writer receives only its own request"
        );
        assert!(frame.delivery.mark_handed_off());
        let reply = json!({"jsonrpc":"2.0","id":id,"result":{"roots":[]}});
        assert!(proxy.resolve_pending(id, &session, reply.clone()));
        assert_eq!(finish(wait).await, Ok(reply));
        assert!(!pending(&proxy, id));
        assert_eq!(writer.queued_count(), 0, "all staged frames must drain");
    }
}

#[tokio::test(start_paused = true)]
async fn mik_7388_channel_outer_timeout_cleans_a_delivered_waiter() {
    let (mux, proxy, session) = fixture();
    let mut writer = mux.register_request_writer(&session).expect("writer");
    let id = "roots-outer-timeout";
    let owned = Arc::clone(&proxy);
    let origin = session.clone();
    let wait = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_millis(100),
            owned.send_request(
                &origin,
                id,
                "roots/list",
                None,
                Arc::new(DeliveryProgress::default()),
            ),
        )
        .await
    });
    let frame = receive(&mut writer).await;
    assert!(
        pending(&proxy, id),
        "timeout must act on a real registered exchange"
    );
    assert!(frame.delivery.mark_handed_off());
    tokio::time::advance(Duration::from_millis(101)).await;
    assert!(
        tokio::time::timeout(LIMIT, wait)
            .await
            .expect("outer test bound")
            .expect("no task panic")
            .is_err()
    );
    assert!(
        !pending(&proxy, id),
        "outer future drop must remove the waiter"
    );
    assert!(
        !proxy.resolve_pending(
            id,
            &session,
            json!({"jsonrpc":"2.0","id":id,"result":{"roots":[]}})
        ),
        "a timed-out waiter cannot consume a late valid reply"
    );
}

#[derive(Default)]
struct RetryLog(std::sync::Mutex<Vec<Value>>);

#[async_trait::async_trait]
impl BackendInvoker for RetryLog {
    async fn invoke(&self, retry_params: Value) -> Value {
        self.0.lock().expect("retry log").push(retry_params);
        json!({"content":[{"type":"text","text":"done"}]})
    }
}

struct NoObserver;

impl BridgeObserver for NoObserver {
    fn record(&self, _record: BridgeRecord) {}
}

fn start_bridge(
    proxy: &Arc<ProxyManager>,
    session: &str,
    retries: &Arc<RetryLog>,
) -> tokio::task::JoinHandle<Result<Value, BridgeError>> {
    let proxy = Arc::clone(proxy);
    let session = session.to_string();
    let retries = Arc::clone(retries);
    tokio::spawn(async move {
        let first = crate::protocol::mrtr::InputRequired {
            requests: [("question".to_string(), json!({"method":"roots/list"}))]
                .into_iter()
                .collect(),
            request_state: Some("backend-opaque-state".to_string()),
        };
        let declared = crate::protocol::meta::classify_request(
            Some(&json!({"_meta":{
                crate::protocol::meta::KEY_PROTOCOL_VERSION:"2026-07-28",
                crate::protocol::meta::KEY_CLIENT_CAPABILITIES:{"roots":{}}
            }})),
            None,
        )
        .declared_capabilities();
        InputBridge {
            channel: proxy.as_ref(),
            backend: retries.as_ref(),
            observer: &NoObserver,
            bounds: BridgeBounds {
                per_prompt: BRIDGE_PROMPT_TIMEOUT,
                ..BridgeBounds::DEFAULT
            },
        }
        .run(&session, declared, None, &first)
        .await
    })
}

#[tokio::test(start_paused = true)]
async fn mik_7388_channel_pre_handoff_expiry_does_not_retry_backend() {
    let (mux, proxy, session) = fixture();
    let mut writer = mux.register_request_writer(&session).expect("writer");
    let retries = Arc::new(RetryLog::default());
    let wait = start_bridge(&proxy, &session, &retries);
    let frame = receive(&mut writer).await;
    let request: Value = serde_json::from_str(&frame.json).expect("valid request");
    let id = request["id"].as_str().expect("bridge ID");
    assert!(
        pending(&proxy, id),
        "precondition: enqueued but never handed off"
    );
    tokio::time::advance(BRIDGE_PROMPT_TIMEOUT + Duration::from_millis(1)).await;
    let result = tokio::time::timeout(LIMIT, wait)
        .await
        .expect("outer test bound")
        .expect("no task panic");
    assert!(
        matches!(
            result,
            Err(BridgeError::Delivery {
                error: DeliveryError::NoSession,
                ..
            })
        ),
        "pre-handoff timeout is non-delivery, not unanswered consent: {result:?}"
    );
    assert!(retries.0.lock().expect("retry log").is_empty());
    assert!(!pending(&proxy, id));
    assert!(
        !frame.delivery.mark_handed_off(),
        "expired queued work cannot appear later"
    );
}

#[tokio::test(start_paused = true)]
async fn mik_7388_channel_handed_off_live_timeout_retries_with_missing_answer() {
    let (mux, proxy, session) = fixture();
    let mut writer = mux.register_request_writer(&session).expect("writer");
    let retries = Arc::new(RetryLog::default());
    let wait = start_bridge(&proxy, &session, &retries);
    let frame = receive(&mut writer).await;
    let request: Value = serde_json::from_str(&frame.json).expect("valid request");
    let id = request["id"].as_str().expect("bridge ID");
    assert!(pending(&proxy, id));
    assert!(frame.delivery.mark_handed_off());
    tokio::time::advance(BRIDGE_PROMPT_TIMEOUT + Duration::from_millis(1)).await;
    let result = tokio::time::timeout(LIMIT, wait)
        .await
        .expect("outer test bound")
        .expect("no task panic");
    assert_eq!(
        result,
        Ok(json!({"content":[{"type":"text","text":"done"}]}))
    );
    let calls = retries.0.lock().expect("retry log");
    assert_eq!(
        calls.len(),
        1,
        "a live unanswered prompt retries the backend exactly once"
    );
    assert!(
        calls[0].get("inputResponses").is_none(),
        "an unanswered-only round omits the response member, including an empty map"
    );
    assert_eq!(calls[0]["requestState"], "backend-opaque-state");
    assert!(!pending(&proxy, id));
}
