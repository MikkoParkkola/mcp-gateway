// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An ended subscription tells its subscriber: one signed notice to its
//! callback, naming it by its public handle. Owner
//! unsubscribe sends none. These rows end the row through the store's
//! carrier directly; the revoke paths that reach it have rows of their own.

use super::*;

const KEY_SECRET: &str = "lifecycle-revoke-notice-key";

/// An API-key caller: the one credential whose subscription may have no expiry.
fn key_caller(principal: &str) -> Caller {
    let mut caller = caller(principal);
    caller.credential.kind = crate::security::audit::CredentialKind::ApiKey;
    caller.credential.principal = principal.to_owned();
    caller.credential.api_key = Some(super::super::records::ApiKeyRef {
        name: "k".to_owned(),
        principal: crate::gateway::auth::principal_of(KEY_SECRET)
            .storage_form()
            .to_owned(),
        digest_tag: Some(crate::gateway::auth::secret_tag(KEY_SECRET)),
    });
    caller
}

/// A started hub with a real audit log, the receiver `rx`, and one API-key
/// subscription of `p1` to the probe source with `ttlMs: null` under
/// `allow_no_expiry`: it never expires and never refreshes.
async fn subscriber(
    rx: Receiver,
) -> (Arc<EventsHub>, Arc<Probe>, Receiver, Arc<tempfile::TempDir>) {
    let dir = crate::test_dir_keep::kept_tempdir();
    let config = crate::config::EventsConfig {
        callback_allow_private: vec!["127.0.0.0/8".to_owned()],
        retry_base: std::time::Duration::from_millis(200),
        allow_no_expiry: true,
        ..crate::config::EventsConfig::default()
    };
    let hub = EventsHub::open_trusting(&config, dir.path(), rx.root.clone()).expect("hub");
    hub.keep_test_dir(Arc::clone(&dir));
    let probe = Arc::new(Probe::default());
    hub.register_source(probe.clone());
    seed_verified_at(&hub, &config, "p1", &rx.url);
    let log = Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(
            crate::security::TransparencyLogConfig {
                enabled: true,
                path: dir
                    .path()
                    .join("audit.jsonl")
                    .to_string_lossy()
                    .into_owned(),
                ..crate::security::TransparencyLogConfig::default()
            },
        ))
        .expect("audit log"),
    );
    hub.start(Services {
        audit: Some(log),
        ..services()
    });
    hub.subscribe(&key_caller("p1"), Some(&no_expiry_params(&rx)))
        .await
        .expect("subscribe");
    let row = hub
        .store
        .subscriptions()
        .into_iter()
        .find(|s| s.name == NAME)
        .expect("premise: the subscription row exists");
    assert!(row.expires_at.is_none(), "premise: a row with no expiry");
    assert!(row.api_key.is_some(), "premise: an API-key row");
    assert!(hub.reconcile_catalogue(fanout::CatalogueScan::Complete));
    (hub, probe, rx, dir)
}

/// `p1`'s subscribe parameters for the probe event, with no expiry.
fn no_expiry_params(rx: &Receiver) -> Value {
    json!({"name": NAME, "arguments": {"k": "v"}, "ttlMs": null, "delivery": {
        "mode": "webhook", "url": rx.url, "secret": whsec()}})
}

async fn no_expiry_subscriber() -> (Arc<EventsHub>, Arc<Probe>, Receiver, Arc<tempfile::TempDir>) {
    subscriber(receiver().await).await
}

/// Paired control: the owner's own unsubscribe queues no notice at all.
#[tokio::test]
async fn an_owner_unsubscribe_queues_no_ended_notice() {
    let (hub, _probe, rx, dir) = no_expiry_subscriber().await;
    let params = json!({"name": NAME, "arguments": {"k": "v"}, "delivery": {"url": rx.url}});
    hub.unsubscribe(&key_caller("p1"), Some(&params))
        .await
        .expect("unsubscribe");
    assert!(
        hub.store.subscriptions().iter().all(|s| s.name != NAME),
        "premise: the row is gone"
    );
    assert_eq!(
        outbox_files(dir.path()),
        0,
        "nothing queued for the callback"
    );
}

/// The receiver's posts once `count` have arrived, or after the wait bound.
async fn posts_until(rx: &Receiver, count: usize) -> Vec<(axum::http::HeaderMap, Vec<u8>)> {
    for _ in 0..600 {
        if rx.got.lock().len() >= count {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    rx.got.lock().clone()
}

/// One post is the ended notice for `handle` with `code`, carrying no secret.
fn assert_ended_notice(post: &(axum::http::HeaderMap, Vec<u8>), handle: &str, code: i64) -> Value {
    assert_eq!(
        post.0
            .get("x-mcp-subscription-id")
            .and_then(|v| v.to_str().ok()),
        Some(handle),
        "named by its public handle"
    );
    let body: Value = serde_json::from_slice(&post.1).expect("json body");
    assert_eq!(body["name"], "subscription.ended");
    assert_eq!(body["data"]["code"], code);
    let text = body.to_string();
    assert!(
        !text.contains("whsec_") && !text.contains(KEY_SECRET),
        "no secret: {text}"
    );
    body
}

/// A source offering the reserved name is refused, so only the gateway can sign one.
/// Its own kind: the hub keys sources by kind, so sharing `Probe`'s would replace it.
/// `reserved` picks what it offers: the reserved name, or an ordinary one
/// it can switch away from after registering.
struct Reserved {
    reserved: std::sync::atomic::AtomicBool,
}

impl Reserved {
    fn offering_reserved(now: bool) -> Arc<Self> {
        Arc::new(Self {
            reserved: std::sync::atomic::AtomicBool::new(now),
        })
    }
}

#[async_trait::async_trait]
impl EventSource for Reserved {
    fn kind(&self) -> SourceKind {
        SourceKind::Schedule
    }
    fn descriptors(&self) -> Vec<EventDescriptor> {
        let name = if self.reserved.load(Ordering::SeqCst) {
            "subscription.ended"
        } else {
            "reserved.later"
        };
        vec![EventDescriptor {
            name: name.into(),
            description: "a source claiming the reserved name".into(),
            input_schema: json!({"type": "object"}),
            payload_schema: json!({"type": "object"}),
            scope: Visibility::Owner,
            kind: SourceKind::Schedule,
        }]
    }
    fn matches(
        &self,
        _: &str,
        _: &Value,
        _: &SourceEvent,
        _: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        true
    }
    async fn authorize(&self, _: &str, _: &str, _: &Value) -> Result<(), RpcError> {
        Ok(())
    }
    async fn on_first_subscriber(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &Value,
    ) -> Result<(), RpcError> {
        Ok(())
    }
    async fn on_last_subscriber(&self, _: &str) {}
}

#[tokio::test]
async fn a_source_offering_the_reserved_name_is_not_catalogued() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("hub");
    hub.keep_test_dir(Arc::clone(&dir));
    hub.register_source(Arc::new(Probe::default()));
    hub.register_source(Reserved::offering_reserved(true));
    assert!(
        hub.source(SourceKind::Schedule).is_none(),
        "the source offering the reserved name is not registered"
    );
    let names: Vec<String> = hub.catalogue().iter().map(|d| d.name.clone()).collect();
    assert!(
        names.iter().any(|n| n == NAME),
        "premise: an ordinary source is catalogued: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n == "subscription.ended"),
        "the reserved name is refused: {names:?}"
    );
}

/// CARRIER.4: a source whose offer turns to the reserved name after it
/// registered is not catalogued with it, and no lookup finds it.
#[tokio::test]
async fn a_source_that_turns_to_the_reserved_name_is_not_offered() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("hub");
    hub.keep_test_dir(Arc::clone(&dir));
    let shifty = Reserved::offering_reserved(false);
    hub.register_source(shifty.clone());
    let names = || -> Vec<String> { hub.catalogue().iter().map(|d| d.name.clone()).collect() };
    assert!(
        hub.source(SourceKind::Schedule).is_some() && names().iter().any(|n| n == "reserved.later"),
        "premise: registered with an ordinary name: {:?}",
        names()
    );
    shifty.reserved.store(true, Ordering::SeqCst);
    assert!(
        !names().iter().any(|n| n == "subscription.ended"),
        "the reserved name is not catalogued: {:?}",
        names()
    );
    assert!(
        hub.source_offering("subscription.ended").is_none(),
        "no source is found for the reserved name"
    );
}

/// CARRIER.4 (R1 at carrier level): a notice goes out though the source now
/// refuses the ended row: an event's access and source checks never judge
/// a notice, whose row has already ended.
#[tokio::test]
async fn a_notice_goes_out_though_the_source_refuses_the_ended_row() {
    let (hub, probe, rx, _dir) = no_expiry_subscriber().await;
    probe.deny.store(true, Ordering::SeqCst);
    let handle = end_now(&hub).await;
    let posts = posts_until(&rx, 1).await;
    assert_eq!(posts.len(), 1, "one notice to the callback");
    assert_ended_notice(&posts[0], &handle, -32012);
}

/// End `p1`'s probe row through the carrier with code -32012, as a revoke
/// path will, and wake the worker; its handle.
async fn end_now(hub: &Arc<EventsHub>) -> String {
    let row = hub
        .store
        .subscriptions()
        .into_iter()
        .find(|s| s.name == NAME)
        .expect("premise: the row is live before it ends");
    let handle = hub.handle(&row.id).expect("handle");
    let stamp = super::super::outbox::EndedStamp {
        at: chrono::Utc::now(),
        code: -32012,
        event_id: "evt_ended_carrier".to_owned(),
    };
    let tail = super::super::tail_policy(&hub.config);
    let ended = hub
        .store
        .end_where(&row.id, stamp, tail, |r| r.incarnation == row.incarnation)
        .expect("io");
    assert!(ended, "premise: the row ended");
    hub.runtime.wake.notify_one();
    handle
}

/// Polls until the store holds no ended row, or the wait bound.
async fn ended_rows_settle(hub: &EventsHub) -> usize {
    for _ in 0..600 {
        if hub.store.ended_rows().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    hub.store.ended_rows().len()
}

/// CARRIER.2 (R9): a refused notice is retried under the same `webhook-id`,
/// and once delivered its ended row and file are gone.
#[tokio::test]
async fn a_refused_notice_is_retried_under_the_same_webhook_id_then_its_row_goes() {
    let rx = receiver_answering(Arc::new(|n| {
        if n == 0 {
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        } else {
            axum::http::StatusCode::OK
        }
    }))
    .await;
    let (hub, _probe, rx, _dir) = subscriber(rx).await;
    let handle = end_now(&hub).await;
    let posts = posts_until(&rx, 2).await;
    assert_eq!(posts.len(), 2, "a refused attempt, then a retry");
    for post in &posts {
        assert_ended_notice(post, &handle, -32012);
    }
    let id = |p: &(axum::http::HeaderMap, Vec<u8>)| p.0.get("webhook-id").cloned();
    assert_eq!(
        id(&posts[0]).as_ref().and_then(|v| v.to_str().ok()),
        Some("evt_ended_carrier"),
        "the stored event id is the webhook-id"
    );
    assert_eq!(
        id(&posts[0]),
        id(&posts[1]),
        "the retry keeps the webhook-id"
    );
    assert_eq!(
        ended_rows_settle(&hub).await,
        0,
        "delivered: the ended row is gone"
    );
    assert!(
        crate::events::records::committed_records(hub.store.ended_dir()).is_empty(),
        "and its file"
    );
}

/// CARRIER.2 (R23): a notice pending beside a re-grant's event: both arrive.
#[tokio::test]
async fn a_notice_and_a_regrants_event_both_arrive() {
    let (hub, _probe, rx, _dir) = no_expiry_subscriber().await;
    let id = hub
        .store
        .subscriptions()
        .into_iter()
        .find(|s| s.name == NAME)
        .expect("row")
        .id;
    let handle = end_now(&hub).await;
    // A plain caller's re-grant under the same id: an API key outside this
    // fixture's live config would be refused at the event's access check.
    subscribe_at(&hub, "p1", &rx.url).await;
    assert!(
        hub.store.get(&id).is_some(),
        "premise: the re-grant took the ended row's id"
    );
    hub.emit(event());
    let posts = posts_until(&rx, 2).await;
    let mut names: Vec<String> = posts
        .iter()
        .map(|(_, body)| {
            let body: Value = serde_json::from_slice(body).expect("json");
            body["name"].as_str().unwrap_or_default().to_owned()
        })
        .collect();
    names.sort();
    let mut want = vec![NAME.to_owned(), "subscription.ended".to_owned()];
    want.sort();
    assert_eq!(names, want, "the notice and the event, once each");
    let notice = posts
        .iter()
        .find(|(_, body)| String::from_utf8_lossy(body).contains("subscription.ended"))
        .expect("the notice");
    assert_ended_notice(notice, &handle, -32012);
}

/// CARRIER.3 (R14b): an unsubscribe while the notice's POST is under way
/// answers only once that attempt has settled: the post is in by then.
#[tokio::test]
async fn an_unsubscribe_answers_after_a_notice_in_flight() {
    let (hub, _probe, rx, dir) = no_expiry_subscriber().await;
    let (reached, release) = hub.before_send.arm();
    end_now(&hub).await;
    crate::test_pause::within("the notice reaching its send", reached.notified()).await;
    let params = json!({"name": NAME, "arguments": {"k": "v"}, "delivery": {"url": rx.url}});
    let answer = async {
        hub.unsubscribe(&key_caller("p1"), Some(&params))
            .await
            .expect("unsubscribe");
        rx.got.lock().len()
    };
    let drive = async {
        // The unsubscribe has committed: the ended row is gone.
        for _ in 0..600 {
            if hub.store.ended_rows().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        release.notify_one();
    };
    let (posted_at_answer, ()) =
        crate::test_pause::within("the unsubscribe", async { tokio::join!(answer, drive) }).await;
    assert_eq!(
        posted_at_answer, 1,
        "the attempt in flight settled before the unsubscribe answered"
    );
    assert_eq!(outbox_files(dir.path()), 0, "nothing left to send");
}

/// CARRIER.4 (R16b): a source event named `subscription.ended` is dropped at
/// fan-out, even for a row that names it.
#[tokio::test]
async fn a_source_event_with_the_reserved_name_is_dropped_at_fan_out() {
    let (hub, _probe, _rx, dir) = no_expiry_subscriber().await;
    let mut row = hub
        .store
        .subscriptions()
        .into_iter()
        .find(|s| s.name == NAME)
        .expect("row");
    row.id = "sub_reserved".to_owned();
    row.name = "subscription.ended".to_owned();
    let now = chrono::Utc::now();
    let caps = crate::events::store::Caps {
        per_principal: 10,
        global: 10,
    };
    hub.store
        .admit(
            row,
            true,
            caps,
            chrono::Duration::zero(),
            now,
            super::super::tail_policy(&hub.config),
        )
        .expect("io")
        .expect("premise: a row naming the reserved event");
    let reserved = SourceEvent {
        name: "subscription.ended".into(),
        ..event()
    };
    hub.fan_out(&services(), &reserved).await;
    assert_eq!(outbox_files(dir.path()), 0, "nothing queued for it");
}
