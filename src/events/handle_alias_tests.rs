// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8697 slice 3 (design §13, §13.6, §14.1-§14.3): the client-facing
//! subscription handle is the keyed alias, never the stored id, and the events
//! store is bound to the record key it was written under.
//!
//! The fixtures are copies of `lifecycle_tests`' private ones: a sibling test
//! module cannot reach them, and this file adds no production surface.

#![cfg_attr(
    test,
    allow(
        clippy::disallowed_methods,
        reason = "test code reads the host clock (MIK-8202 AC.14)"
    )
)]
use serde_json::{Value, json};

use super::fanout::SourceEvent;
use super::records::{Credential, Subscription};
use super::rpc::{Caller, subscription_id};
use super::types::{EventDescriptor, SourceKind, Visibility};
use super::*;
use crate::gateway::record_principal::{RecordPrincipalKey, subscription_alias, test_record_key};

#[path = "handle_alias_store_tests.rs"]
mod store_binding;

const NAME: &str = "probe.alias";

/// Another key than [`test_record_key`]: a rotation.
const OTHER_KEY: &str = "another-record-key-for-rotation-0123456789abcdef";

/// A source written against the trait only, matching every event.
struct Probe;

#[async_trait::async_trait]
impl EventSource for Probe {
    fn kind(&self) -> SourceKind {
        SourceKind::RestWatch
    }
    fn descriptors(&self) -> Vec<EventDescriptor> {
        vec![EventDescriptor {
            name: NAME.into(),
            description: "alias test source".into(),
            input_schema: json!({"type": "object", "properties": {"k": {"type": "string"}}}),
            payload_schema: json!({"type": "object"}),
            scope: Visibility::Owner,
            kind: SourceKind::RestWatch,
        }]
    }
    fn matches(
        &self,
        _p: &str,
        _a: &Value,
        _e: &SourceEvent,
        _n: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        true
    }
    async fn authorize(&self, _p: &str, _n: &str, _a: &Value) -> Result<(), RpcError> {
        Ok(())
    }
    async fn on_first_subscriber(
        &self,
        _k: &str,
        _p: &str,
        _n: &str,
        _a: &Value,
    ) -> Result<(), RpcError> {
        Ok(())
    }
    async fn on_last_subscriber(&self, _key: &str) {}
}

fn caller(principal: &str) -> Caller {
    Caller {
        principal: Some(principal.to_owned()),
        credential: Credential {
            kind: crate::security::audit::CredentialKind::None,
            principal: String::new(),
            api_key: None,
            expires_at: None,
            binding: None,
        },
        visible_backends: std::collections::HashSet::new(),
        admin: false,
        identity: None,
        read_key: None,
    }
}

fn whsec() -> String {
    use base64::Engine as _;
    format!(
        "whsec_{}",
        base64::engine::general_purpose::STANDARD.encode([7_u8; 32])
    )
}

fn services_with(key: RecordPrincipalKey) -> Services {
    Services {
        live: Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
        #[cfg(feature = "firewall")]
        firewall: None,
        audit: None,
        provenance: None,
        public_provenance: None,
        #[cfg(feature = "cost-governance")]
        budget: None,
        credentials: LiveCredentials::default(),
        record_key: Some(Arc::new(key)),
    }
}

fn services() -> Services {
    services_with(test_record_key())
}

fn other_key() -> RecordPrincipalKey {
    RecordPrincipalKey::from_text(OTHER_KEY).expect("long enough")
}

fn url(principal: &str) -> String {
    format!("https://{principal}.example/cb")
}

fn arguments() -> Value {
    json!({"k": "v"})
}

/// The stored id of `principal`'s subscription to [`NAME`] at `callback`.
fn stored(principal: &str, callback: &str) -> String {
    subscription_id(principal, callback, NAME, &arguments())
}

/// The handle a subscriber must see for that subscription under `key`.
fn alias(key: &RecordPrincipalKey, principal: &str, callback: &str) -> String {
    subscription_alias(key, &stored(principal, callback))
}

/// Seed a verified `(principal, callback)` through a row of another event
/// type, so the subscribe under test needs no callback POST.
fn seed_verified_at(
    hub: &EventsHub,
    config: &crate::config::EventsConfig,
    principal: &str,
    callback: &str,
) {
    let row: Subscription = serde_json::from_value(json!({
        "v": 1, "id": format!("seed_{principal}"), "principal": principal,
        "url": callback, "name": "seed", "arguments": {}, "secret": "whsec_x",
        "previous_secret": null, "previous_until": null,
        "granted_at": chrono::Utc::now(), "expires_at": null, "active": true,
        "failed_since": null, "last_delivery_at": null, "last_error": null
    }))
    .expect("row");
    let caps = store::Caps {
        per_principal: 10,
        global: 10,
    };
    hub.store
        .admit(
            row,
            true,
            caps,
            chrono::Duration::zero(),
            chrono::Utc::now(),
            tail_policy(config),
        )
        .expect("io")
        .expect("admitted");
}

fn subscribe_params(callback: &str) -> Value {
    json!({"name": NAME, "arguments": arguments(), "delivery": {
        "mode": "webhook", "url": callback, "secret": whsec()}})
}

async fn subscribe_at(hub: &Arc<EventsHub>, principal: &str, callback: &str) -> Value {
    hub.subscribe(&caller(principal), Some(&subscribe_params(callback)))
        .await
        .unwrap_or_else(|e| panic!("subscribe {principal}: {e:?}"))
}

fn unsubscribe_params(callback: &str, id: Option<&str>) -> Value {
    let mut params = json!({"name": NAME, "arguments": arguments(), "delivery": {"url": callback}});
    if let Some(id) = id {
        params["id"] = json!(id);
    }
    params
}

/// The rows of [`NAME`] in the store (the seed rows excluded).
fn rows(hub: &EventsHub) -> Vec<Subscription> {
    hub.store
        .subscriptions()
        .into_iter()
        .filter(|s| s.name == NAME)
        .collect()
}

/// A hub on `dir` with the probe source registered and `(principal, callback)`
/// verified.
fn hub_at(
    dir: &std::path::Path,
    config: &crate::config::EventsConfig,
    principal: &str,
    callback: &str,
) -> Arc<EventsHub> {
    let hub = EventsHub::open(config, dir).expect("hub");
    hub.register_source(Arc::new(Probe));
    seed_verified_at(&hub, config, principal, callback);
    hub
}

fn event(upstream_id: &str) -> SourceEvent {
    SourceEvent {
        kind: SourceKind::RestWatch,
        name: NAME.into(),
        backend: "probe".into(),
        scope: Visibility::Owner,
        owner: None,
        upstream_id: upstream_id.into(),
        occurred_at: chrono::Utc::now(),
        data: json!({}),
        lifecycle_key: None,
    }
}

/// The committed outbox records under `dir`, as JSON.
fn outbox(dir: &std::path::Path) -> Vec<Value> {
    std::fs::read_dir(dir.join("outbox")).map_or_else(
        |_| Vec::new(),
        |entries| {
            entries
                .filter_map(Result::ok)
                .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
                .filter_map(|e| std::fs::read_to_string(e.path()).ok())
                .filter_map(|t| serde_json::from_str(&t).ok())
                .collect()
        },
    )
}

// H1: the subscribe answer's handle is the keyed alias, never the stored id.
#[tokio::test]
async fn h1_the_subscribe_answer_carries_the_alias_not_the_stored_id() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    let hub = hub_at(dir.path(), &config, "p", &url("p"));
    hub.runtime.services.set(Arc::new(services())).ok();
    let answer = subscribe_at(&hub, "p", &url("p")).await;
    assert_ne!(
        answer["id"],
        json!(stored("p", &url("p"))),
        "the stored id leaked: {answer}"
    );
    assert_eq!(
        answer["id"],
        json!(alias(&test_record_key(), "p", &url("p"))),
        "{answer}"
    );
    let row_ids: Vec<String> = rows(&hub).into_iter().map(|s| s.id).collect();
    assert_eq!(
        row_ids,
        [stored("p", &url("p"))],
        "the store keeps the stored id"
    );
}

// H2: a repeat of the same subscribe answers the same alias, one row.
#[tokio::test]
async fn h2_an_idempotent_subscribe_answers_the_same_alias() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    let hub = hub_at(dir.path(), &config, "p", &url("p"));
    hub.runtime.services.set(Arc::new(services())).ok();
    let first = subscribe_at(&hub, "p", &url("p")).await;
    let second = subscribe_at(&hub, "p", &url("p")).await;
    let expected = json!(alias(&test_record_key(), "p", &url("p")));
    assert_eq!(
        (&first["id"], &second["id"]),
        (&expected, &expected),
        "{first} / {second}"
    );
    assert_eq!(rows(&hub).len(), 1, "one subscription row");
}

// H4: a newly fanned-out event's eventId derives from the alias (fanout.rs:49).
#[tokio::test]
async fn h4_a_new_event_id_derives_from_the_alias() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    let hub = hub_at(dir.path(), &config, "p", &url("p"));
    hub.runtime.services.set(Arc::new(services())).ok();
    subscribe_at(&hub, "p", &url("p")).await;
    hub.fan_out(&services(), &event("up-1")).await;
    let records = outbox(dir.path());
    assert_eq!(records.len(), 1, "one delivery enqueued");
    let alias = alias(&test_record_key(), "p", &url("p"));
    assert_eq!(
        records[0]["event_id"],
        json!(fanout::event_id(SourceKind::RestWatch, "up-1", &alias)),
        "eventId from the alias, not the stored id"
    );
}

// H6: no client-visible field of the subscribe answer holds a stored id.
#[tokio::test]
async fn h6_the_subscribe_answer_holds_no_stored_id() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    let hub = hub_at(dir.path(), &config, "p", &url("p"));
    hub.runtime.services.set(Arc::new(services())).ok();
    let answer = subscribe_at(&hub, "p", &url("p")).await;
    assert!(
        !answer.to_string().contains("sub_"),
        "a stored id in the answer: {answer}"
    );
}

// H8 (lead): the handle is keyed before anything is written. A hub with no
// services cannot key it, so the subscribe is refused and no row of the event
// is written. Production never serves an unstarted hub (the hub reaches
// MetaMcp only after `start`, events_wiring.rs); this pins the order.
#[tokio::test]
async fn h8_a_subscribe_the_hub_cannot_key_writes_nothing() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    let hub = hub_at(dir.path(), &config, "p", &url("p"));
    let params = subscribe_params(&url("p"));
    let refused = hub.subscribe(&caller("p"), Some(&params)).await;
    assert!(refused.is_err(), "an unkeyable subscribe is refused");
    assert!(rows(&hub).is_empty(), "no row was committed");
}

// U1 (characterization, §14.1): the owner's unsubscribe recomputes the row
// from its own arguments and removes it.
#[tokio::test]
async fn u1_the_owners_unsubscribe_removes_its_row() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    let hub = hub_at(dir.path(), &config, "p", &url("p"));
    hub.runtime.services.set(Arc::new(services())).ok();
    subscribe_at(&hub, "p", &url("p")).await;
    let answer = hub
        .unsubscribe(&caller("p"), Some(&unsubscribe_params(&url("p"), None)))
        .await;
    assert_eq!(answer.expect("unsubscribe"), json!({}));
    assert!(rows(&hub).is_empty(), "the owner's row is gone");
}

// U2 (characterization, §14.1): another caller with identical arguments
// recomputes another id, finds nothing, and the owner's row stays.
#[tokio::test]
async fn u2_another_callers_unsubscribe_leaves_the_owners_row() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    let hub = hub_at(dir.path(), &config, "p", &url("p"));
    hub.runtime.services.set(Arc::new(services())).ok();
    subscribe_at(&hub, "p", &url("p")).await;
    let answer = hub
        .unsubscribe(&caller("q"), Some(&unsubscribe_params(&url("p"), None)))
        .await;
    assert_eq!(answer.expect("an absent row is not an error"), json!({}));
    assert_eq!(
        rows(&hub).len(),
        1,
        "the owner's row survives another caller"
    );
}

// U3 (characterization, §14.1): an `id` in the params is never read. A wrong
// id does not stop the owner; the owner's alias or stored id does not let
// another caller in.
#[tokio::test]
async fn u3_an_id_in_unsubscribe_params_is_ignored() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    let hub = hub_at(dir.path(), &config, "p", &url("p"));
    hub.runtime.services.set(Arc::new(services())).ok();
    subscribe_at(&hub, "p", &url("p")).await;
    let owner_alias = alias(&test_record_key(), "p", &url("p"));
    for id in [owner_alias.as_str(), &stored("p", &url("p"))] {
        hub.unsubscribe(&caller("q"), Some(&unsubscribe_params(&url("p"), Some(id))))
            .await
            .expect("unsubscribe");
        assert_eq!(
            rows(&hub).len(),
            1,
            "another caller passing {id} removed the owner's row"
        );
    }
    hub.unsubscribe(
        &caller("p"),
        Some(&unsubscribe_params(&url("p"), Some("garbage"))),
    )
    .await
    .expect("unsubscribe");
    assert!(rows(&hub).is_empty(), "a wrong id did not stop the owner");
}

// U4 (characterization, §14.1): refresh is a repeat subscribe. The owner's
// keeps one row; another caller's identical subscribe makes its own.
#[tokio::test]
async fn u4_refresh_by_repeat_subscribe_is_per_caller() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    let hub = hub_at(dir.path(), &config, "p", &url("p"));
    seed_verified_at(&hub, &config, "q", &url("p"));
    hub.runtime.services.set(Arc::new(services())).ok();
    subscribe_at(&hub, "p", &url("p")).await;
    let refreshed = subscribe_at(&hub, "p", &url("p")).await;
    assert!(
        refreshed["deliveryStatus"].is_object(),
        "a repeat subscribe is a refresh: {refreshed}"
    );
    assert_eq!(rows(&hub).len(), 1, "the owner's refresh keeps one row");
    subscribe_at(&hub, "q", &url("p")).await;
    let ids: std::collections::HashSet<String> = rows(&hub).into_iter().map(|s| s.id).collect();
    assert_eq!(
        ids.len(),
        2,
        "another caller's subscribe is its own row: {ids:?}"
    );
}

// U5 (§13.2): after a key change the owner re-learns the handle by a repeat
// subscribe, and unsubscribe still works (it never needed the handle).
#[tokio::test]
async fn u5_after_a_key_change_a_repeat_subscribe_answers_the_new_alias() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    let hub = hub_at(dir.path(), &config, "p", &url("p"));
    hub.runtime.services.set(Arc::new(services())).ok();
    subscribe_at(&hub, "p", &url("p")).await;
    drop(hub);
    let hub = EventsHub::open(&config, dir.path()).expect("reopen");
    hub.register_source(Arc::new(Probe));
    hub.runtime
        .services
        .set(Arc::new(services_with(other_key())))
        .ok();
    let answer = subscribe_at(&hub, "p", &url("p")).await;
    assert_eq!(
        answer["id"],
        json!(alias(&other_key(), "p", &url("p"))),
        "{answer}"
    );
    hub.unsubscribe(&caller("p"), Some(&unsubscribe_params(&url("p"), None)))
        .await
        .expect("unsubscribe");
    assert!(
        rows(&hub).is_empty(),
        "unsubscribe works after the key change"
    );
}

/// The posts a receiver has received: the headers and body of each.
type Posts = Arc<parking_lot::Mutex<Vec<(axum::http::HeaderMap, Vec<u8>)>>>;

/// One HTTPS receiver with its own CA (a copy of `lifecycle_tests::receiver`).
/// It answers 200 with no body, so a verification challenge to it fails.
struct Receiver {
    url: String,
    root: reqwest::Certificate,
    got: Posts,
}

async fn receiver() -> Receiver {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let ca = crate::mtls::CertGenerator::init_ca(&crate::mtls::CaParams {
        cn: "events handle alias test CA",
        validity_days: 1,
    })
    .expect("CA");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("non-blocking");
    let addr = listener.local_addr().expect("addr");
    let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
    let mut leaf = rcgen::CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "127.0.0.1");
    leaf.distinguished_name = dn;
    leaf.subject_alt_names = vec![rcgen::SanType::IpAddress(addr.ip())];
    let ca_key = rcgen::KeyPair::from_pem(&ca.key_pem).expect("CA key");
    let issuer = rcgen::Issuer::from_ca_cert_pem(&ca.cert_pem, ca_key).expect("issuer");
    let leaf_pem = leaf.signed_by(&leaf_key, &issuer).expect("leaf").pem();
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
        leaf_pem.into_bytes(),
        leaf_key.serialize_pem().into_bytes(),
    )
    .await
    .expect("tls");
    let got = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let sink = Arc::clone(&got);
    let app = axum::Router::new().route(
        "/hook",
        axum::routing::post(
            move |headers: axum::http::HeaderMap, body: axum::body::Bytes| {
                let sink = Arc::clone(&sink);
                async move {
                    sink.lock().push((headers, body.to_vec()));
                    axum::http::StatusCode::OK
                }
            },
        ),
    );
    tokio::spawn(async move {
        let _ = axum_server::from_tcp_rustls(listener, tls)
            .expect("listener")
            .serve(app.into_make_service())
            .await;
    });
    Receiver {
        url: format!("https://{addr}/hook"),
        root: reqwest::Certificate::from_pem(ca.cert_pem.as_bytes()).expect("root"),
        got,
    }
}

/// [`services`] with a real transparency log in `dir`: delivery needs the
/// audit trail it promises before it sends (MIK-7802).
fn audited(dir: &std::path::Path) -> Services {
    let log = Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(
            crate::security::TransparencyLogConfig {
                enabled: true,
                path: dir.join("audit.jsonl").to_string_lossy().into_owned(),
                ..crate::security::TransparencyLogConfig::default()
            },
        ))
        .expect("audit log"),
    );
    Services {
        audit: Some(log),
        ..services()
    }
}

/// Start delivery on `hub` as the gateway wiring does: start, then the startup
/// reconcile, before which nothing is sent (MIK-8076).
fn start_delivery(hub: &Arc<EventsHub>, dir: &std::path::Path) {
    hub.start(audited(dir));
    assert!(hub.reconcile_catalogue(fanout::CatalogueScan::Complete));
}

fn delivery_config() -> crate::config::EventsConfig {
    crate::config::EventsConfig {
        callback_allow_private: vec!["127.0.0.0/8".to_owned()],
        retry_base: std::time::Duration::from_millis(200),
        ..crate::config::EventsConfig::default()
    }
}

/// Wait up to 30 s for the receiver's first post; its headers.
async fn first_post(rx: &Receiver) -> axum::http::HeaderMap {
    for _ in 0..600 {
        if let Some((headers, _)) = rx.got.lock().first().cloned() {
            return headers;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("no post reached the receiver");
}

fn header(headers: &axum::http::HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

// H3: a delivery's x-mcp-subscription-id is the alias (client.rs:197 via
// worker.rs:434), computed at send time.
#[tokio::test]
async fn h3_a_delivery_header_carries_the_alias() {
    let rx = receiver().await;
    let dir = tempfile::tempdir().expect("dir");
    let config = delivery_config();
    let hub = EventsHub::open_trusting(&config, dir.path(), rx.root.clone()).expect("hub");
    hub.register_source(Arc::new(Probe));
    seed_verified_at(&hub, &config, "p", &rx.url);
    hub.runtime.services.set(Arc::new(services())).ok();
    subscribe_at(&hub, "p", &rx.url).await;
    hub.fan_out(&services(), &event("up-3")).await;
    drop(hub);
    let hub = EventsHub::open_trusting(&config, dir.path(), rx.root.clone()).expect("reopen");
    hub.register_source(Arc::new(Probe));
    start_delivery(&hub, dir.path());
    let headers = first_post(&rx).await;
    let got = header(&headers, "x-mcp-subscription-id");
    assert!(
        !got.starts_with("sub_"),
        "the stored id leaked in the header: {got}"
    );
    assert_eq!(got, alias(&test_record_key(), "p", &rx.url));
}

// H3b: the verification challenge's x-mcp-subscription-id is the alias too
// (rpc.rs:698 -> client.rs:146). The receiver fails the challenge, which is
// fine: the row reads the header of the challenge it got.
#[tokio::test]
async fn h3b_the_verification_challenge_header_carries_the_alias() {
    let rx = receiver().await;
    let dir = tempfile::tempdir().expect("dir");
    let config = delivery_config();
    let hub = EventsHub::open_trusting(&config, dir.path(), rx.root.clone()).expect("hub");
    hub.register_source(Arc::new(Probe));
    hub.runtime.services.set(Arc::new(services())).ok();
    let _ = hub
        .subscribe(&caller("p"), Some(&subscribe_params(&rx.url)))
        .await;
    let headers = first_post(&rx).await;
    let got = header(&headers, "x-mcp-subscription-id");
    assert!(
        !got.starts_with("sub_"),
        "the stored id leaked in the challenge: {got}"
    );
    assert_eq!(got, alias(&test_record_key(), "p", &rx.url));
}

// H5 (§14.2): a record already enqueued keeps its stored eventId on delivery
// (H5a, characterization), while its header alias is computed at send time
// from the stored subscription id (H5b).
#[tokio::test]
async fn h5_an_enqueued_record_keeps_its_event_id_and_gets_the_alias_header() {
    let rx = receiver().await;
    // The pre-upgrade formula: the eventId built from the stored id.
    let legacy = fanout::event_id(SourceKind::RestWatch, "up-5", &stored("p", &rx.url));
    let dir = tempfile::tempdir().expect("dir");
    let config = delivery_config();
    let hub = EventsHub::open_trusting(&config, dir.path(), rx.root.clone()).expect("hub");
    hub.register_source(Arc::new(Probe));
    seed_verified_at(&hub, &config, "p", &rx.url);
    hub.runtime.services.set(Arc::new(services())).ok();
    subscribe_at(&hub, "p", &rx.url).await;
    hub.fan_out(&services(), &event("up-5")).await;
    drop(hub);
    // Stamp the enqueued record with a pre-upgrade eventId.
    let path = std::fs::read_dir(dir.path().join("outbox"))
        .expect("outbox")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            !p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with('.'))
        })
        .expect("one record");
    let mut record: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("json");
    record["event_id"] = json!(legacy);
    std::fs::write(&path, serde_json::to_vec(&record).expect("json")).expect("write");
    let hub = EventsHub::open_trusting(&config, dir.path(), rx.root.clone()).expect("reopen");
    hub.register_source(Arc::new(Probe));
    start_delivery(&hub, dir.path());
    let headers = first_post(&rx).await;
    assert_eq!(
        header(&headers, "webhook-id"),
        legacy,
        "H5a: the stored eventId is kept"
    );
    assert_eq!(
        header(&headers, "x-mcp-subscription-id"),
        alias(&test_record_key(), "p", &rx.url),
        "H5b: the header alias is computed at send time"
    );
}

/// Every `subscription_id` value anywhere in `v`.
fn subscription_ids(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(map) => {
            for (k, v) in map {
                if k == "subscription_id" {
                    out.extend(v.as_str().map(str::to_owned));
                }
                subscription_ids(v, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|v| subscription_ids(v, out)),
        _ => {}
    }
}

// H7 (§13 "records"): the events governance record names the subscription by
// its alias. Today `events.unsubscribe` records the stored id (rpc.rs:731).
#[tokio::test]
async fn h7_governance_records_carry_the_alias_not_the_stored_id() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    let hub = hub_at(dir.path(), &config, "p", &url("p"));
    let audit_path = dir.path().join("audit.jsonl");
    let log = Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(
            crate::security::TransparencyLogConfig {
                enabled: true,
                path: audit_path.to_string_lossy().into_owned(),
                ..crate::security::TransparencyLogConfig::default()
            },
        ))
        .expect("audit log"),
    );
    hub.runtime
        .services
        .set(Arc::new(Services {
            audit: Some(log),
            ..services()
        }))
        .ok();
    subscribe_at(&hub, "p", &url("p")).await;
    hub.unsubscribe(&caller("p"), Some(&unsubscribe_params(&url("p"), None)))
        .await
        .expect("unsubscribe");
    let mut text = String::new();
    for _ in 0..100 {
        text = std::fs::read_to_string(&audit_path).unwrap_or_default();
        if text.contains("events.unsubscribe") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let mut ids = Vec::new();
    for line in text.lines() {
        if let Ok(v) = serde_json::from_str::<Value>(line) {
            subscription_ids(&v, &mut ids);
        }
    }
    assert!(
        !ids.is_empty(),
        "the unsubscribe left a governance record: {text}"
    );
    let expected = alias(&test_record_key(), "p", &url("p"));
    assert!(
        ids.iter().all(|id| *id == expected),
        "records name the alias {expected}: {ids:?}"
    );
    assert!(!text.contains("sub_"), "a stored id in the audit log");
}
