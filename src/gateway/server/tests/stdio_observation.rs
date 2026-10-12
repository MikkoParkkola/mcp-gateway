// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7212 OBS.1: the observation record on the stdio path (moved from `server/mod.rs`, MIK-8144).

use super::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::field::{Field, Visit};
use tracing_subscriber::Registry;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

type Record = HashMap<String, String>;

#[derive(Default)]
struct Fields(Record);

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_string(), value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().to_string(), value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().to_string(), format!("{value:?}"));
    }
}

struct Collector(Arc<Mutex<Vec<Record>>>);

impl<S: tracing::Subscriber> Layer<S> for Collector {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != "mcp_gateway::observed" {
            return;
        }
        let mut fields = Fields::default();
        event.record(&mut fields);
        self.0.lock().expect("collector lock").push(fields.0);
    }
}

/// A field value with any `Debug` quoting removed, so a record written
/// through `record_str` and one written through `record_debug` compare
/// the same. The test is about which revision was observed, not about
/// which `Visit` method the emit site happened to reach.
fn value<'a>(record: &'a Record, name: &str) -> &'a str {
    record.get(name).map_or("", |v| v.trim_matches('"'))
}

/// Runs one request through the real stdio dispatcher under a scoped
/// subscriber and returns every `mcp_gateway::observed` record it
/// emitted.
///
/// Scoped, not global: `with_default` is thread-local and a
/// current-thread runtime polls on this thread, so the capture needs no
/// process-wide lock and cannot collide with a sibling test.
fn records_for(request: &serde_json::Value) -> Vec<Record> {
    records_for_session("stdio-session", std::slice::from_ref(request))
}

/// Runs a SEQUENCE of requests through the real stdio dispatcher on one
/// session id and returns the records emitted by the LAST one.
///
/// A session-scoped fact cannot be observed by a single-request test: the
/// handshake and the request that reports it are two different messages.
/// The session id is a parameter because the revision store is
/// process-wide, so two tests sharing a literal would observe each
/// other's handshake.
fn records_for_session(session_id: &str, requests: &[serde_json::Value]) -> Vec<Record> {
    // `tracing` caches each callsite's interest process-wide. A sibling
    // test that reaches the emit site while no subscriber is installed
    // caches `never`, and every later capture on every thread is then
    // skipped -- measured at 2 failures in 8 full-suite runs before this
    // line existed. A global subscriber that is interested keeps the
    // cached interest at `sometimes`, so the thread-local subscriber
    // below decides each event. Interest, not delivery: this one
    // discards, `with_default` still owns what the test sees.
    crate::test_log_capture::keep_interest_open();

    let captured = Arc::new(Mutex::new(Vec::new()));
    let subscriber = Registry::default()
        .with(Collector(Arc::clone(&captured)))
        .with(tracing::level_filters::LevelFilter::DEBUG);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime");
    tracing::subscriber::with_default(subscriber, || {
        runtime.block_on(async {
            let meta = test_meta_mcp();
            for request in requests {
                // Cleared per message: the caller asked for the LAST
                // request's records, and a test asserting "the record"
                // must not be handed the handshake's as well.
                captured.lock().expect("collector lock").clear();
                Gateway::dispatch_single(
                    &meta,
                    &test_tool_policy(),
                    &test_mtls_policy(),
                    request,
                    session_id,
                )
                .await;
            }
        });
    });
    captured.lock().expect("collector lock").clone()
}

// The capture's own proof. Without it, "no records" is
// indistinguishable from "the collector never saw anything", and the
// red row below would be pinning a broken fixture instead of a real
// gap. Emits the same target the handler emits and asserts it lands.
#[test]
fn the_capture_sees_a_record_emitted_under_it() {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let subscriber = Registry::default()
        .with(Collector(Arc::clone(&captured)))
        .with(tracing::level_filters::LevelFilter::DEBUG);
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(
            target: "mcp_gateway::observed",
            protocol_revision = "2026-07-28",
            revision_source = "_meta",
            "protocol revision observed"
        );
    });

    let records = captured.lock().expect("collector lock").clone();
    let record = records
        .iter()
        .find(|record| record.contains_key("protocol_revision"))
        .expect("the collector must see a record emitted in its scope");
    assert_eq!(value(record, "protocol_revision"), "2026-07-28");
    assert_eq!(value(record, "revision_source"), "_meta");
}

// OBS.1, row 1. A modern stdio request carries its revision in `_meta`,
// so the record must name both the revision and the place it came from.
// `revision_source` has four values -- `_meta`, `header`, `handshake`,
// `none` (`protocol::meta::classify_and_observe`) -- and stdio has no
// headers, so `_meta` is the only one a well-formed modern stdio
// request can produce.
#[test]
fn ac_obs_1_stdio_records_the_revision_and_that_meta_carried_it() {
    let records = records_for(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "ping",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        }
    }));

    let revision = records
        .iter()
        .find(|record| record.contains_key("protocol_revision"))
        .unwrap_or_else(|| {
            // Two different defects reach this line and the message has to
            // tell them apart: an empty capture is the tracing harness never
            // delivering, a non-empty one without the key is the record site
            // itself omitting the field or the dispatcher returning early.
            let keys: Vec<Vec<&String>> = records
                .iter()
                .map(|record| record.keys().collect())
                .collect();
            panic!(
                "a stdio request must be observed: {} record(s) captured, \
                 keys {:?}. Empty => the tracing capture never delivered; \
                 non-empty => the record site ran without `protocol_revision`",
                records.len(),
                keys,
            )
        });
    assert_eq!(
        value(revision, "protocol_revision"),
        "2026-07-28",
        "the record must carry the revision the request declared"
    );
    assert_eq!(
        value(revision, "revision_source"),
        "_meta",
        "stdio has no headers, so a modern request's revision can only \
         have come from `_meta`"
    );
}

/// The record a two-message session must produce, or a panic naming
/// which of the two defects produced no record at all.
fn revision_record_after(session_id: &str, requested: &str) -> Record {
    let records = records_for_session(
        session_id,
        &[
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": requested,
                    "clientInfo": {"name": "row-20", "version": "0"},
                    "capabilities": {}
                }
            }),
            // Legacy shape on purpose: no `_meta`, and stdio has no
            // header, so the session is the ONLY place the revision can
            // come from. A modern fixture would pass without the store.
            json!({"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {}}),
        ],
    );
    records
        .iter()
        .find(|record| record.contains_key("protocol_revision"))
        .unwrap_or_else(|| {
            panic!(
                "the request after `initialize` must be observed: {} record(s) captured",
                records.len()
            )
        })
        .clone()
}

// OBS.1, row 20. A stdio session settles its revision at `initialize`
// and every later request is served under it. The record must say so,
// and must say where it learned it -- `handshake`, the fourth
// `revision_source` value, decided in the design note rather than
// invented here.
#[test]
fn ac_obs_1_stdio_records_the_revision_the_handshake_negotiated() {
    let record = revision_record_after("stdio-row-20", "2025-06-18");
    assert_eq!(
        value(&record, "protocol_revision"),
        "2025-06-18",
        "a request after the handshake must carry the negotiated revision, \
         not `absent`"
    );
    assert_eq!(
        value(&record, "revision_source"),
        "handshake",
        "the revision came from the session's handshake, and the record \
         must name that source rather than leaving it `none`"
    );
}

// OBS.1, row 21. Ask and answer diverge whenever the ask is
// unsupported: `negotiate_version` falls back to `PROTOCOL_VERSION`.
// The record reports what the server ANSWERED. Recording the ask would
// be cluster G row 2's defect again -- a record asserting one thing
// while the code resolved another.
#[test]
fn ac_obs_1_stdio_records_the_answer_not_the_ask() {
    let record = revision_record_after("stdio-row-21", "2019-01-01");
    assert_eq!(
        value(&record, "protocol_revision"),
        crate::protocol::PROTOCOL_VERSION,
        "an unsupported request is answered with the fallback revision, \
         and the record must carry the answer"
    );
    assert_ne!(
        value(&record, "protocol_revision"),
        "2019-01-01",
        "the client's ask is not the session's revision"
    );
}

// OBS.1 / MRTR, the stdio retry gap -- NOT closed by this change and
// deliberately left red rather than pinned as correct. See
// `docs/design/2026-09-02-cluster-g-stdio-dispatch-parity.md` §P3,
// "`NO_RETRY` on stdio -- declared OUT, with something watching it":
// closing it needs `RetryFields` built at the convergence point and
// malformed retry fields refused pre-dispatch on both transports, which
// is its own change with its own test rows.
#[test]
#[ignore = "stdio hardcodes `retry: &NO_RETRY` (server/mod.rs); out of scope for cluster G, watched here so the defect is not pinned as correct"]
fn stdio_should_present_a_retry_when_the_context_declares_one() {
    let source = include_str!("../mod.rs");
    // Split so this assertion is not itself the occurrence it looks
    // for: a watcher that can never go green watches nothing.
    let hardcoded = concat!("retry: &", "NO_RETRY");
    assert!(
        !source.contains(hardcoded),
        "the stdio context must build its retry fields at the convergence \
         point instead of hardcoding an absent retry"
    );
}
