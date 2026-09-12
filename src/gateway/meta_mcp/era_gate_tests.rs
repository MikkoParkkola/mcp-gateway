// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows 13 to 15c of `docs/design/2026-09-11-outbound-era-gated-health-probe.md`
//! — the three outbound call sites section 4 gates, alongside the health probe.
//!
//! These rows live here rather than in `src/backend/tests.rs` because the send
//! they pin is the gateway's, not the probe's: `logging/setLevel` fans out over
//! every backend and the two `resources/*` verbs are forwarded per client
//! request. What they share with the probe rows is the fixture shape — a
//! backend wired to a recording transport whose era is resolved from its own
//! answer to `server/discover`, so no row asserts an era it also sets.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use crate::backend::{Backend, BackendRegistry};
use crate::config::BackendConfig;
use crate::error::Result;
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::transport::Transport;

/// A resource the fixture backend owns, so `find_resource_owner` resolves to it
/// and the two `resources/*` rows reach the forward these rows exist to pin.
const OWNED_URI: &str = "file:///owned/by/the/fixture.txt";

/// Records every method that reaches the wire and answers enough of the
/// protocol for era resolution and resource ownership to work. Deliberately
/// answers *successfully* to the gated methods: a row asserting "the method
/// never arrived" must not be able to pass because the peer refused it.
struct EraMock {
    methods: std::sync::Mutex<Vec<String>>,
    modern: bool,
    connected: AtomicBool,
}

impl EraMock {
    fn new(modern: bool) -> Self {
        Self {
            methods: std::sync::Mutex::new(Vec::new()),
            modern,
            connected: AtomicBool::new(true),
        }
    }

    fn methods(&self) -> Vec<String> {
        self.methods.lock().expect("methods lock").clone()
    }

    fn saw(&self, method: &str) -> bool {
        self.methods().iter().any(|m| m == method)
    }
}

#[async_trait::async_trait]
impl Transport for EraMock {
    async fn request(&self, method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
        self.methods
            .lock()
            .expect("methods lock")
            .push(method.to_string());
        let id = RequestId::Number(1);
        match method {
            // The era classification probe. A modern peer knows the method and
            // declines the version; a legacy one has never heard of it.
            "server/discover" => {
                let code = if self.modern {
                    crate::protocol::era::UNSUPPORTED_PROTOCOL_VERSION
                } else {
                    crate::protocol::era::METHOD_NOT_FOUND_CODE
                };
                Ok(JsonRpcResponse::error(Some(id), code, "declined"))
            }
            "resources/list" => Ok(JsonRpcResponse::success_serialized(
                id,
                json!({"resources": [{"uri": OWNED_URI, "name": "owned"}]}),
            )),
            _ => Ok(JsonRpcResponse::success_serialized(id, json!({}))),
        }
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    async fn close(&self) -> Result<()> {
        self.connected.store(false, Ordering::Relaxed);
        Ok(())
    }
}

async fn backend_with_era(name: &str, modern: bool) -> (Arc<Backend>, Arc<EraMock>) {
    let mock = Arc::new(EraMock::new(modern));
    let backend = Arc::new(Backend::new(
        name,
        BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let transport = Arc::clone(&mock) as Arc<dyn Transport>;
    backend.set_transport_for_test(Arc::clone(&transport));
    backend.resolve_era_for_test(&transport).await;
    let expected = if modern {
        crate::protocol::era::Era::Modern
    } else {
        crate::protocol::era::Era::Legacy
    };
    assert_eq!(
        backend.cached_era().await,
        Some(expected),
        "precondition: the fixture must construct a {expected:?} peer"
    );
    (backend, mock)
}

fn meta(backends: Vec<Arc<Backend>>) -> MetaMcp {
    let registry = Arc::new(BackendRegistry::new());
    for backend in backends {
        assert!(registry.register(backend), "fixture backends are distinct");
    }
    MetaMcp::new(registry)
}

/// Row 13 — the `logging/setLevel` fan-out skips a modern backend and still
/// forwards to a legacy one **in the same call**. Both halves are asserted from
/// one invocation because the defect an implementation is most likely to ship
/// is a gate that reads a gateway-wide value rather than each backend's era,
/// and such a gate is invisible to a row that registers one backend.
#[tokio::test]
async fn row_13_logging_set_level_skips_a_modern_backend_and_forwards_to_a_legacy_one() {
    let (modern, modern_mock) = backend_with_era("modern", true).await;
    let (legacy, legacy_mock) = backend_with_era("legacy", false).await;
    let meta = meta(vec![modern, legacy]);

    let params = json!({"level": "debug"});
    let response = meta
        .handle_logging_set_level(RequestId::Number(1), Some(&params))
        .await;
    assert!(
        response.error.is_none(),
        "skipping a backend must not fail the request: {response:?}"
    );

    assert!(
        !modern_mock.saw("logging/setLevel"),
        "logging/setLevel was removed in 2026-07-28 and must not reach a modern peer, saw: {:?}",
        modern_mock.methods()
    );
    assert!(
        legacy_mock.saw("logging/setLevel"),
        "a legacy peer still serves logging/setLevel and must still be forwarded"
    );
}

/// Row 14 — `resources/subscribe` against a modern backend is refused by the
/// gateway with `-32601` and never reaches the transport.
#[tokio::test]
async fn row_14_resources_subscribe_to_a_modern_backend_is_refused_in_the_gateway() {
    let (modern, mock) = backend_with_era("modern", true).await;
    let meta = meta(vec![modern]);

    let params = json!({"uri": OWNED_URI});
    let response = meta
        .handle_resources_subscribe(RequestId::Number(1), Some(&params))
        .await;

    let error = response
        .error
        .as_ref()
        .unwrap_or_else(|| panic!("a removed method must be refused, got: {response:?}"));
    assert_eq!(
        error.code,
        crate::protocol::era::METHOD_NOT_FOUND_CODE,
        "the gateway's refusal carries the code the peer would have sent"
    );
    assert!(
        !mock.saw("resources/subscribe"),
        "the refusal must happen before the wire, saw: {:?}",
        mock.methods()
    );
}

/// Row 15 — `resources/unsubscribe`, the same two assertions. Split from row 14
/// rather than looped, because the two call sites are two separate forwards and
/// a gate applied to one of them is the defect this pair exists to catch.
#[tokio::test]
async fn row_15_resources_unsubscribe_to_a_modern_backend_is_refused_in_the_gateway() {
    let (modern, mock) = backend_with_era("modern", true).await;
    let meta = meta(vec![modern]);

    let params = json!({"uri": OWNED_URI});
    let response = meta
        .handle_resources_unsubscribe(RequestId::Number(1), Some(&params))
        .await;

    let error = response
        .error
        .as_ref()
        .unwrap_or_else(|| panic!("a removed method must be refused, got: {response:?}"));
    assert_eq!(
        error.code,
        crate::protocol::era::METHOD_NOT_FOUND_CODE,
        "the gateway's refusal carries the code the peer would have sent"
    );
    assert!(
        !mock.saw("resources/unsubscribe"),
        "the refusal must happen before the wire, saw: {:?}",
        mock.methods()
    );
}

/// Row 15c — the mirror half, and a regression guard: a **legacy** backend still
/// receives both `resources/*` verbs, before and after. It passes at HEAD, which
/// forwards everything, and it is what keeps the gate from being implemented as
/// a blanket refusal.
#[tokio::test]
async fn row_15c_a_legacy_backend_still_receives_both_resource_verbs() {
    let (legacy, mock) = backend_with_era("legacy", false).await;
    let meta = meta(vec![legacy]);

    let params = json!({"uri": OWNED_URI});
    let subscribe = meta
        .handle_resources_subscribe(RequestId::Number(1), Some(&params))
        .await;
    let unsubscribe = meta
        .handle_resources_unsubscribe(RequestId::Number(2), Some(&params))
        .await;

    assert!(
        subscribe.error.is_none(),
        "a legacy peer serves resources/subscribe: {subscribe:?}"
    );
    assert!(
        unsubscribe.error.is_none(),
        "a legacy peer serves resources/unsubscribe: {unsubscribe:?}"
    );
    assert!(
        mock.saw("resources/subscribe") && mock.saw("resources/unsubscribe"),
        "both verbs must still reach a legacy peer, saw: {:?}",
        mock.methods()
    );
}
