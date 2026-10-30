// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use crate::error::rpc_codes::METHOD_NOT_FOUND;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::backend::Backend;
use crate::config::BackendConfig;
use crate::protocol::era::UNSUPPORTED_PROTOCOL_VERSION;
use crate::transport::Transport;

use super::*;

/// Records every method that reaches the wire and answers the era probe
/// per `modern`; everything else (including a removed method, if the
/// gate under test fails to catch it) succeeds, so a row asserting "the
/// method never arrived" can't pass because the peer refused it anyway.
struct EraMock {
    methods: Mutex<Vec<String>>,
    modern: bool,
    connected: AtomicBool,
}

impl EraMock {
    fn new(modern: bool) -> Self {
        Self {
            methods: Mutex::new(Vec::new()),
            modern,
            connected: AtomicBool::new(true),
        }
    }

    fn saw(&self, method: &str) -> bool {
        self.methods
            .lock()
            .expect("methods lock")
            .iter()
            .any(|m| m == method)
    }
}

#[async_trait::async_trait]
impl Transport for EraMock {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        self.methods
            .lock()
            .expect("methods lock")
            .push(method.to_string());
        let id = RequestId::Number(1);
        if method == "server/discover" {
            let code = if self.modern {
                UNSUPPORTED_PROTOCOL_VERSION
            } else {
                METHOD_NOT_FOUND
            };
            return Ok(JsonRpcResponse::error(Some(id), code, "declined"));
        }
        Ok(JsonRpcResponse::success_serialized(id, json!({})))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    async fn close(&self) -> crate::Result<()> {
        self.connected.store(false, Ordering::Relaxed);
        Ok(())
    }
}

/// A backend whose era was resolved from its own `server/discover`
/// answer, exactly as `resolve_era` does on a real start — not asserted
/// by a setter.
async fn backend_with_era(name: &str, modern: bool) -> (Backend, Arc<EraMock>) {
    let mock = Arc::new(EraMock::new(modern));
    let backend = Backend::new(
        name,
        BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    );
    let transport = Arc::clone(&mock) as Arc<dyn Transport>;
    backend.set_transport_for_test(Arc::clone(&transport));
    backend.resolve_era_for_test(&transport).await;
    (backend, mock)
}

// `ping` is picked deliberately: it is NOT one of the three methods any
// meta-dispatch call site already gates (resources/subscribe,
// resources/unsubscribe, logging/setLevel), so a pass here can only come
// from the direct route's send itself doing the check, not from some other
// gate this row would be fooled by.
#[tokio::test]
async fn dispatch_in_scope_refuses_a_removed_method_to_a_modern_backend() {
    let (backend, mock) = backend_with_era("modern", true).await;

    let response = super::direct_send::dispatch_non_call(
        super::direct_send::NonToolMethod::new("ping").expect("not tools/call"),
        &backend,
        &RequestId::Number(7),
        None,
        (crate::transport::LentCredential::default(), None),
    )
    .await
    .expect("the gateway answers the refusal itself; the transport call does not error");

    let error = response
        .error
        .as_ref()
        .unwrap_or_else(|| panic!("a removed method must be refused, got: {response:?}"));
    assert_eq!(
        error.code, METHOD_NOT_FOUND,
        "the gateway's refusal carries the code the peer would have sent"
    );
    assert_eq!(
        response.id.as_ref(),
        Some(&RequestId::Number(7)),
        "a refusal the gateway answers itself must still be correlatable: {response:?}"
    );
    assert!(
        !mock.saw("ping"),
        "the refusal must happen before the wire, saw: {:?}",
        mock.methods.lock().expect("methods lock")
    );
}

// Regression guard: a legacy backend must still receive a method the
// 2026-07-28 revision removed — it is legal there. If this row breaks,
// the fix is wrong, not this row.
#[tokio::test]
async fn dispatch_in_scope_still_forwards_a_removed_method_to_a_legacy_backend() {
    let (backend, mock) = backend_with_era("legacy", false).await;

    let response = super::direct_send::dispatch_non_call(
        super::direct_send::NonToolMethod::new("ping").expect("not tools/call"),
        &backend,
        &RequestId::Number(7),
        None,
        (crate::transport::LentCredential::default(), None),
    )
    .await
    .expect("legacy peer answers");

    assert!(
        response.error.is_none(),
        "a legacy peer still serves ping: {response:?}"
    );
    assert!(mock.saw("ping"), "ping must still reach a legacy peer");
}
