// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The direct route mints its own progress token inside a request scope.

use std::sync::Mutex;

use async_trait::async_trait;

use super::*;
use crate::backend::Backend;
use crate::config::BackendConfig;
use crate::protocol::RequestId;
use crate::transport::Transport;

/// Records the params as the backend would see them on the wire.
struct Recorder(Mutex<Option<Value>>);

#[async_trait]
impl Transport for Recorder {
    async fn request(
        &self,
        _method: &str,
        params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        *self.0.lock().unwrap() = params;
        Ok(JsonRpcResponse::success(RequestId::Number(1), json!({})))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

fn recording_backend() -> (Arc<Backend>, Arc<Recorder>) {
    let backend = Arc::new(Backend::new(
        "direct",
        BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(5),
    ));
    let recorder = Arc::new(Recorder(Mutex::new(None)));
    backend.set_transport_for_test(recorder.clone() as Arc<dyn Transport>);
    (backend, recorder)
}

/// `POST /mcp/{name}` is a client request like any other, so the token the
/// backend sees must be the gateway's own. The mint no-ops outside a
/// request scope, so dropping the wrapper here would be silent -- this row
/// is what makes it loud.
#[tokio::test]
async fn a_call_on_this_route_sends_the_backend_a_minted_token() {
    let (backend, recorder) = recording_backend();

    dispatch_in_scope(
        &backend,
        "tools/call",
        &RequestId::Number(1),
        Some(json!({ "name": "t", "_meta": { "progressToken": 7 } })),
        &[],
        None,
    )
    .await
    .expect("the recording transport answers");

    let sent = recorder.0.lock().unwrap().clone().expect("params recorded");
    let token = &sent["_meta"]["progressToken"];
    assert_ne!(
        token,
        &json!(7),
        "the caller's own token reached the backend"
    );
    assert!(
        token.as_str().is_some_and(|t| t.starts_with("gw-")),
        "backend was sent {token:?}"
    );
}
