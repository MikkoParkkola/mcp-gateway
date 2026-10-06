// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7685 (#2530): after stdio EOF, every teardown await sits under one
//! stated deadline. A backend whose stop never completes cannot keep the
//! operator's stdio gateway alive past it.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::time::{Instant, timeout};

use crate::backend::Backend;
use crate::config::{BackendConfig, Config, FailsafeConfig};
use crate::gateway::Gateway;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::transport::Transport;

/// A transport whose close never returns, and says when it was entered.
struct NeverCloses {
    entered: Arc<AtomicBool>,
}

#[async_trait]
impl Transport for NeverCloses {
    async fn request(
        &self,
        _method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        Ok(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            json!({}),
        ))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        self.entered.store(true, Ordering::SeqCst);
        std::future::pending().await
    }
}

// Paused time: the bound is tens of seconds of timers, not of work. Tokio
// does not auto-advance while a blocking task (file IO) runs, so the IO stays
// real (MIK-7839).
#[tokio::test(start_paused = true)]
async fn stdio_eof_returns_within_the_bound_when_a_backend_never_stops() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    // The task store under the test's own directory, never the default under $HOME.
    let yaml = format!(
        "tasks:\n  store_dir: {}\n",
        serde_json::to_string(&dir.path().join("tasks").display().to_string())
            .expect("a JSON string")
    );
    crate::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
    let config = Config::load(Some(&path)).expect("config loads");
    let gateway = Gateway::new(config)
        .await
        .expect("gateway boots")
        .with_data_dir(dir.path().to_path_buf());

    // Its own close budget is far past any shutdown bound: only the stdio
    // teardown's deadline can end the wait.
    let mut stuck = Backend::new(
        "stuck",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    );
    stuck.budgets.close_stage = Duration::from_secs(3600);
    let stuck = Arc::new(stuck);
    let entered = Arc::new(AtomicBool::new(false));
    stuck.set_transport_for_test(Arc::new(NeverCloses {
        entered: Arc::clone(&entered),
    }));
    assert!(gateway.backends.register(Arc::clone(&stuck)));

    let (stdin, input) = tokio::io::duplex(64 * 1024);
    let (output, _reader) = tokio::io::duplex(64 * 1024);
    let task = tokio::spawn(async move { gateway.run_stdio_on(input, output, None).await });
    let eof = Instant::now();
    drop(stdin);

    // No request is in flight, so the drain ends at once; the stated bound
    // from EOF is the drain window plus the teardown window, with slack.
    let bound = super::super::STDIO_DRAIN_TIMEOUT + Duration::from_secs(15);
    timeout(bound, task)
        .await
        .unwrap_or_else(|_| panic!("run_stdio_on must return within {bound:?} of EOF"))
        .expect("the serve task does not panic")
        .expect("run_stdio_on returns Ok");
    assert!(eof.elapsed() < bound, "{:?}", eof.elapsed());
    assert!(
        entered.load(Ordering::SeqCst),
        "teardown reached the close that never returns, so the bound ended it"
    );
}
