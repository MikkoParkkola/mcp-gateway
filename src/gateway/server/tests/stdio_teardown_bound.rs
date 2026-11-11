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
    let dir = crate::test_dir_keep::kept_tempdir();
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

#[cfg(unix)]
mod hurry {
    use super::*;
    use tokio::io::AsyncWriteExt;

    const ROW_BOUND: Duration = Duration::from_secs(15);
    /// Under `ROW_BOUND`, so a stuck step is named before the generic wait fails.
    const NAMED_STEP_BOUND: Duration = Duration::from_secs(14);

    #[derive(Default)]
    struct ReplyBackend {
        hold: crate::test_pause::Slot,
        produced: std::sync::atomic::AtomicUsize,
        closed: AtomicBool,
    }
    #[async_trait]
    impl Transport for ReplyBackend {
        async fn request(&self, method: &str, _: Option<Value>) -> crate::Result<JsonRpcResponse> {
            let result = if method == "tools/list" {
                json!({"tools": [{"name": "echo", "inputSchema": {"type": "object"},
                    "annotations": {"readOnlyHint": true}}]})
            } else if method == "ping" {
                json!({})
            } else {
                assert_eq!(method, "tools/call");
                self.hold.pause().await;
                self.produced.fetch_add(1, Ordering::SeqCst);
                json!({"content": [{"type": "text", "text": "done"}], "isError": false})
            };
            Ok(JsonRpcResponse::success(RequestId::Number(1), result))
        }
        async fn notify(&self, _: &str, _: Option<Value>) -> crate::Result<()> {
            Ok(())
        }
        fn is_connected(&self) -> bool {
            !self.closed.load(Ordering::SeqCst)
        }
        async fn close(&self) -> crate::Result<()> {
            self.closed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }
    #[tokio::test]
    async fn a_hurry_does_not_discard_replies_already_produced() {
        use crate::test_pause::within;
        use tokio::io::AsyncReadExt;

        let dir = crate::test_dir_keep::kept_tempdir();
        let mut config = Config::default();
        config.tasks.store_dir = dir.path().join("tasks").display().to_string();
        config.capabilities.enabled = false;
        config.cache.default_ttl = Duration::ZERO;
        config.meta_mcp.surfaced_tools = vec![crate::config::SurfacedToolConfig {
            server: "reply".into(),
            tool: "echo".into(),
        }];
        let mut gateway = Gateway::new(config)
            .await
            .expect("gateway boots")
            .with_data_dir(dir.path().to_path_buf());
        let wire = Arc::new(ReplyBackend::default());
        let backend = Arc::new(Backend::new(
            "reply",
            BackendConfig::default(),
            &FailsafeConfig::default(),
            Duration::from_secs(60),
        ));
        backend.set_transport_for_test(wire.clone());
        backend.get_tools_shared().await.expect("tools cached");
        assert!(gateway.backends.register(backend));
        let hurry = gateway.hurry_trigger_for_test();
        let deadline = gateway.backends.stop_deadline();
        let (_, drain) = gateway.stdio_drain_seams_for_test();
        let (mut stdin, input) = tokio::io::duplex(65536);
        let (output, mut stdout) = tokio::io::duplex(1);
        let task = tokio::spawn(async move { gateway.run_stdio_on(input, output, None).await });
        let call = |id| {
            json!({"jsonrpc": "2.0", "id": id,
            "method": "tools/call", "params": {"name": "echo", "arguments": {"n": id}}})
            .to_string()
                + "\n"
        };
        let (executing, release) = wire.hold.arm();
        let line = call(0);
        stdin.write_all(line.as_bytes()).await.expect("call");
        within("backend executing", executing.notified()).await;
        let n = 3;
        for id in 1..=n {
            let line = call(id);
            stdin.write_all(line.as_bytes()).await.expect("call");
            named(
                &format!("backend produced reply {id}"),
                wait_for(|| wire.produced.load(Ordering::SeqCst) == id),
            )
            .await;
        }
        // The first reply blocks in the writer (stdout holds one byte) and the
        // rest wait in its queue. No stdout reader has run yet.
        stdin.shutdown().await.expect("EOF");
        within("drain started", drain.notified()).await;
        assert!(wire.is_connected(), "in-flight backend alive at hurry");
        hurry.send(()).expect("hurry listener installed");
        named(
            "hurry moves the registry deadline",
            wait_for(|| deadline.get().is_some()),
        )
        .await;
        release.notify_one();
        let mut bytes = String::new();
        within("stdout closes", stdout.read_to_string(&mut bytes))
            .await
            .expect("read stdout");
        let served = within("serve ends", task).await.expect("serve task");
        served.expect("stdio result");
        let replies: Vec<Value> = bytes
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        let missing: Vec<_> = (0..=n)
            .filter(|id| !replies.iter().any(|r| r["id"] == json!(id)))
            .collect();
        assert!(
            missing.is_empty(),
            "hurry discarded replies: {missing:?}; id 0 was executing, ids 1..={n} were produced"
        );
        for reply in replies {
            assert_eq!(reply["jsonrpc"], "2.0");
            if reply["id"] == 0 {
                assert!(reply.get("result").is_some() || reply["error"]["code"].is_number());
            } else {
                assert_eq!(reply["result"]["content"][0]["text"], "done");
            }
        }
    }

    async fn fixture() -> (Gateway, Arc<tempfile::TempDir>, Arc<AtomicBool>) {
        let dir = crate::test_dir_keep::kept_tempdir();
        let mut config = Config::default();
        config.tasks.store_dir = dir.path().join("tasks").display().to_string();
        config.server.shutdown_timeout = Duration::from_secs(30);
        let gateway = Gateway::new(config)
            .await
            .expect("gateway boots")
            .with_data_dir(dir.path().to_path_buf());
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
        assert!(gateway.backends.register(stuck));
        (gateway, dir, entered)
    }

    /// Name the step a stuck wait belongs to, so a red row says where it stopped.
    async fn named<T>(step: &str, wait: impl std::future::Future<Output = T>) -> T {
        timeout(NAMED_STEP_BOUND, wait)
            .await
            .unwrap_or_else(|_| panic!("{step}: not reached"))
    }

    async fn wait_for(mut ready: impl FnMut() -> bool) {
        timeout(ROW_BOUND, async {
            while !ready() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("seam reached");
    }

    /// A fresh signal after EOF or the first signal cuts a held drain and the
    /// shared registry deadline. Red if the first signal hurries, or a late one is lost.
    #[tokio::test]
    async fn a_signal_after_the_read_loop_hurries_the_registry() {
        for signal_ends_read in [false, true] {
            let (mut gateway, _dir, entered) = fixture().await;
            let first = gateway.shutdown_trigger_for_test();
            let hurry = gateway.hurry_trigger_for_test();
            let deadline = gateway.backends.stop_deadline();
            let (hold, drain) = gateway.stdio_drain_seams_for_test();
            let (reached, _release) = hold.arm();
            let (mut stdin, input) = tokio::io::duplex(65536);
            let (output, _reader) = tokio::io::duplex(65536);
            let task = tokio::spawn(async move { gateway.run_stdio_on(input, output, None).await });
            stdin
                .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n")
                .await
                .expect("send held dispatch");
            timeout(ROW_BOUND, reached.notified())
                .await
                .expect("dispatch held");
            if signal_ends_read {
                first.send(()).expect("first signal listener");
            } else {
                stdin.shutdown().await.expect("EOF");
            }
            timeout(ROW_BOUND, drain.notified())
                .await
                .expect("read loop ended");
            assert_eq!(deadline.get(), None, "the first signal must not hurry");
            hurry.send(()).expect("late signal listener is installed");
            wait_for(|| entered.load(Ordering::SeqCst)).await;
            let now = std::time::Instant::now();
            let cut = deadline
                .get()
                .expect("hurry published the registry deadline");
            assert!(cut > now, "backend stop still has a graceful window");
            assert!(
                cut <= now
                    + crate::transport::KILL_RESERVE_FOR_TEST
                    + crate::transport::HURRY_WINDOW
            );
            timeout(ROW_BOUND, task)
                .await
                .expect("hurried stop ends")
                .expect("serve task")
                .expect("stdio result");
        }
    }

    #[tokio::test]
    async fn a_hurry_during_post_drain_cleanup_does_not_repoll_the_finished_drain() {
        let (mut gateway, _dir, _entered) = fixture().await;
        let hurry = gateway.hurry_trigger_for_test();
        let deadline = gateway.backends.stop_deadline();
        let (reached, release) = gateway.test_seams.stdio_before_backends_hold.arm();
        let (stdin, input) = tokio::io::duplex(65536);
        let (output, _reader) = tokio::io::duplex(65536);
        let task = tokio::spawn(async move { gateway.run_stdio_on(input, output, None).await });
        drop(stdin);
        // This point is reached only after the read loop and `before` finish.
        named("post-drain cleanup held", reached.notified()).await;
        assert_eq!(deadline.get(), None, "ordinary backend stop has not begun");
        hurry.send(()).expect("late signal listener is installed");
        named(
            "hurry moves the registry deadline",
            wait_for(|| deadline.get().is_some()),
        )
        .await;
        release.notify_one();
        let cut = deadline
            .get()
            .expect("hurry published the registry deadline");
        assert!(
            cut <= std::time::Instant::now()
                + crate::transport::KILL_RESERVE_FOR_TEST
                + crate::transport::HURRY_WINDOW
        );
        timeout(ROW_BOUND, task)
            .await
            .expect("hurried stop ends")
            .expect("the serve task does not panic")
            .expect("run_stdio_on returns Ok");
    }

    /// A signal remains effective after backend stopping starts.
    /// Red if the listener disappears when pre-backend shutdown finishes.
    #[tokio::test]
    async fn a_signal_during_backend_stop_shortens_its_deadline() {
        let (mut gateway, _dir, entered) = fixture().await;
        let hurry = gateway.hurry_trigger_for_test();
        let deadline = gateway.backends.stop_deadline();
        let (stdin, input) = tokio::io::duplex(65536);
        let (output, _reader) = tokio::io::duplex(65536);
        let task = tokio::spawn(async move { gateway.run_stdio_on(input, output, None).await });
        drop(stdin);
        wait_for(|| entered.load(Ordering::SeqCst)).await;
        let old = deadline.get().expect("ordinary stop started");
        hurry.send(()).expect("late listener remains installed");
        wait_for(|| deadline.get().is_some_and(|cut| cut < old)).await;
        assert!(
            deadline.get().expect("shortened")
                <= std::time::Instant::now()
                    + crate::transport::KILL_RESERVE_FOR_TEST
                    + crate::transport::HURRY_WINDOW
        );
        timeout(ROW_BOUND, task)
            .await
            .expect("hurried stop ends")
            .expect("serve task")
            .expect("stdio result");
    }
}
