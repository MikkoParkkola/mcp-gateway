// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shared isolated-child and non-advancing observation helpers for server tests.

use std::time::Duration;

const CHILD: &str = "MCP_V4_EXPIRY_BUILDER_CHILD";

pub(super) fn isolated_child(name: &str) -> bool {
    if std::env::var(CHILD).as_deref() == Ok(name) {
        return false;
    }
    let dir = tempfile::tempdir().expect("isolated persistence directory");
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", name, "--nocapture"])
        .env(CHILD, name)
        .env("HOME", dir.path())
        .env("XDG_DATA_HOME", dir.path().join("data"))
        .env("XDG_CONFIG_HOME", dir.path().join("config"));
    let log_path = dir.path().join("child.log");
    let log = std::fs::File::create(&log_path).expect("child output");
    command.stdout(log.try_clone().unwrap()).stderr(log);
    let mut child = command.spawn().expect("run exact isolated test");
    let deadline = std::time::Instant::now() + Duration::from_secs(45);
    let status = loop {
        if let Some(status) = child.try_wait().expect("observe isolated child") {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "isolated child exceeded 45 seconds:\n{}",
                std::fs::read_to_string(&log_path).unwrap_or_default()
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let output = std::fs::read_to_string(&log_path).expect("read isolated child output");
    assert!(status.success(), "child failed:\n{output}");
    assert!(output.contains(&format!("COMPLETED {name}")));
    true
}

pub(super) async fn observed_without_time_advance<F: std::future::Future>(
    future: F,
) -> Option<F::Output> {
    use std::task::Poll;
    let clock = tokio::time::Instant::now();
    let watchdog = std::time::Instant::now() + Duration::from_secs(5);
    let mut future = std::pin::pin!(future);
    let result = std::future::poll_fn(|cx| match future.as_mut().poll(cx) {
        Poll::Ready(value) => Poll::Ready(Some(value)),
        Poll::Pending if std::time::Instant::now() >= watchdog => Poll::Ready(None),
        Poll::Pending => {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
    assert_eq!(tokio::time::Instant::now(), clock);
    result
}
