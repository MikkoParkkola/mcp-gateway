// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The stdio task store at the end of a session: EOF releases its lease,
//! drains a running task, and an auth config that cannot resolve leaves it
//! open. Moved out of the stdio owner rows to keep them under the
//! file-size ceiling.

use super::*;

/// U6: EOF releases the stdio store's lease before `run_stdio_on` returns.
#[tokio::test]
async fn stdio_eof_releases_the_store_lease_before_returning() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let (url, _rounds) = backend().await;
    let store = crate::test_dir_keep::kept_tempdir();
    let mut config = Config::default();
    config.tasks.store_dir = store.path().display().to_string();
    config.backends.insert(
        BACKEND.to_string(),
        BackendConfig {
            enabled: true,
            transport: TransportConfig::Http {
                http_url: url,
                streamable_http: Some(true),
                protocol_version: None,
            },
            ..BackendConfig::default()
        },
    );
    let data = crate::test_dir_keep::kept_tempdir();
    let gateway = Gateway::new(config.clone())
        .await
        .expect("gateway boots")
        .with_data_dir(data.path().to_path_buf());
    let (mut stdin, input) = tokio::io::duplex(64 * 1024);
    let (output, reader) = tokio::io::duplex(1 << 20);
    let served = tokio::spawn(async move { gateway.run_stdio_on(input, output, None).await });
    let mut lines = BufReader::new(reader).lines();
    let handshake = json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "owner2", "version": "1"}}});
    stdin
        .write_all(format!("{handshake}\n").as_bytes())
        .await
        .expect("write");
    tokio::time::timeout(Duration::from_secs(10), lines.next_line())
        .await
        .expect("handshake answered in time")
        .expect("read");
    let created = modern_call(1, TOOL, "u6", true);
    stdin
        .write_all(format!("{created}\n").as_bytes())
        .await
        .expect("write");
    let answer = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
        .await
        .expect("answered in time")
        .expect("read")
        .expect("a line");
    assert!(answer.contains("taskId"), "a task was created: {answer}");
    drop(stdin);
    tokio::time::timeout(Duration::from_secs(40), served)
        .await
        .expect("EOF returns within the bound")
        .expect("no panic")
        .expect("run_stdio_on returns Ok");
    let reopened = reopen_stdio_store(&config).await;
    if let Ok((service, _)) = &reopened {
        service.keep_test_dir(Arc::clone(&store));
    }
    assert!(
        reopened.is_ok(),
        "the lease is free once run_stdio_on returned"
    );
}

/// U9: EOF while a task is still running waits for it. `run_stdio_on` is
/// still serving while the held call is open, returns once it settles, and
/// the store, reopened at once, is free and holds the backend's own result:
/// the worker finished before the store closed. A task cut off instead would
/// recover at reopen as completed with a restart error, never with `done`.
#[tokio::test]
async fn eof_drains_a_running_task_before_returning() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let (url, mut arrived, release) = held_backend().await;
    let store = crate::test_dir_keep::kept_tempdir();
    let mut config = Config::default();
    config.tasks.store_dir = store.path().display().to_string();
    config.server.shutdown_timeout = Duration::from_secs(20);
    config.backends.insert(
        BACKEND.to_string(),
        BackendConfig {
            enabled: true,
            transport: TransportConfig::Http {
                http_url: url,
                streamable_http: Some(true),
                protocol_version: None,
            },
            ..BackendConfig::default()
        },
    );
    let data = crate::test_dir_keep::kept_tempdir();
    let gateway = Gateway::new(config.clone())
        .await
        .expect("gateway boots")
        .with_data_dir(data.path().to_path_buf());
    let (mut stdin, input) = tokio::io::duplex(64 * 1024);
    let (output, reader) = tokio::io::duplex(1 << 20);
    let mut served = tokio::spawn(async move { gateway.run_stdio_on(input, output, None).await });
    let mut lines = BufReader::new(reader).lines();
    let handshake = json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "owner2", "version": "1"}}});
    stdin
        .write_all(format!("{handshake}\n").as_bytes())
        .await
        .expect("write");
    tokio::time::timeout(Duration::from_secs(10), lines.next_line())
        .await
        .expect("handshake answered in time")
        .expect("read");
    let created = modern_call(1, "held", "u9", true);
    stdin
        .write_all(format!("{created}\n").as_bytes())
        .await
        .expect("write");
    let answer = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
        .await
        .expect("answered in time")
        .expect("read")
        .expect("a line");
    let answer: Value = serde_json::from_str(&answer).expect("one frame");
    let id = answer
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("a task handle: {answer}"))
        .to_owned();
    tokio::time::timeout(Duration::from_secs(10), arrived.wait_for(|seen| *seen >= 1))
        .await
        .expect("the held call reaches the backend")
        .expect("fixture alive");
    drop(stdin);
    // Five seconds is far past EOF's own work; a server that does not drain
    // returns well inside it, one that does is still held by the barrier.
    assert!(
        tokio::time::timeout(Duration::from_secs(5), &mut served)
            .await
            .is_err(),
        "EOF waits for the running task instead of returning past it"
    );
    release.send_modify(|open| *open = true);
    tokio::time::timeout(Duration::from_secs(30), served)
        .await
        .expect("EOF returns once the task settled")
        .expect("no panic")
        .expect("run_stdio_on returns Ok");
    let (service, _executor) = reopen_stdio_store(&config)
        .await
        .expect("the lease is free once run_stdio_on returned");
    service.keep_test_dir(Arc::clone(&store));
    let task = service
        .get(LOCAL_OPERATOR_PRINCIPAL, &id)
        .expect("the local operator's task is in its store");
    let wire = serde_json::to_value(task.task.wire()).expect("the task serializes");
    assert_eq!(
        task.task.status(),
        crate::protocol::tasks::TaskStatus::Completed,
        "{wire}"
    );
    assert!(
        wire.to_string().contains("done") && !wire.to_string().contains("gateway_restart"),
        "settled by its own worker with the backend's result, not by recovery: {wire}"
    );
}

/// Stdio serves no listener route, so its task store does
/// not depend on the gateway's auth configuration. A bearer token whose
/// secret reference cannot be resolved leaves the store open.
#[tokio::test]
async fn an_unresolvable_auth_config_leaves_the_stdio_store_open() {
    let fixture = Box::pin(fixture(None)).await;
    let store = crate::test_dir_keep::kept_tempdir();
    let mut config = Config::default();
    config.tasks.store_dir = store.path().display().to_string();
    config.auth.bearer_token = Some("env:MIK_7638_UNSET_FIXTURE_TOKEN".to_string());
    assert!(
        crate::gateway::auth::ResolvedAuthConfig::try_from_config(
            &config.auth,
            &crate::config::EnvOverlay::default(),
            crate::gateway::record_principal::TEST_RECORD_KEY
        )
        .is_err(),
        "premise: the fixture's auth secret must not resolve"
    );
    let opened = stdio_tasks::open(
        &config,
        &fixture.meta,
        &std::sync::Arc::new(crate::config_reload::LiveConfig::with_auth(
            config.clone(),
            std::sync::Arc::new(crate::gateway::server::stdio_tasks::default_auth(
                &crate::config::EnvOverlay::default(),
                std::sync::Arc::new(crate::gateway::record_principal::test_record_key()),
            )),
        )),
    )
    .await;
    assert!(
        opened.is_some(),
        "an auth secret stdio never uses turned its task store off"
    );
    if let Some((tasks, expiry)) = opened {
        let window = std::time::Duration::from_secs(5);
        let budget = crate::gateway::server::task_runtime::ShutdownBudget::within(window, window);
        stdio_tasks::shutdown(&tasks, expiry, budget).await;
    }
}
