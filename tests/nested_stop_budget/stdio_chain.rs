// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The rows whose outer gateway runs in stdio mode: a chain stopped by EOF
//! and then a second signal, three levels deep, and a plain SIGTERM.

use super::*;

/// Each nested hurry must fit its parent's remaining kill window, rather than
/// restarting 300 ms after SIGTERM and losing its reaper to its parent's kill.
/// Every pid of a three-level chain, asserted live before the stop begins.
fn live_chain(root: &Path, outer: u32, leaves: &[&str]) -> Vec<u32> {
    let mut tree = vec![
        outer,
        read_pid(root, "middle.pid"),
        read_pid(root, "inner.pid"),
    ];
    for name in leaves {
        tree.push(read_pid(root, &format!("leaf-{name}.pid")));
        tree.push(read_pid(root, &format!("leaf-{name}.grandchild.pid")));
    }
    assert_eq!(
        alive_pids(&tree),
        tree,
        "every chain level must be live before stop"
    );
    tree
}

#[tokio::test]
async fn a_three_level_nested_gateway_chain_leaves_no_leaf_after_a_hurry() {
    let temp = tempfile::tempdir().expect("temp root");
    let root = temp.path();
    let leaves = ["leaf_a", "leaf_b"];
    let inner = write_inner_config(root, &leaves, Duration::from_secs(30));
    let middle = write_chain_parent(root, "middle", "inner", &inner, During::Nothing, None);
    let outer = write_chain_parent(root, "outer", "middle", &middle, During::Nothing, None);
    let log = std::fs::File::create(root.join("gateway.log")).expect("log");
    let mut reaped = gateway_bin::Reaped::new(
        tokio::process::Command::from(gateway_bin::command(
            &root.join("home"),
            gateway_bin::Inherit::Environment,
        ))
        .env("RUST_LOG", "mcp_gateway=info")
        .env("MCP_GATEWAY_CONFIG_DIR", root.join("gateway-state"))
        .current_dir(root)
        .arg("--config")
        .arg(outer)
        .args(["serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::from(log.try_clone().expect("log handle")))
        .stderr(Stdio::from(log))
        .process_group(0)
        .kill_on_drop(true)
        .spawn()
        .expect("outer gateway"),
    );
    let pid = reaped.child_mut().id().expect("outer pid");
    let cleanup = KillGroup {
        pid,
        root: root.into(),
    };
    let mut stdin = reaped.child_mut().stdin.take().expect("stdin");
    let mut messages = vec![
        initialize(),
        json!({"jsonrpc":"2.0", "method":"notifications/initialized"}),
    ];
    for (id, name) in leaves.iter().enumerate() {
        let mut message = invoke(name, id + 1);
        let inner_call = message["params"]["arguments"].take();
        message["params"]["arguments"] =
            json!({"server":"middle", "tool":"gateway_invoke", "arguments":inner_call});
        messages.push(message);
    }
    for message in messages {
        stdin
            .write_all(format!("{message}\n").as_bytes())
            .await
            .expect("stdio");
    }
    let ready_by = Instant::now() + READY_BOUND;
    while leaves
        .iter()
        .any(|name| !root.join(format!("called-{name}")).exists())
    {
        assert!(
            Instant::now() < ready_by,
            "holds never started\n{}",
            logs(root)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let tree = live_chain(root, pid, &leaves);
    // EOF installs the hurry listener before logging this message. The busy
    // calls keep teardown pending until the subsequent SIGTERM cuts it short.
    drop(stdin);
    let eof_by = Instant::now() + READY_BOUND;
    while !logs(root).contains("stdio: EOF reached, shutting down") {
        assert!(
            Instant::now() < eof_by,
            "outer never saw EOF\n{}",
            logs(root)
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let hurried_at = Instant::now();
    sigterm(pid);
    // Observation time, not a watchdog: the outer kills at ~300 ms; allow
    // another 2 s for scheduling and exit, not the 6 s reap reserve.
    tokio::time::sleep_until(hurried_at + Duration::from_millis(2300)).await;
    assert!(
        logs(root).contains("shutdown hurried by a signal"),
        "outer did not hurry\n{}",
        logs(root)
    );
    let alive = alive_pids(&tree);
    assert!(
        alive.is_empty(),
        "chain processes survived the outer's hurry kill window: {alive:?}; all pids: {tree:?}\n{}",
        logs(root)
    );
    tokio::time::timeout(Duration::from_secs(10), reaped.child_mut().wait())
        .await
        .expect("outer exit deadline")
        .expect("outer exit");
    reaped.reap().await;
    std::mem::forget(cleanup);
}

/// A hurried stop (EOF then a second signal) of an outer gateway whose backend is a
/// gateway with two leaves of its own: the outer's group kill lands before the
/// inner's own hurried path has killed the leaves, which have their own process
/// groups, so every pid of the tree must still be dead afterwards.
/// Red if a gateway-child's leaves outlive the stop (the sweep before the kill is missing).
#[tokio::test]
async fn a_two_level_hurried_stop_leaves_no_leaf() {
    two_level_hurried_stop(During::Nothing).await;
}

/// The same hurried stop, but the inner is stopped (SIGSTOP) before the outer's
/// stop begins and never continued, so it ends nothing by itself: only the
/// outer's descendant sweep can end its leaves and their children.
/// Fails when that sweep no longer ends what a killed gateway-backend started.
#[tokio::test]
async fn a_hurried_nested_gateway_frozen_past_its_need_still_leaves_no_leaf() {
    two_level_hurried_stop(During::Freeze).await;
}

/// EOF, then a second signal, to a stdio outer whose backend is a gateway with two
/// leaves; given `During::Freeze`, the inner is frozen before the EOF, where this
/// outer's stop begins.
#[allow(
    clippy::too_many_lines,
    reason = "one hurried chain's start, stop and checks, with the freeze and the watch at their places in it"
)]
async fn two_level_hurried_stop(during: During) {
    let temp = tempfile::tempdir().expect("temp root");
    let root = temp.path();
    let leaves = ["leaf_a", "leaf_b"];
    let inner = write_inner_config(root, &leaves, Duration::from_secs(30));
    let outer = write_chain_parent(root, "outer", "inner", &inner, during, None);
    let log = std::fs::File::create(root.join("gateway.log")).expect("log");
    let mut reaped = gateway_bin::Reaped::new(
        tokio::process::Command::from(gateway_bin::command(
            &root.join("home"),
            gateway_bin::Inherit::Environment,
        ))
        .env("RUST_LOG", "mcp_gateway=info")
        .env("MCP_GATEWAY_CONFIG_DIR", root.join("gateway-state"))
        .current_dir(root)
        .arg("--config")
        .arg(outer)
        .args(["serve", "--stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::from(log.try_clone().expect("log handle")))
        .stderr(Stdio::from(log))
        .process_group(0)
        .kill_on_drop(true)
        .spawn()
        .expect("outer gateway"),
    );
    let pid = reaped.child_mut().id().expect("outer pid");
    let cleanup = KillGroup {
        pid,
        root: root.into(),
    };
    let mut stdin = reaped.child_mut().stdin.take().expect("stdin");
    let mut messages = vec![
        initialize(),
        json!({"jsonrpc":"2.0", "method":"notifications/initialized"}),
    ];
    for (id, name) in leaves.iter().enumerate() {
        let message = invoke(name, id + 1);
        messages.push(message);
    }
    for message in messages {
        stdin
            .write_all(format!("{message}\n").as_bytes())
            .await
            .expect("stdio");
    }
    let ready_by = Instant::now() + READY_BOUND;
    while leaves
        .iter()
        .any(|name| !root.join(format!("called-{name}")).exists())
    {
        assert!(
            Instant::now() < ready_by,
            "holds never started\n{}",
            logs(root)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let roles = chain_roles(root, &leaves);
    let tree: Vec<u32> = std::iter::once(pid)
        .chain(roles.iter().map(|(_, pid)| *pid))
        .collect();
    assert_eq!(
        alive_pids(&tree),
        tree,
        "every pid of the tree must be live before the stop"
    );
    if matches!(during, During::Freeze) {
        // tree[1] is the inner gateway's pid; its leaves and their children follow.
        freeze_before_the_stop(root, tree[1], &tree[2..]).await;
    }
    // Started before the EOF, where this outer's stop begins, so no exit is missed.
    #[cfg(target_os = "linux")]
    let watch = matches!(during, During::Watch).then(|| measure::Watch::start(&roles));
    // EOF installs the hurry listener before logging this message. The busy
    // calls keep teardown pending until the subsequent SIGTERM cuts it short.
    drop(stdin);
    let eof_by = Instant::now() + READY_BOUND;
    while !logs(root).contains("stdio: EOF reached, shutting down") {
        assert!(
            Instant::now() < eof_by,
            "outer never saw EOF\n{}",
            logs(root)
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // On the watcher's clock, taken just before the second signal.
    #[cfg(target_os = "linux")]
    let signalled_mono_ns = measure::now_ns();
    let hurried_at = Instant::now();
    sigterm(pid);
    // Observation time, not a watchdog: the outer kills at ~300 ms; allow
    // another 2 s for scheduling and exit, not the 6 s reap reserve.
    tokio::time::sleep_until(hurried_at + Duration::from_millis(2300)).await;
    assert!(
        logs(root).contains("shutdown hurried by a signal"),
        "outer did not hurry\n{}",
        logs(root)
    );
    let alive = alive_pids(&tree);
    assert!(
        alive.is_empty(),
        "chain processes survived the outer's hurry kill window: {alive:?}; all pids: {tree:?}\n{}",
        logs(root)
    );
    #[cfg(target_os = "linux")]
    if let Some(watch) = watch {
        watch
            .report(measure::Path::Hurried, CHAIN_PARENT_STOP, signalled_mono_ns)
            .await;
    }
    tokio::time::timeout(Duration::from_secs(10), reaped.child_mut().wait())
        .await
        .expect("outer exit deadline")
        .expect("outer exit");
    reaped.reap().await;
    std::mem::forget(cleanup);
}

/// One measured hurried stop for the margin harness: the stdio outer's EOF, then its second
/// signal, with the same MEASURE line as the normal path's (path "hurried"). The hurried kill
/// comes `HURRY_WINDOW` after the signal, so these runs size nothing: they are a sweep check.
#[cfg(target_os = "linux")]
#[ignore = "a measurement for the margin harness, not a CI row"]
#[tokio::test]
async fn measure_one_hurried_nested_stop_for_the_margin() {
    two_level_hurried_stop(During::Watch).await;
}

/// A SIGTERM to a stdio-mode gateway (what systemd or docker stop sends) leaves no
/// backend running once the gateway has exited, even a backend that ignores EOF
/// and SIGTERM and has a call in flight. Red if the gateway's teardown stops killing
/// what its backends' graceful stop left.
#[tokio::test]
async fn a_sigterm_to_a_stdio_gateway_leaves_no_backend_running() {
    let temp = tempfile::tempdir().expect("temp root");
    let root = temp.path().to_path_buf();
    let root = root.as_path();
    let config = write_inner_config(root, &["leaf"], Duration::from_secs(8));
    let log = std::fs::File::create(root.join("gateway.log")).expect("log");
    let child = tokio::process::Command::from(gateway_bin::command(
        &root.join("home"),
        gateway_bin::Inherit::Environment,
    ))
    .env("MCP_GATEWAY_CONFIG_DIR", root.join("gateway-state"))
    .current_dir(root)
    .arg("--config")
    .arg(config)
    .args(["serve", "--stdio"])
    .stdin(Stdio::piped())
    .stdout(Stdio::from(log.try_clone().expect("log handle")))
    .stderr(Stdio::from(log))
    .process_group(0)
    .kill_on_drop(true)
    .spawn() // spawn-check: waits for exit: the SIGTERM under test, then a bounded child wait; Reaped reaps after; KillGroup covers panic
    .expect("gateway");
    let mut reaped = gateway_bin::Reaped::new(child);
    let pid = reaped.child_mut().id().expect("pid");
    let cleanup = KillGroup {
        pid,
        root: root.into(),
    };
    let mut stdin = reaped.child_mut().stdin.take().expect("stdin");
    for message in [
        initialize(),
        json!({"jsonrpc":"2.0", "method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{
            "name":"gateway_invoke", "arguments":{"server":"leaf", "tool":"hold", "arguments":{}}
        }}),
    ] {
        stdin
            .write_all(format!("{message}\n").as_bytes())
            .await
            .expect("write stdio");
    }
    let ready_by = Instant::now() + READY_BOUND;
    while !root.join("called-leaf").exists() {
        assert!(
            Instant::now() < ready_by,
            "hold never started\n{}",
            logs(root)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let leaf = read_pid(root, "leaf-leaf.pid");
    let grandchild = read_pid(root, "leaf-leaf.grandchild.pid");
    assert!(
        pids::alive(leaf) && pids::alive(grandchild),
        "leaf and its grandchild must be live at stop\n{}",
        logs(root)
    );
    let deadline = Instant::now() + STDIO_SIGTERM_EXIT_BOUND;
    sigterm(pid);
    tokio::time::timeout_at(deadline, reaped.child_mut().wait())
        .await
        .unwrap_or_else(|_| panic!("gateway exit deadline\n{}", logs(root)))
        .expect("gateway exit");
    while pids::alive(leaf) || pids::alive(grandchild) {
        assert!(
            Instant::now() < deadline,
            "leaf {leaf} or its grandchild {grandchild} still running after gateway exited\n{}",
            logs(root)
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Safety net only: the gateway has already exited, so this sends no signal.
    reaped.reap().await;
    std::mem::forget(cleanup);
    drop(stdin);
}
