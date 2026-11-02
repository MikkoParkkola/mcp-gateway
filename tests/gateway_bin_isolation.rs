// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7637: a gateway started through `gateway_bin` with nothing inherited (the
//! case of every spawner that used to call `env_clear`) still resolves its home
//! to the fixture: the default task store it opens at startup is created there.
//! Before the helper, a spawner that cleared the environment and forgot one
//! isolation variable left the child to find the developer's real home.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::process::Stdio;
use std::time::{Duration, Instant};

#[test]
fn a_cleared_environment_still_opens_the_store_under_the_fixture_home() {
    let fixture = tempfile::tempdir().expect("a fixture home");
    let store = fixture.path().join(".mcp-gateway").join("tasks");
    let mut child = gateway_bin::command(fixture.path(), gateway_bin::Inherit::Nothing)
        .args(["serve", "--stdio"])
        .current_dir(fixture.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn() // spawn-check: waits for exit: the row reaps it before its fixture drops
        .expect("the gateway starts");

    // Bounded only as a hang guard: the store appears as the child starts.
    let deadline = Instant::now() + Duration::from_secs(60);
    while !store.is_dir() && Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("child status") {
            panic!("the gateway exited ({status}) before opening its store");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let opened = store.is_dir();

    drop(child.stdin.take());
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().expect("child status").is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.wait();
    assert!(
        opened,
        "the default task store was not created under the fixture home {}",
        fixture.path().display()
    );
}

/// `gateway_bin::Reaped`: a test's gateway is stopped, and every process it
/// started is gone, before the folders it writes into are removed.
#[cfg(unix)]
mod reaped {
    use super::gateway_bin::Reaped;
    use std::path::Path;
    use std::process::Stdio;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;
    use tokio::io::AsyncBufReadExt as _;

    const BOUND: Duration = Duration::from_secs(30);

    /// One python process: on SIGTERM it marks `term` in `side`, waits up to
    /// 30 s for `release` there, marks `exit` and exits 0. `ignore` makes it
    /// ignore SIGTERM instead; `exit` makes it exit right after `ready`.
    const CHILD: &str = r#"import os, signal, sys, time
side = sys.argv[1]
def mark(name):
    open(os.path.join(side, name), "w").close()
def term(*_):
    mark("term")
    deadline = time.time() + 30
    while not os.path.exists(os.path.join(side, "release")) and time.time() < deadline:
        time.sleep(0.01)
    mark("exit")
    os._exit(0)
signal.signal(signal.SIGTERM, signal.SIG_IGN if sys.argv[2] == "ignore" else term)
print("ready", flush=True)
if sys.argv[2] == "exit":
    os._exit(0)
while True:
    time.sleep(1)
"#;

    /// A started child that has installed its handler, owning `folder`.
    /// `mode` is `term`, `ignore` or `exit` (see [`CHILD`]). The child is
    /// owned before the ready wait, so a failed handshake leaks no process.
    async fn started(side: &Path, folder: tempfile::TempDir, mode: &str) -> (Reaped, u32) {
        let child = tokio::process::Command::new("python3")
            .arg("-c")
            .arg(CHILD)
            .arg(side)
            .arg(mode)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn() // spawn-check: not the gateway: the rows' own child
            .expect("python3 starts");
        let mut reaped = Reaped::new(child);
        reaped.owning(folder);
        let pid = reaped.child_mut().id().expect("a live child");
        let stdout = reaped.child_mut().stdout.take().expect("piped stdout");
        let mut lines = tokio::io::BufReader::new(stdout).lines();
        let ready = tokio::time::timeout(BOUND, lines.next_line()).await;
        assert!(
            matches!(&ready, Ok(Ok(Some(line))) if line == "ready"),
            "{ready:?}"
        );
        (reaped, pid)
    }

    async fn appears(path: &Path) -> bool {
        let deadline = tokio::time::Instant::now() + BOUND;
        while !path.exists() {
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        true
    }

    /// Whether `pid` is a live process (not gone, not a zombie).
    fn alive(pid: u32) -> bool {
        let out = std::process::Command::new("ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()
            .expect("ps");
        let stat = String::from_utf8_lossy(&out.stdout);
        let stat = stat.trim();
        !stat.is_empty() && !stat.starts_with('Z')
    }

    /// SIGKILLs a pid when the row ends, so a red run leaks no process.
    struct KillPid(u32);

    impl Drop for KillPid {
        fn drop(&mut self) {
            let _ = std::process::Command::new("kill")
                .args(["-KILL", &self.0.to_string()])
                .stderr(Stdio::null())
                .status();
        }
    }

    /// On a current-thread runtime: the stop drains the child with SIGTERM,
    /// keeps the folder while the child runs, keeps the runtime serving, and
    /// removes the folder only after the child exited.
    #[tokio::test]
    async fn a_stop_drains_the_child_before_its_folder_goes() {
        let side = tempfile::tempdir().expect("a side folder");
        let folder = tempfile::tempdir().expect("an owned folder");
        let owned = folder.path().to_path_buf();
        let (reaped, pid) = started(side.path(), folder, "term").await;
        let _kill = KillPid(pid);
        let ticks = Arc::new(AtomicU64::new(0));
        let ticker = tokio::spawn({
            let ticks = Arc::clone(&ticks);
            async move {
                loop {
                    ticks.fetch_add(1, Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            }
        });
        let stop = tokio::spawn(reaped.stop());

        assert!(
            appears(&side.path().join("term")).await,
            "the child got no SIGTERM"
        );
        // A stop that blocked the runtime would let this row run again only
        // after the child exited, so the ticker moving while `exit` is still
        // absent shows the runtime kept serving.
        let before = ticks.load(Ordering::Relaxed);
        while ticks.load(Ordering::Relaxed) <= before {
            tokio::task::yield_now().await;
        }
        assert!(
            !side.path().join("exit").exists(),
            "the runtime stalled while the stop waited"
        );
        assert!(owned.is_dir(), "the folder went before the child exited");

        std::fs::write(side.path().join("release"), "").expect("release");
        let status = tokio::time::timeout(BOUND, stop)
            .await
            .expect("the stop ends")
            .expect("the stop task");
        ticker.abort();
        assert!(status.success(), "{status}");
        assert!(!owned.exists(), "a drained stop removes the folder");
        assert!(!alive(pid), "the child was reaped");
    }

    /// A child that died by a signal before the stop leaves its folder in
    /// place: what it started may still be writing.
    #[tokio::test]
    async fn a_signal_death_keeps_the_folder() {
        let side = tempfile::tempdir().expect("a side folder");
        let folder = tempfile::tempdir().expect("an owned folder");
        let owned = folder.path().to_path_buf();
        let (mut reaped, pid) = started(side.path(), folder, "term").await;
        let _kill = KillPid(pid);
        reaped.child_mut().start_kill().expect("SIGKILL");
        let status = tokio::time::timeout(BOUND, reaped.stop())
            .await
            .expect("the stop ends");
        let kept_on_disk = owned.is_dir();
        let _ = std::fs::remove_dir_all(&owned);
        assert!(!status.success(), "{status}");
        assert!(
            kept_on_disk,
            "a signal death must not authorise removing the folder"
        );
    }

    /// A reap then a stop, as a restart helper does: the stop keeps the first
    /// reap's drained exit and removes the folder.
    #[tokio::test]
    async fn a_stop_after_a_reap_keeps_its_drained_exit() {
        let side = tempfile::tempdir().expect("a side folder");
        std::fs::write(side.path().join("release"), "").expect("release");
        let folder = tempfile::tempdir().expect("an owned folder");
        let owned = folder.path().to_path_buf();
        let (mut reaped, pid) = started(side.path(), folder, "term").await;
        let _kill = KillPid(pid);
        let first = tokio::time::timeout(BOUND, reaped.reap())
            .await
            .expect("the reap ends");
        let status = tokio::time::timeout(BOUND, reaped.stop())
            .await
            .expect("the stop ends");
        let left = owned.exists();
        let _ = std::fs::remove_dir_all(&owned);
        assert!(first.success() && status.success(), "{first} {status}");
        assert!(
            !left,
            "a drained reap followed by a stop removes the folder"
        );
    }

    /// A child that exited by itself before the stop keeps its folder: what it
    /// started was never told to stop.
    #[tokio::test]
    async fn an_exit_before_the_stop_keeps_the_folder() {
        let side = tempfile::tempdir().expect("a side folder");
        let folder = tempfile::tempdir().expect("an owned folder");
        let owned = folder.path().to_path_buf();
        let (reaped, pid) = started(side.path(), folder, "exit").await;
        let _kill = KillPid(pid);
        let gone_by = tokio::time::Instant::now() + BOUND;
        while alive(pid) && tokio::time::Instant::now() < gone_by {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let status = tokio::time::timeout(BOUND, reaped.stop())
            .await
            .expect("the stop ends");
        let kept_on_disk = owned.is_dir();
        let _ = std::fs::remove_dir_all(&owned);
        assert!(status.success(), "{status}");
        assert!(
            kept_on_disk,
            "an exit the stop did not ask for must not authorise removing the folder"
        );
    }

    /// A child that ignores SIGTERM: the reap fails the test after its bound,
    /// the child is killed and reaped, and its folder is kept.
    #[tokio::test]
    async fn a_reap_past_its_bound_fails_and_keeps_the_folder() {
        let side = tempfile::tempdir().expect("a side folder");
        let folder = tempfile::tempdir().expect("an owned folder");
        let owned = folder.path().to_path_buf();
        let (mut reaped, pid) = started(side.path(), folder, "ignore").await;
        let _kill = KillPid(pid);
        let reap = tokio::spawn(async move {
            reaped.reap_within(Duration::from_millis(500)).await;
        });
        let joined = tokio::time::timeout(BOUND, reap)
            .await
            .expect("the reap ends");
        let kept_on_disk = owned.is_dir();
        let _ = std::fs::remove_dir_all(&owned);
        assert!(
            joined.is_err_and(|e| e.is_panic()),
            "a reap past its bound must fail"
        );
        assert!(!alive(pid), "the child was killed and reaped");
        assert!(kept_on_disk, "an undrained child's folder is kept");
    }

    /// A stop dropped before it finished: the owner kills and reaps the child
    /// and keeps the folder.
    #[tokio::test]
    async fn a_cancelled_stop_reaps_and_keeps_the_folder() {
        let side = tempfile::tempdir().expect("a side folder");
        let folder = tempfile::tempdir().expect("an owned folder");
        let owned = folder.path().to_path_buf();
        let (reaped, pid) = started(side.path(), folder, "term").await;
        let _kill = KillPid(pid);
        let stop = tokio::spawn(reaped.stop());
        let termed = appears(&side.path().join("term")).await;
        stop.abort();
        let _ = stop.await;
        let kept_on_disk = owned.is_dir();
        let _ = std::fs::remove_dir_all(&owned);
        assert!(termed, "the child got no SIGTERM");
        assert!(!alive(pid), "the child was killed and reaped");
        assert!(kept_on_disk, "a cancelled stop keeps the folder");
    }

    /// A stdio backend that starts a descendant ignoring stdin EOF (its pid
    /// in `d.pid`), so only the gateway's own tree stop ends it.
    const BACKEND: &str = r#"import json, os, subprocess, sys
grandchild = subprocess.Popen(["sleep", "600"], stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
with open("d.pid.tmp", "w") as f:
    f.write(str(grandchild.pid))
os.replace("d.pid.tmp", "d.pid")
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    if msg.get("method") == "initialize":
        result = {"protocolVersion": msg["params"]["protocolVersion"], "capabilities": {"tools": {}},
                  "serverInfo": {"name": "tree", "version": "1"}}
    elif msg.get("method") == "tools/list":
        result = {"tools": []}
    else:
        result = {}
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
"#;

    /// A gateway's stop ends what the gateway started, not only the gateway.
    #[tokio::test]
    async fn a_stop_ends_the_gateways_backend_tree() {
        let folder = tempfile::tempdir().expect("a gateway folder");
        let root = folder.path().to_path_buf();
        std::fs::write(root.join("backend.py"), BACKEND).expect("backend");
        let config = format!(
            "server:\n  host: 127.0.0.1\n  port: 0\n  shutdown_timeout: 20s\n\
             tasks:\n  store_dir: {tasks}\n\
             backends:\n  tree:\n    command: python3 -u backend.py\n    cwd: {root}\n",
            tasks = root.join("tasks").display(),
            root = root.display()
        );
        // The gateway refuses a config other users can read.
        mcp_gateway::gateway::test_helpers::write_owner_only(root.join("gateway.yaml"), config)
            .expect("config");
        let log = std::fs::File::create(root.join("gateway.log")).expect("log");
        let mut reaped = Reaped::new(
            tokio::process::Command::from(super::gateway_bin::command(
                &root.join("home"),
                super::gateway_bin::Inherit::Environment,
            ))
            .env("MCP_GATEWAY_CONFIG_DIR", root.join("state"))
            .current_dir(&root)
            .args(["-c", "gateway.yaml", "serve"])
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().expect("log handle")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("the gateway starts"),
        );
        let logs = || std::fs::read_to_string(root.join("gateway.log")).unwrap_or_default();
        reaped.owning(folder);
        let _kill_gateway = KillPid(reaped.child_mut().id().expect("a live gateway"));

        assert!(
            appears(&root.join("d.pid")).await,
            "the backend never started\n{}",
            logs()
        );
        let grandchild: u32 = std::fs::read_to_string(root.join("d.pid"))
            .expect("the descendant's pid")
            .trim()
            .parse()
            .expect("a pid");
        let _kill = KillPid(grandchild);
        // The stop must land after the gateway installed its shutdown
        // handler, which it has once it answers /livez.
        let live_by = tokio::time::Instant::now() + BOUND;
        while !super::gateway_bin::logged_port(&root.join("gateway.log"))
            .is_some_and(super::gateway_bin::answers_livez)
        {
            assert!(
                tokio::time::Instant::now() < live_by,
                "the gateway never answered /livez\n{}",
                logs()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let status = tokio::time::timeout(Duration::from_secs(120), reaped.stop())
            .await
            .expect("the stop ends");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while alive(grandchild) && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let survived = alive(grandchild);
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            status.success() && !survived,
            "the gateway drains on SIGTERM ({status}) and its backend's descendant \
             {grandchild} is gone (still alive: {survived})"
        );
    }
}
