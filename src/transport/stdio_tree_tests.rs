// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8895: a stdio backend owns its process tree. It leads its own process
//! group, so a stop sent to the gateway's group (tini -g, a terminal's ^C)
//! does not reach it before the gateway drains, and ending the backend ends
//! every process it started, not only the launcher.
//!
//! A `#[path]` child of the transport, like `stdio_tests.rs`, so `use super::*`
//! resolves the same items.

use super::*;
use std::time::Duration;

/// Starts `sh server.sh`: answers `initialize`, reads the notification, then
/// runs `after`. The workspace is the script's cwd, for pid files.
async fn started(after: &str) -> (tempfile::TempDir, Arc<StdioTransport>) {
    let workspace = tempfile::tempdir().expect("workspace");
    let script = r#"id_of() { printf '%s' "$1" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p'; }
read -r request
printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"PROTO","capabilities":{}}}\n' "$(id_of "$request")"
read -r initialized
AFTER
"#
    .replace("PROTO", PROTOCOL_VERSION)
    .replace("AFTER", after);
    std::fs::write(workspace.path().join("server.sh"), script).expect("write server");
    let transport = StdioTransport::new(
        "sh server.sh",
        HashMap::new(),
        Some(workspace.path().to_string_lossy().into_owned()),
        Duration::from_secs(30),
        None,
    );
    transport.start().await.expect("handshake");
    (workspace, transport)
}

/// A descendant of the launcher that outlives nothing on its own: it sleeps
/// for a minute, its pid in `d.pid`, while the launcher waits on stdin.
const DESCENDANT: &str =
    "sleep 60 </dev/null >/dev/null 2>&1 & echo $! > d.pid\nwhile IFS= read -r l; do :; done";

/// The descendant's pid, once the script has written it.
async fn descendant(dir: &Path) -> u32 {
    let file = dir.join("d.pid");
    for _ in 0..250 {
        if let Some(pid) = std::fs::read_to_string(&file)
            .ok()
            .and_then(|text| text.trim().parse().ok())
        {
            return pid;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the descendant never wrote its pid");
}

/// `ps -o pgid=` for `pid`, on Linux and macOS alike; `None` once it is gone.
fn pgid_of(pid: u32) -> Option<u32> {
    let out = std::process::Command::new("ps")
        .args(["-o", "pgid=", "-p", &pid.to_string()])
        .output()
        .expect("ps");
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

/// Whether `pid` is still a live process (not gone, not a zombie).
fn alive(pid: u32) -> bool {
    let out = std::process::Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .expect("ps");
    let stat = String::from_utf8_lossy(&out.stdout);
    let stat = stat.trim();
    !stat.is_empty() && !stat.starts_with('Z')
}

/// Wait for `pid` to end, failing the row if it is still alive after the
/// bound. The bound covers the reaper's grace and settle, with room for a
/// loaded host.
async fn gone(pid: u32, what: &str) {
    for _ in 0..500 {
        if !alive(pid) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("{what}: pid {pid} is still alive");
}

/// Kills a descendant a failing row left behind, so a red run leaks nothing.
struct Reap(u32);

impl Drop for Reap {
    fn drop(&mut self) {
        let _ = std::process::Command::new("kill")
            .args(["-9", &self.0.to_string()])
            .status();
    }
}

/// STOP.1 premise: the backend is not in the gateway's process group, so a
/// signal to that group (tini -g, ^C) does not reach it before the drain.
#[tokio::test]
async fn a_backend_leads_its_own_process_group() {
    let (w, t) = started(DESCENDANT).await;
    let child = descendant(w.path()).await;
    let _reap = Reap(child);
    let gateway = pgid_of(std::process::id()).expect("gateway pgid");
    let backend = pgid_of(child).expect("descendant pgid");
    assert_ne!(
        backend, gateway,
        "the backend's tree shares the gateway's process group"
    );
    t.close().await.expect("close");
}

/// STOP.1: `close` ends the launcher's descendants, not only the launcher.
#[tokio::test]
async fn close_ends_the_backends_descendants() {
    let (w, t) = started(DESCENDANT).await;
    let child = descendant(w.path()).await;
    let _reap = Reap(child);
    t.close().await.expect("close");
    gone(child, "close left the backend's descendant running").await;
}

/// The Drop path: a transport dropped without `close` (a cancelled
/// `run_stdio`) still ends the whole tree.
#[tokio::test]
async fn a_dropped_transport_ends_the_backends_descendants() {
    let (w, t) = started(DESCENDANT).await;
    let child = descendant(w.path()).await;
    let _reap = Reap(child);
    drop(t);
    gone(
        child,
        "a dropped transport left the backend's descendant running",
    )
    .await;
}
