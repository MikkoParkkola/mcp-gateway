// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! 2b-1: the read-only CA snapshot a fetching preview gets.
#![cfg(target_os = "linux")]

use super::{fetching, finish};
use mcp_gateway::preview_sandbox::Started;

/// 2b-1, kills "the CA files are missing or writable in the root": from the
/// run child, `ca.pem` is there and cannot be written, removed or renamed,
/// `empty.npmrc` and `empty-certs` are there and empty, and nothing can be
/// added beside them.
#[tokio::test]
async fn ca_files_are_read_only_from_the_run_child() {
    require_private_home!();
    let script = "d=/etc/mcp-gateway-preview
        test -f $d/ca.pem && echo ca-present
        (echo x > $d/ca.pem) 2>/dev/null && echo ca-writable
        (rm -f $d/ca.pem) 2>/dev/null; test -f $d/ca.pem && echo ca-kept
        (mv $d/ca.pem $d/moved) 2>/dev/null && echo ca-moved
        test -f $d/empty.npmrc && echo npmrc-present
        test -s $d/empty.npmrc || echo npmrc-empty
        test -d $d/empty-certs && [ -z \"$(ls -A $d/empty-certs)\" ] && echo certs-empty
        (touch $d/new) 2>/dev/null && echo dir-writable
        true";
    let Some(Started { mut child, .. }) = fetching(script).await else {
        return;
    };
    drop(child.stdin.take());
    let out = finish(child).await;
    assert!(out.status.success(), "{}", out.stderr);
    let seen: Vec<&str> = out.stdout.lines().collect();
    assert_eq!(
        seen,
        [
            "ca-present",
            "ca-kept",
            "npmrc-present",
            "npmrc-empty",
            "certs-empty"
        ],
        "{}",
        out.stdout
    );
}

/// 2b-1: the CA snapshot sits under host `/tmp` (the rows pass no
/// `XDG_RUNTIME_DIR`), which staging covers, so "bind by pathname after
/// staging" fails; this fails loudly if the temp dir is not `/tmp`.
#[tokio::test]
async fn the_ca_snapshot_sits_under_tmp_on_this_host() {
    require_private_home!();
    let Some(Started { mut child, .. }) = fetching("sleep 30").await else {
        return;
    };
    let unshare = child.id().expect("unshare is running");
    let cmdline = std::fs::read(format!("/proc/{unshare}/cmdline")).expect("cmdline");
    let text = String::from_utf8_lossy(&cmdline).into_owned();
    let _ = child.kill().await;
    assert!(text.contains("\"ca\":\"/tmp/"), "{text}");
}
