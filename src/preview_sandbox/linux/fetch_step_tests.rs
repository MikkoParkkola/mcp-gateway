// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the helper's npm fetch step (R-env).

use super::npm_env;

/// Kills "a variable is added, dropped or changed": the npm environment is
/// exactly this list, the credential and relay port substituted.
#[test]
fn the_npm_environment_is_exactly_the_designed_list() {
    let mut got = npm_env("c0ffee", 41_234, "/usr/lib/node/bin:/usr/lib/npm/bin");
    got.sort();
    let proxy = "http://x:c0ffee@127.0.0.1:41234";
    let ca = "/etc/mcp-gateway-preview/ca.pem";
    let empty = "/etc/mcp-gateway-preview/empty.npmrc";
    let mut want: Vec<(String, String)> = [
        ("PATH", "/usr/lib/node/bin:/usr/lib/npm/bin"),
        ("HOME", "/preview-home"),
        ("TMPDIR", "/preview-home"),
        ("HTTPS_PROXY", proxy),
        ("HTTP_PROXY", proxy),
        ("npm_config_https_proxy", proxy),
        ("npm_config_proxy", proxy),
        ("NO_PROXY", ""),
        ("npm_config_ignore_scripts", "true"),
        ("npm_config_registry", "https://registry.npmjs.org/"),
        ("npm_config_git", "/nonexistent/git"),
        ("npm_config_audit", "false"),
        ("npm_config_fund", "false"),
        ("npm_config_update_notifier", "false"),
        ("npm_config_cafile", ca),
        ("npm_config_strict_ssl", "true"),
        ("npm_config_userconfig", empty),
        ("npm_config_globalconfig", empty),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
    .collect();
    want.sort();
    assert_eq!(got, want);
}

/// Kills "the pipes are drained one after the other": the child fills
/// stderr first, so a drain that waits on stdout first deadlocks with it.
/// Both tails come back (lines, so the tail keeps whole lines just under the
/// 64 KiB cap) and the child exits.
#[test]
fn both_pipes_drain_at_once() {
    use std::process::{Command, Stdio};
    use std::time::Duration;
    let mut child = Command::new("/bin/sh")
        .args([
            "-c",
            "yes 0123456789abcdef | head -c 1048576 >&2; yes 0123456789abcdef | head -c 1048576",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let drains = super::drain(
        child.stdout.take().expect("stdout"),
        child.stderr.take().expect("stderr"),
    );
    let pid = child.id();
    let (sent, done) = std::sync::mpsc::channel();
    std::thread::spawn(move || sent.send((child.wait(), drains.join())));
    let Ok((status, (out, err))) = done.recv_timeout(Duration::from_secs(30)) else {
        // Unstick the deadlocked child so the row fails instead of hanging.
        let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
        panic!("the drains deadlocked with the child");
    };
    assert!(status.expect("wait").success());
    let cap = crate::preview_sandbox::fetch_output::TAIL_BYTES;
    // Each tail starts at a line boundary: within one 17-byte line of the cap.
    for tail in [&out, &err] {
        assert!(tail.len() <= cap && tail.len() > cap - 17, "{}", tail.len());
    }
}

/// Kills "the run keeps the plan's program or PATH" and "the spec's version
/// stays in the package name": a scoped, version-pinned spec runs the bin
/// named after the package, with the server's arguments, and PATH is node's
/// directory then the install's `.bin`, exactly.
#[test]
fn the_run_after_a_fetch_is_the_packages_bin() {
    let home = tempfile::tempdir().expect("home");
    let package = home.path().join("pkg/node_modules/@s/pkg");
    std::fs::create_dir_all(package.join("bin")).expect("dirs");
    std::fs::write(
        package.join("package.json"),
        br#"{"name":"@s/pkg","bin":{"pkg":"bin/cli.js","other":"bin/o.js"}}"#,
    )
    .expect("manifest");
    std::fs::write(package.join("bin/cli.js"), b"#!/usr/bin/env node\n").expect("bin");
    std::fs::write(package.join("bin/o.js"), b"#!/usr/bin/env node\n").expect("other");
    let run = super::npm_run(
        home.path(),
        "@s/pkg@1.2.3",
        &["--flag".into()],
        "/opt/node/bin",
    )
    .expect("run");
    let bin = package
        .join("bin/cli.js")
        .canonicalize()
        .expect("canonical");
    let bin = bin.to_str().expect("utf-8").to_owned();
    let dot_bin = home.path().join("pkg/node_modules/.bin");
    assert_eq!(
        run,
        super::Run {
            program: bin.clone(),
            argv: vec![bin, "--flag".into()],
            path: format!("/opt/node/bin:{}", dot_bin.display()),
        }
    );
}
