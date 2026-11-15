// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The helper's npm fetch step (ADR-027 step 6): what the fetch command runs
//! with. Its environment is cleared and holds exactly these variables, so no
//! host proxy, `NODE_OPTIONS` or npm configuration reaches it.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "the npm fetch step, a later commit, runs it")
)]

use std::thread::JoinHandle;

use super::mounts::PREVIEW_CONFIG;
use crate::preview_sandbox::fetch_output::read_tail;

/// The npm fetch command's whole environment: the D5 list (proxy through the
/// relay with the fetch credential, no scripts, no git, the public registry)
/// plus the CA amendment's trust variables (the snapshot as `cafile`, strict
/// TLS, and an empty npmrc as both the user and the global config). `path` is
/// node's directory, then npm's.
pub(super) fn npm_env(credential: &str, port: u16, path: &str) -> Vec<(String, String)> {
    let proxy = format!("http://x:{credential}@127.0.0.1:{port}");
    let home = super::plan::HOME;
    let ca = format!("{PREVIEW_CONFIG}/ca.pem");
    let empty = format!("{PREVIEW_CONFIG}/empty.npmrc");
    [
        ("PATH", path),
        ("HOME", home),
        ("TMPDIR", home),
        ("HTTPS_PROXY", proxy.as_str()),
        ("HTTP_PROXY", proxy.as_str()),
        ("npm_config_https_proxy", proxy.as_str()),
        ("npm_config_proxy", proxy.as_str()),
        ("NO_PROXY", ""),
        ("npm_config_ignore_scripts", "true"),
        ("npm_config_registry", "https://registry.npmjs.org/"),
        ("npm_config_git", "/nonexistent/git"),
        ("npm_config_audit", "false"),
        ("npm_config_fund", "false"),
        ("npm_config_update_notifier", "false"),
        // npm's cafile replaces node's built-in roots (npm >= 9, the probe's floor).
        ("npm_config_cafile", ca.as_str()),
        ("npm_config_strict_ssl", "true"),
        ("npm_config_userconfig", empty.as_str()),
        ("npm_config_globalconfig", empty.as_str()),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
    .collect()
}

/// The fetch command's two output pipes, each drained on its own thread so a
/// child writing a lot to one cannot block while the other is read. Joined
/// only after the sweep, when every holder of either pipe is gone.
pub(super) struct Drains {
    out: JoinHandle<std::io::Result<Vec<u8>>>,
    err: JoinHandle<std::io::Result<Vec<u8>>>,
}

/// Start draining `stdout` and `stderr`, each on its own thread to its last
/// 64 KiB.
pub(super) fn drain(
    mut stdout: std::process::ChildStdout,
    mut stderr: std::process::ChildStderr,
) -> Drains {
    let out = std::thread::spawn(move || read_tail(&mut stdout));
    let err = std::thread::spawn(move || read_tail(&mut stderr));
    Drains { out, err }
}

impl Drains {
    /// Both tails, stdout's then stderr's; a failed read leaves that tail empty.
    pub(super) fn join(self) -> (Vec<u8>, Vec<u8>) {
        let tail = |handle: JoinHandle<std::io::Result<Vec<u8>>>| {
            handle.join().ok().and_then(Result::ok).unwrap_or_default()
        };
        (tail(self.out), tail(self.err))
    }
}

#[cfg(test)]
#[path = "fetch_step_tests.rs"]
mod tests;
