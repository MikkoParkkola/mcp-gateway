// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The helper's npm fetch step (ADR-027 step 6): what the fetch command runs
//! with. Its environment is cleared and holds exactly these variables, so no
//! host proxy, `NODE_OPTIONS` or npm configuration reaches it.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "the npm fetch step, a later commit, runs it")
)]

use super::mounts::PREVIEW_CONFIG;

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
    out: std::thread::JoinHandle<std::io::Result<Vec<u8>>>,
}

/// Start draining `stdout` and `stderr`, each to its last 64 KiB.
pub(super) fn drain(
    stdout: std::process::ChildStdout,
    stderr: std::process::ChildStderr,
) -> Drains {
    let out = std::thread::spawn(move || {
        let (mut stdout, mut stderr) = (stdout, stderr);
        let _ = crate::preview_sandbox::fetch_output::read_tail(&mut stdout)?;
        crate::preview_sandbox::fetch_output::read_tail(&mut stderr)
    });
    Drains { out }
}

impl Drains {
    /// Both tails, stdout's then stderr's; a failed read leaves that tail empty.
    pub(super) fn join(self) -> (Vec<u8>, Vec<u8>) {
        let err = self
            .out
            .join()
            .ok()
            .and_then(Result::ok)
            .unwrap_or_default();
        (Vec::new(), err)
    }
}

/// What the run phase runs after an npm fetch.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Run {
    /// The file the drop step execs.
    pub(super) program: String,
    /// `argv[0]` (the bin) and the server's own arguments.
    pub(super) argv: Vec<String>,
    /// node's directory, then the install's bin directory.
    pub(super) path: String,
}

/// The run after an npm fetch of `spec` installed under `home`: the
/// package's own bin (`npm_bin` confines it to the package's directory),
/// exec'd directly with `run_args`, and PATH holding node's directory
/// `node_dir` and the install's `.bin`, never the plan's own program or PATH.
pub(super) fn npm_run(
    home: &std::path::Path,
    spec: &str,
    run_args: &[String],
    node_dir: &str,
) -> Result<Run, crate::preview_sandbox::Refusal> {
    let _ = (home, spec, run_args, node_dir);
    Err(crate::preview_sandbox::Refusal::Step(
        "the run after a fetch is not built yet".into(),
    ))
}

#[cfg(test)]
#[path = "fetch_step_tests.rs"]
mod tests;
