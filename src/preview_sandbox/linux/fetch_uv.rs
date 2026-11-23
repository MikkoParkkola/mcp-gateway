// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The helper's uv fetch step (the uv fetch design, decisions 3, 6, 7 and 9):
//! uv's install inside the shared fetch frame, every interpreter spawn of the
//! fetch given `-S` through a wrapper, the direct-URL check, then the run of
//! the package's own console script.

use std::os::unix::net::UnixStream;
use std::path::Path;

use super::fetch_step::{FetchError, FetchFailure, Run, frame, run_dropped};
use super::helper::{SetupFailure, step_call};
use super::mounts::PREVIEW_CONFIG;
use super::plan::{self, Limits, UvFetch};
use crate::preview_sandbox::control_msg::{FetchStep, SetupStep};
use crate::preview_sandbox::install::{check_direct_url, uv_entry_point, uv_name, uv_tool_env};

/// The wrapper uv is given as its interpreter, in the preview home.
pub(super) const WRAPPER: &str = ".preview-python";

/// Write `home/.preview-python`, the interpreter uv runs: `python` with
/// `-S`, so no site processing (`.pth`, `sitecustomize`, `usercustomize`)
/// runs while the credential is live. Mode 0555; a failure is the setup's
/// (a file the root needs could not be made), before any `fetch_start`.
pub(super) fn write_wrapper(home: &Path, python: &str) -> Result<(), SetupFailure> {
    use std::os::unix::fs::PermissionsExt as _;
    let path = home.join(WRAPPER);
    let quoted = python.replace('\'', "'\\''");
    step_call(
        SetupStep::Mounting,
        || "writing the wrapper".to_owned(),
        || {
            std::fs::write(&path, format!("#!/bin/sh\nexec '{quoted}' -S \"$@\"\n"))
                // Set after the write, so the gateway's umask cannot narrow it.
                .and_then(|()| {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o555))
                })
        },
    )
}

/// The uv install's whole environment (design 6): the proxy through the
/// relay with the fetch credential, the public index, no builds, no config
/// files, no interpreter downloads, no bytecode, the tool env and cache in
/// the preview home, and only the fetch's CA snapshot trusted. PATH is the
/// interpreter's directory, then uv's.
pub(super) fn uv_env(credential: &str, port: u16, path: &str) -> Vec<(String, String)> {
    let proxy = format!("http://x:{credential}@127.0.0.1:{port}");
    let home = plan::HOME;
    let tools = format!("{home}/uv-tools");
    let tool_bin = format!("{home}/uv-tools/bin");
    let cache = format!("{home}/uv-cache");
    let ca = format!("{PREVIEW_CONFIG}/ca.pem");
    let certs = format!("{PREVIEW_CONFIG}/empty-certs");
    [
        ("PATH", path),
        ("HOME", home),
        ("TMPDIR", home),
        ("HTTPS_PROXY", proxy.as_str()),
        ("HTTP_PROXY", proxy.as_str()),
        ("NO_PROXY", ""),
        ("UV_INDEX_URL", "https://pypi.org/simple"),
        ("UV_NO_BUILD", "1"),
        ("UV_NO_CONFIG", "1"),
        ("UV_PYTHON_DOWNLOADS", "never"),
        // No UV_COMPILE_BYTECODE, whatever its value: uv reads it as its
        // --compile-bytecode option, which with the install's
        // --no-compile-bytecode is a usage error, so every fetch would fail.
        ("UV_TOOL_DIR", tools.as_str()),
        ("UV_TOOL_BIN_DIR", tool_bin.as_str()),
        ("UV_CACHE_DIR", cache.as_str()),
        ("SSL_CERT_FILE", ca.as_str()),
        ("SSL_CERT_DIR", certs.as_str()),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
    .collect()
}

/// The helper's uv fetch step: the wrapper written before the credential,
/// then inside the shared frame uv's one install and the direct-URL check;
/// the run follows only when the fetch and all of the teardown succeeded.
pub(super) fn uv(
    control: &mut UnixStream,
    uv: &UvFetch,
    limits: Limits,
) -> Result<Run, FetchError> {
    let home = Path::new(plan::HOME);
    write_wrapper(home, &uv.python).map_err(FetchError::Setup)?;
    let uv_dir = Path::new(&uv.uv)
        .parent()
        .and_then(Path::to_str)
        .unwrap_or("/");
    frame(control, &uv.ip, |credential, port, deadline| {
        let env = uv_env(credential, port, &format!("{}:{uv_dir}", uv.python_dir));
        let wrapper = format!("{}/{WRAPPER}", plan::HOME);
        let install = [
            "tool",
            "install",
            "--native-tls",
            "--no-build",
            "--no-compile-bytecode",
            "--python",
            wrapper.as_str(),
            uv.spec.as_str(),
        ];
        run_dropped(&uv.uv, "uv", &install, &env, deadline, limits, credential)
            .map_err(FetchFailure::at(FetchStep::UvInstall))?;
        check_direct_url(&uv_tool_env(home, &uv.spec), deadline)
            .map(|_| ())
            .map_err(|r| FetchFailure::at(FetchStep::DirectUrlCheck)(r.to_string()))
    })?;
    uv_run(home, &uv.spec, &uv.run_args, &uv.python_dir)
        .map_err(|r| FetchError::Setup(SetupFailure::new(SetupStep::TargetMissing, r.to_string())))
}

/// The run after a uv fetch of `spec` under `home` (D6): the console script
/// the package's own metadata names, exec'd directly with `run_args`, PATH
/// holding the interpreter's directory then the tool env's `bin`.
pub(super) fn uv_run(
    home: &Path,
    spec: &str,
    run_args: &[String],
    python_dir: &str,
) -> Result<Run, crate::preview_sandbox::Refusal> {
    let env = uv_tool_env(home, spec);
    let script = uv_entry_point(&env, &uv_name(spec))?;
    let program = script.to_str().ok_or_else(|| {
        crate::preview_sandbox::Refusal::Step("the package's entry point is not UTF-8".into())
    })?;
    Ok(Run {
        program: program.to_owned(),
        argv: std::iter::once(program.to_owned())
            .chain(run_args.iter().cloned())
            .collect(),
        path: format!("{python_dir}:{}", env.join("bin").display()),
    })
}

#[cfg(tp4)]
#[cfg(test)]
#[path = "fetch_uv_tests.rs"]
mod tests;
