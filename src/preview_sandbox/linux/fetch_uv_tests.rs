// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the helper's uv fetch step that need no sandbox (its test plan,
//! U-wrapper and U-both).

use std::os::unix::fs::PermissionsExt as _;

use super::super::plan::{FetchPaths, NpmFetch, UvFetch};
use super::{WRAPPER, write_wrapper};
use crate::preview_sandbox::control_msg::SetupStep;

/// U-wrapper, kills m-late-setup: a home the wrapper cannot be written in
/// (it lies under a regular file, so ENOTDIR for any euid) fails as a setup
/// step before any `fetch_start`: the helper's mounting status, not denied.
#[test]
fn u_wrapper_a_write_failure_is_setup() {
    let root = tempfile::tempdir().expect("root");
    let file = root.path().join("not-a-dir");
    std::fs::write(&file, "").expect("file");
    let failed =
        write_wrapper(&file.join("home"), "/usr/bin/python3.12").expect_err("the write fails");
    assert_eq!((failed.step, failed.denied), (SetupStep::Mounting, false));
}

/// U-wrapper, kills m-no-wrapper-flag, m-unquoted-wrapper and m-wrapper-mode:
/// the wrapper execs the interpreter, single-quoted (a quote in its path
/// written as `'\''`), with `-S` before uv's own arguments; mode 0555.
#[test]
fn u_wrapper_execs_the_interpreter_quoted_with_site_off() {
    for (python, line) in [
        (
            "/opt/py/bin/python3.12",
            "exec '/opt/py/bin/python3.12' -S \"$@\"",
        ),
        (
            "/home/a b/it's/bin/python3.12",
            "exec '/home/a b/it'\\''s/bin/python3.12' -S \"$@\"",
        ),
    ] {
        let home = tempfile::tempdir().expect("home");
        write_wrapper(home.path(), python).expect("written");
        let path = home.path().join(WRAPPER);
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            format!("#!/bin/sh\n{line}\n"),
            "{python}"
        );
        assert_eq!(
            std::fs::metadata(&path).expect("meta").permissions().mode() & 0o7777,
            0o555,
            "{python}"
        );
    }
}

fn npm() -> NpmFetch {
    NpmFetch {
        spec: "a".into(),
        run_args: Vec::new(),
        npm: "/usr/bin/npm".into(),
        node_dir: "/usr/bin".into(),
        ip: "/usr/sbin/ip".into(),
        proxy: "/run/x/proxy.sock".into(),
    }
}

fn uv() -> UvFetch {
    UvFetch {
        spec: "a".into(),
        name: "a".into(),
        run_args: Vec::new(),
        uv: "/usr/bin/uv".into(),
        python: "/usr/bin/python3.12".into(),
        python_dir: "/usr/bin".into(),
        ip: "/usr/sbin/ip".into(),
        proxy: "/run/x/proxy.sock".into(),
    }
}

/// U-both (design 4), kills m-both-allowed: a plan naming both an npm and a
/// uv fetch refuses; either alone, or neither, is that fetcher.
#[test]
fn u_both_a_plan_with_npm_and_uv_refuses() {
    let paths = |npm: Option<NpmFetch>, uv: Option<UvFetch>| FetchPaths {
        ca: "/run/x/ca.pem".into(),
        npm,
        uv,
    };
    assert_eq!(
        paths(Some(npm()), Some(uv())).fetcher(),
        Err("checking the plan (it names both an npm and a uv fetch)".to_owned())
    );
    let only_npm = paths(Some(npm()), None);
    assert_eq!(
        only_npm.fetcher(),
        Ok(Some(super::super::plan::Fetcher::Npm(&npm())))
    );
    let only_uv = paths(None, Some(uv()));
    assert_eq!(
        only_uv.fetcher(),
        Ok(Some(super::super::plan::Fetcher::Uv(&uv())))
    );
    assert_eq!(paths(None, None).fetcher(), Ok(None));
}

/// The production text of `file` under `src/preview_sandbox/linux`.
fn linux_source(file: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/preview_sandbox/linux")
        .join(file);
    crate::test_source_text::production_text(&std::fs::read_to_string(path).expect("source"))
}

/// U-uvstep-scan, support for the review-carried m-no-redact: the uv step
/// cannot start or read a process itself, so the shared runner (which
/// redacts the last line) is its only route to a command's output.
#[test]
fn u_uvstep_scan_the_uv_step_runs_commands_only_through_the_runner() {
    let uv_step = linux_source("fetch_uv.rs");
    // Positive controls: the slice is the uv step, and the runner's own
    // text holds what the uv step may not.
    assert!(
        uv_step.contains("FetchStep::UvInstall"),
        "the uv step's text"
    );
    assert!(linux_source("fetch_step.rs").contains("Stdio::piped"));
    for banned in [
        "Command::new",
        "Stdio::piped",
        ".stdout(",
        ".stderr(",
        "last_line(",
        "from_utf8",
    ] {
        assert!(!uv_step.contains(banned), "the uv step holds {banned}");
    }
}

/// U-runner-scan: exactly one production call of `last_line(` in the Linux
/// fetch code, inside `run_dropped` in `fetch_step.rs`.
#[test]
fn u_runner_scan_the_one_redacting_call_sits_in_the_runner() {
    let mut calls = Vec::new();
    for file in ["fetch_step.rs", "fetch_uv.rs", "helper.rs", "mod.rs"] {
        let text = linux_source(file);
        for (at, _) in text.match_indices("last_line(") {
            calls.push((
                file,
                text[..at].rfind("fn ").map(|f| {
                    text[f + 3..]
                        .split('(')
                        .next()
                        .unwrap_or_default()
                        .to_owned()
                }),
            ));
        }
    }
    assert_eq!(
        calls,
        [("fetch_step.rs", Some("run_dropped".to_owned()))],
        "the last_line( calls"
    );
}
