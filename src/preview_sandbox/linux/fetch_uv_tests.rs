// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the helper's uv fetch step that need no sandbox (its test plan,
//! U-wrapper and U-both).

use std::os::unix::fs::PermissionsExt as _;

use super::super::plan::{FetchPaths, NpmFetch, UvFetch};
use super::{WRAPPER, write_wrapper};
use crate::preview_sandbox::control_msg::FetchStep;

/// U-wrapper, kills m-late-setup: a home the wrapper cannot be written in
/// (it lies under a regular file, so ENOTDIR for any euid) fails at setup.
#[test]
fn u_wrapper_a_write_failure_is_setup() {
    let root = tempfile::tempdir().expect("root");
    let file = root.path().join("not-a-dir");
    std::fs::write(&file, "").expect("file");
    let failed =
        write_wrapper(&file.join("home"), "/usr/bin/python3.12").expect_err("the write fails");
    assert_eq!(failed.step, FetchStep::Setup);
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
        control: "/run/x/control.sock".into(),
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
