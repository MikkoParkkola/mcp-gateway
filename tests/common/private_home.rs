// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A private gateway home for integration tests that resolve the home
//! in-process, and the child-process protocol their rows share.
//!
//! An integration binary links the library without `cfg(test)`, so its
//! in-process code resolves the home through the debug arm: the test-home
//! override if set, else the account's real home. `require_private_home!()`,
//! the first statement of every such test, refuses to run unless the override
//! names a private directory, so a bare `cargo test` never reads or writes the
//! real home. Harnesses set the override (`scripts/ci/shard_tests.py`,
//! `spark-cargo`).
#![allow(dead_code)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The first statement of a test that resolves the gateway home in-process.
#[macro_export]
macro_rules! require_private_home {
    () => {
        $crate::private_home::require_private_home_now()
    };
}

/// RED STUB: refuses nothing yet. The rule lands with the implementation.
pub fn require_private_home_now() {}

/// The variable a row's child reads to know it is the child of that row.
pub const ROW_CHILD: &str = "MCP_GW_ROW_CHILD";

/// How often the parent polls its child, and how long it waits at most.
const POLL: Duration = Duration::from_millis(50);
const BOUND: Duration = Duration::from_secs(120);

/// True in the child spawned for `row`; a child never spawns again.
pub fn is_row_child(row: &str) -> bool {
    std::env::var(ROW_CHILD).as_deref() == Ok(row)
}

/// libtest's path for `name` in a module: `module_path!()` without the crate segment.
pub fn test_path(module_path: &str, name: &str) -> String {
    match module_path.split_once("::") {
        Some((_, rest)) => format!("{rest}::{name}"),
        None => name.to_string(),
    }
}

/// What a row expects of its child.
pub enum Expect {
    /// Exit success and exactly one passed test.
    Pass,
    /// Exit failure, exactly one failed test, and a panic containing every fragment.
    Refuse(Vec<String>),
}

/// [`Expect::Refuse`] from string slices.
pub fn refuse(fragments: &[&str]) -> Expect {
    Expect::Refuse(fragments.iter().map(|f| (*f).to_string()).collect())
}

/// The current test binary with an empty env plus what any process needs:
/// PATH, the temp dir variables, the platform home (so the child resolves the
/// same real home as its parent), the coverage profile and the mutant switch.
pub fn literal_env_command() -> Command {
    let mut command = Command::new(std::env::current_exe().expect("the test binary"));
    command.env_clear();
    for name in [
        "PATH",
        "SystemRoot",
        "TEMP",
        "TMP",
        "TMPDIR",
        "HOME",
        "USERPROFILE",
        "LLVM_PROFILE_FILE",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
}

/// Run `row` (a test path in this binary) in a child built from `command`,
/// and check it against `expect`. `ignored` adds `--ignored` for an ignored
/// target. `keep` are the row's temp dirs: kept and named if the child fails.
/// Returns them on success.
pub fn run_row_child(
    mut command: Command,
    row: &str,
    ignored: bool,
    expect: &Expect,
    keep: Vec<tempfile::TempDir>,
) -> Vec<tempfile::TempDir> {
    let output = tempfile::tempdir().expect("an output dir");
    let stdout_path = output.path().join("stdout");
    let stderr_path = output.path().join("stderr");
    let fn_name = row.rsplit("::").next().unwrap_or(row);
    command
        .args(["--exact", row, "--nocapture", "--test-threads=1"])
        .env(ROW_CHILD, fn_name)
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(&stdout_path).expect("stdout file"))
        .stderr(std::fs::File::create(&stderr_path).expect("stderr file"));
    if ignored {
        command.arg("--ignored");
    }
    // The mutant switch reaches every child, unless the row set it itself.
    let row_set_it = command
        .get_envs()
        .any(|(key, _)| key == "MCP_GATEWAY_MUTANT");
    if !row_set_it && let Some(mutant) = std::env::var_os("MCP_GATEWAY_MUTANT") {
        command.env("MCP_GATEWAY_MUTANT", mutant);
    }
    let mut child = command.spawn().expect("the row's child starts"); // spawn-check: waits for exit: polled and reaped below
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("child status") {
            break Some(status);
        }
        if started.elapsed() > BOUND {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(POLL);
    };
    let stdout = std::fs::read_to_string(&stdout_path).unwrap_or_default();
    let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
    print!("{stdout}");
    eprint!("{stderr}");
    let summary = stdout
        .lines()
        .rev()
        .find(|line| line.starts_with("test result: "))
        .unwrap_or("");
    let verdict = match (status, expect) {
        (None, _) => Err(format!("the child ran past {BOUND:?} and was killed")),
        (Some(status), Expect::Pass) => {
            if status.success() && summary.contains(" 1 passed; 0 failed;") {
                Ok(())
            } else {
                Err(format!(
                    "expected one passing test, got {status} and {summary:?}"
                ))
            }
        }
        (Some(status), Expect::Refuse(fragments)) => {
            let missing: Vec<_> = fragments
                .iter()
                .filter(|f| !stderr.contains(f.as_str()))
                .collect();
            if !status.success() && summary.contains(" 0 passed; 1 failed;") && missing.is_empty() {
                Ok(())
            } else {
                Err(format!(
                    "expected one refused test, got {status}, {summary:?}, missing {missing:?}"
                ))
            }
        }
    };
    match verdict {
        Ok(()) => keep,
        Err(why) => {
            let kept: Vec<PathBuf> = keep.into_iter().map(tempfile::TempDir::keep).collect();
            let output = output.keep();
            panic!(
                "{row}: {why}; kept {kept:?} and the child's output in {}",
                output.display()
            );
        }
    }
}

/// A fresh private dir, checked to be a strict descendant of the canonical
/// temp dir and not the real home or anything containing it.
pub fn fresh_private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("a temp dir");
    let canonical = canonical(dir.path());
    let temp = canonical(&std::env::temp_dir());
    assert!(
        canonical != temp && canonical.starts_with(&temp),
        "{} is not inside the temp dir {}",
        canonical.display(),
        temp.display()
    );
    if let Some(home) = real_home() {
        assert!(
            !home.starts_with(&canonical),
            "{} contains the real home {}",
            canonical.display(),
            home.display()
        );
    }
    assert!(
        std::fs::read_dir(dir.path())
            .expect("readable")
            .next()
            .is_none(),
        "a fresh dir is empty"
    );
    dir
}

/// The real home as the platform spells it, if any: the platform's own
/// lookup, which the library falls back to when no override is set.
#[allow(
    clippy::disallowed_methods,
    reason = "the rule compares the override with the platform home itself; crate::home_dir returns the override"
)]
pub fn real_home_raw() -> Option<PathBuf> {
    dirs::home_dir()
}

/// The canonical real home, if any.
pub fn real_home() -> Option<PathBuf> {
    real_home_raw().map(|home| canonical(&home))
}

/// `path` canonicalised, panicking with the path on failure.
pub fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|e| panic!("canonicalise {}: {e}", path.display()))
}

/// `path` with its parent canonicalised and its file name kept: for a leaf
/// that may not exist yet.
pub fn canonical_leaf(path: &Path) -> PathBuf {
    let parent = path.parent().expect("a parent");
    let name = path.file_name().expect("a file name");
    canonical(parent).join(name)
}

/// The env value for `name` as given to the child, for building literal envs.
pub fn os(value: impl Into<OsString>) -> OsString {
    value.into()
}
