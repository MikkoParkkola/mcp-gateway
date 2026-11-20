// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A private gateway home for integration tests that resolve the home in-process, and the
//! child-process protocol their rows share.
//!
//! An integration binary links the library without `cfg(test)`, so its in-process code resolves
//! the home through the debug arm: the test-home override if set, else the account's real home.
//! `require_private_home!()`, the first statement of every such test, refuses to run unless the
//! override names a private directory, so a bare `cargo test` never reads or writes the real
//! home. Harnesses set the override (`scripts/ci/shard_tests.py`, `spark-cargo`). The override
//! must be a fresh empty directory (`mktemp -d`); pointing it at a directory the real home links
//! into is unsupported.
#![allow(dead_code, reason = "each test crate uses part of this helper")]

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

/// Refuse to run unless the gateway home this process resolves is private.
/// The checks run in order; the first failure panics naming its check and the
/// fix for it.
pub fn require_private_home_now() {
    if let Err(refusal) = judge() {
        let fix = if refusal.check == 1 {
            "cargo test without --release: the release library ignores the test-home override"
        } else if refusal.env_fix {
            "env -u XDG_CONFIG_HOME -u MCP_GATEWAY_CONFIG_DIR MCP_GATEWAY_TEST_HOME_DIR=$(mktemp -d) cargo test ... \
             (PowerShell: Remove-Item Env:XDG_CONFIG_HOME, Env:MCP_GATEWAY_CONFIG_DIR -ErrorAction Ignore; \
             $env:MCP_GATEWAY_TEST_HOME_DIR = (New-Item -ItemType Directory (Join-Path $env:TEMP (New-Guid))).FullName)"
        } else {
            "MCP_GATEWAY_TEST_HOME_DIR=$(mktemp -d) cargo test ... \
             (PowerShell: $env:MCP_GATEWAY_TEST_HOME_DIR = (New-Item -ItemType Directory (Join-Path $env:TEMP (New-Guid))).FullName)"
        };
        panic!(
            "private home refused (check {}): {}. This test resolves the gateway home in-process \
             and would otherwise use the real one. Run: {fix}",
            refusal.check, refusal.why
        );
    }
}

/// Why the rule refused: the check that failed, what it found, and whether
/// the fix must also clear the config and data variables.
struct Refusal {
    check: u8,
    why: String,
    env_fix: bool,
}

fn refused(check: u8, why: String, env_fix: bool) -> Result<(), Refusal> {
    Err(Refusal {
        check,
        why,
        env_fix,
    })
}

/// The seven checks of the rule (design-refusal.md), in order.
fn judge() -> Result<(), Refusal> {
    // 1. The release library ignores the override.
    if !cfg!(debug_assertions) {
        return refused(
            1,
            "these tests need a debug build: the release library ignores MCP_GATEWAY_TEST_HOME_DIR"
                .into(),
            false,
        );
    }
    // 2. An override at all.
    let Some(home) =
        std::env::var_os("MCP_GATEWAY_TEST_HOME_DIR").filter(|value| !value.is_empty())
    else {
        return refused(
            2,
            "MCP_GATEWAY_TEST_HOME_DIR is unset or empty".into(),
            false,
        );
    };
    let home = PathBuf::from(home);
    // 3. An existing directory, judged before any canonicalisation.
    if !home.is_dir() {
        return refused(
            3,
            format!(
                "MCP_GATEWAY_TEST_HOME_DIR={} names no existing directory",
                home.display()
            ),
            false,
        );
    }
    // 4. Not the real home by any spelling; both sides canonicalised.
    let canonical_home = std::fs::canonicalize(&home);
    let real = real_home_raw().map(std::fs::canonicalize);
    let canonical_home = match (canonical_home, real) {
        (Ok(ours), Some(Ok(real))) if ours != real => ours,
        (Ok(_), Some(Ok(_))) => {
            return refused(4, format!("{} is the real home", home.display()), false);
        }
        _ => {
            return refused(
                4,
                format!(
                    "{} or the real home cannot be resolved, so it cannot be shown not to be the real home",
                    home.display()
                ),
                false,
            );
        }
    };
    // 5 and 6. The config and data variables: unset, or exactly under the override.
    for (check, var, name) in [
        (5, "XDG_CONFIG_HOME", ".config"),
        (6, "MCP_GATEWAY_CONFIG_DIR", ".mcp-gateway"),
    ] {
        let Some(value) = std::env::var_os(var) else {
            continue;
        };
        let path = PathBuf::from(&value);
        let parent_is_home = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .and_then(|parent| std::fs::canonicalize(parent).ok())
            .is_some_and(|parent| parent == canonical_home);
        if value.is_empty() || path.file_name() != Some(name.as_ref()) || !parent_is_home {
            return refused(
                check,
                format!(
                    "{var} must be unset or <override>/{name}; it is \"{}\"",
                    path.display()
                ),
                true,
            );
        }
    }
    // 7. Nothing under the override leads out of it. Discovery reads more than
    // `.config` and `.mcp-gateway` (`.cursor`, `.claude.json`, ...), so every link
    // and directory, at any depth, must resolve inside.
    let real_home = real_home_raw();
    if let Some((why, at)) = first_way_out(&home, &canonical_home, real_home.as_deref(), "") {
        return refused(7, format!("{why}: {}", at.display()), true);
    }
    Ok(())
}

/// The first entry under `dir` that leads outside `canonical_home`, or that
/// cannot be judged, as (reason, path); the reason names the entry relative to
/// the override, `/`-joined. Links and directories are judged by where they
/// resolve (a Windows junction too, whichever it reports as); only real
/// directories are descended, so a link is never followed. A dangling link
/// counts as outside. Any error but "not found" refuses: a directory that cannot
/// be listed may still open by a known path (an execute-only one does). Only an
/// entry removed meanwhile (a concurrent test) is skipped. A plain file is
/// refused only when it is the real home's file at the same relative path, or
/// that file cannot be read (unix only, see `real_file_reason`).
fn first_way_out(
    dir: &Path,
    canonical_home: &Path,
    real_home: Option<&Path>,
    rel: &str,
) -> Option<(String, PathBuf)> {
    let gone = |e: &std::io::Error| e.kind() == std::io::ErrorKind::NotFound;
    let here = if rel.is_empty() { "the override" } else { rel };
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if gone(&e) => return None,
        Err(e) => return Some((format!("{here} cannot be listed ({e})"), dir.to_path_buf())),
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) if gone(&e) => continue,
            Err(e) => return Some((format!("{here} cannot be listed ({e})"), dir.to_path_buf())),
        };
        let at = entry.path();
        let name = entry.file_name();
        let rel = if rel.is_empty() {
            name.to_string_lossy().into_owned()
        } else {
            format!("{rel}/{}", name.to_string_lossy())
        };
        let meta = match at.symlink_metadata() {
            Ok(meta) => meta,
            Err(e) if gone(&e) => continue,
            Err(e) => return Some((format!("{rel} cannot be read ({e})"), at)),
        };
        let link = meta.file_type().is_symlink();
        if !link && !meta.is_dir() {
            if let Some(why) = real_file_reason(&meta, real_home, &rel) {
                return Some((why, at));
            }
            continue;
        }
        match std::fs::canonicalize(&at) {
            Ok(resolved) if resolved.starts_with(canonical_home) => {}
            Err(_) if at.symlink_metadata().is_err_and(|e| gone(&e)) => continue,
            _ => return Some((format!("{rel} resolves outside the override"), at)),
        }
        if !link && let Some(found) = first_way_out(&at, canonical_home, real_home, &rel) {
            return Some(found);
        }
    }
    None
}

/// Unix: why a plain test-home file is the real home's file at the same
/// relative path (same device and inode), so a write through it changes real
/// config. That covers a hard link into the real home and a real-home symlink
/// into the override (a dotfiles directory used as the test home). Only "not
/// found" (or a non-directory on the way) proves the real path absent; any other
/// error refuses, so an unreadable real home fails closed. The gateway's own hard
/// links (journal publishes, kept backups) stay inside the test home, so they
/// never match.
#[cfg(unix)]
fn real_file_reason(
    meta: &std::fs::Metadata,
    real_home: Option<&Path>,
    rel: &str,
) -> Option<String> {
    use std::io::ErrorKind;
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(real_home?.join(rel)) {
        Ok(theirs) => (theirs.dev() == meta.dev() && theirs.ino() == meta.ino())
            .then(|| format!("{rel} is the real home's {rel} (the same file)")),
        Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => None,
        Err(e) => Some(format!(
            "{rel} cannot be judged: the real home's {rel} cannot be read ({e})"
        )),
    }
}

/// Not unix: std has no stable file id, so a test-home file that is the real
/// home's file is not detected here. A declared limit of check 7.
#[cfg(not(unix))]
fn real_file_reason(_: &std::fs::Metadata, _: Option<&Path>, _: &str) -> Option<String> {
    None
}

/// The variable a row's child reads to know it is the child of that row.
pub const ROW_CHILD: &str = "MCP_GW_ROW_CHILD";

/// How often the parent polls its child, and how long it waits at most.
// limit-under-test (absorbed-by: BOUND): only the poll interval; a slow runner polls more often before BOUND
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
    /// Exit failure, exactly one failed test, a panic containing every
    /// fragment of the first list and none of the second.
    Refuse(Vec<String>, Vec<String>),
}

/// [`Expect::Refuse`] from string slices: what the panic must say, and what it must not.
pub fn refuse(present: &[&str], absent: &[&str]) -> Expect {
    let owned = |list: &[&str]| list.iter().map(|f| (*f).to_string()).collect();
    Expect::Refuse(owned(present), owned(absent))
}

/// The current test binary with an empty env plus what any process needs:
/// PATH, the temp dir variables, the platform home (so the child resolves the
/// same real home as its parent), the coverage profile and the mutant switch.
pub fn literal_env_command() -> Command {
    crate::gateway_bin::test_binary_with_only_env(&[
        "PATH",
        "SystemRoot",
        "TEMP",
        "TMP",
        "TMPDIR",
        "HOME",
        "USERPROFILE",
        "LLVM_PROFILE_FILE",
    ])
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
        (Some(status), Expect::Refuse(present, absent)) => {
            let missing: Vec<_> = present
                .iter()
                .filter(|f| !stderr.contains(f.as_str()))
                .collect();
            let unwanted: Vec<_> = absent
                .iter()
                .filter(|f| stderr.contains(f.as_str()))
                .collect();
            if !status.success()
                && summary.contains(" 0 passed; 1 failed;")
                && missing.is_empty()
                && unwanted.is_empty()
            {
                Ok(())
            } else {
                Err(format!(
                    "expected one refused test, got {status}, {summary:?}, missing {missing:?}, unwanted {unwanted:?}"
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
    let ours = canonical(dir.path());
    let temp = canonical(&std::env::temp_dir());
    assert!(
        ours != temp && ours.starts_with(&temp),
        "{} is not inside the temp dir {}",
        ours.display(),
        temp.display()
    );
    if let Some(home) = real_home() {
        assert!(
            !home.starts_with(&ours),
            "{} contains the real home {}",
            ours.display(),
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

/// T3-T5, one per binary: in a child whose test-home override is a fresh A and
/// whose platform home is a second dir B, with every inherited gateway
/// variable stripped, the gateway data dir this binary resolves is A's
/// `.mcp-gateway`. A library that ignored the override would resolve B's.
pub fn assert_routes_to_the_override(module_path: &str, name: &str) {
    if is_row_child(name) {
        assert!(
            std::env::var_os("MCP_GATEWAY_CONFIG_DIR").is_none(),
            "premise: the data-dir variable is stripped, so home routing decides"
        );
        let a = PathBuf::from(std::env::var_os("MCP_GATEWAY_TEST_HOME_DIR").expect("the override"));
        let data = mcp_gateway::config_persistence::gateway_data_dir();
        assert_eq!(
            canonical_leaf(&data),
            canonical(&a).join(".mcp-gateway"),
            "{}",
            data.display()
        );
        return;
    }
    let a = fresh_private_dir();
    let b = fresh_private_dir();
    let command = crate::gateway_bin::isolated_with_env_home(
        Command::new(std::env::current_exe().expect("the test binary")),
        a.path(),
        b.path(),
        crate::gateway_bin::Inherit::Environment,
    );
    let _kept = run_row_child(
        command,
        &test_path(module_path, name),
        false,
        &Expect::Pass,
        vec![a, b],
    );
}
