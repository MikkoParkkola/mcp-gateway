// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test code under `src/transport` and `src/backend` signals no pid or
//! process group it does not own by construction. A guard that checks a pid
//! and then signals it races the reaper: the leader can be reaped and its pid
//! reused in between, and the signal then reaches someone else's processes (on
//! a shared host, another job's). A row's processes are ended through their
//! owner instead: the transport's `kill_tree_now`, `Backend::retire_now`, or
//! the row's stop deadline moved to now.
//!
//! The sites that existed when this pin landed are counted per file and may
//! only shrink; a new raw signal in any test file there fails the row.

use std::collections::BTreeMap;
use std::path::Path;

/// The raw signal calls the pin counts.
const NEEDLES: [&str; 6] = [
    "kill_process_group(",
    "kill_process(",
    "libc::kill(",
    "killpg(",
    "signal::kill(",
    "Command::new(\"kill\")",
];

/// The sites as they were when the pin landed: shrink only.
const KNOWN: [(&str, usize); 6] = [
    ("src/backend/eviction_close_bound_tests.rs", 1),
    ("src/backend/pool_tests/close_timeouts.rs", 3),
    ("src/backend/pool_tests/recovery_and_shutdown.rs", 2),
    ("src/transport/stdio_child_tree_tests.rs", 3),
    ("src/transport/stdio_frame_tests.rs", 6),
    ("src/transport/stdio_tests.rs", 2),
];

/// Raw signal calls on one line: a needle not preceded by an identifier
/// character (so `test_kill_process(`, a signal-0 probe, is not one).
fn sites(line: &str) -> usize {
    NEEDLES
        .iter()
        .map(|needle| {
            line.match_indices(needle)
                .filter(|(at, _)| {
                    line[..*at]
                        .chars()
                        .next_back()
                        .is_none_or(|c| !(c.is_alphanumeric() || c == '_'))
                })
                .count()
        })
        .sum()
}

fn walk(dir: &Path, root: &Path, counts: &mut BTreeMap<String, usize>) {
    let entries = std::fs::read_dir(dir).expect("read a source directory");
    for entry in entries {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            walk(&path, root, counts);
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .expect("under the crate root")
            .to_string_lossy()
            .replace('\\', "/");
        let rust = path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("rs"));
        if !rust || !relative.contains("test") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("read a test file");
        let found: usize = source.lines().map(sites).sum();
        if found > 0 {
            counts.insert(relative, found);
        }
    }
}

#[test]
fn no_test_file_gains_a_raw_signal_to_a_pid() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut counts = BTreeMap::new();
    for dir in ["src/transport", "src/backend"] {
        walk(&root.join(dir), root, &mut counts);
    }
    let known: BTreeMap<String, usize> = KNOWN
        .iter()
        .map(|(file, count)| ((*file).to_string(), *count))
        .collect();
    let grown: Vec<String> = counts
        .iter()
        .filter(|(file, count)| known.get(*file).is_none_or(|was| *count > was))
        .map(|(file, count)| format!("{file}: {count}"))
        .collect();
    assert!(
        grown.is_empty(),
        "raw signals to a pid in test code (end a row's processes through their owner): {grown:?}"
    );
}

/// The line matcher counts a raw call and skips a signal-0 probe.
#[test]
fn the_matcher_counts_raw_calls_and_skips_probes() {
    assert_eq!(sites("let _ = kill_process_group(pid, Signal::KILL);"), 1);
    assert_eq!(sites("rustix::process::kill_process(pid, sig)"), 1);
    assert_eq!(sites("std::process::Command::new(\"kill\")"), 1);
    assert_eq!(sites("rustix::process::test_kill_process(pid).is_ok()"), 0);
}
