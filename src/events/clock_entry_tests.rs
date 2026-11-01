// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202: in `src/events`, the wall clock is read only at the named
//! decision points below. Each reads once and hands that reading to every
//! helper it calls; no other function reads the clock. Four review rounds
//! each found another read in the middle of a decision, where a clock that
//! fails and recovers between two reads splits one decision in two (a lease
//! judged live, then expired). This test pins the rule: a new read anywhere
//! else, or a second read in one of these, fails it.
//!
//! Counted: `crate::clock` reads (`utc_now`, `unix_secs`,
//! `system_time_or_before_epoch`, `expired_by`, `expired_by_utc`,
//! `stamp_audit_row`), `Now::read`, and chrono's and std's raw `now` constructors, in
//! the product files of this directory (test files and `#[cfg(test)]`
//! modules are skipped). `Instant` is monotonic, not the wall clock.

use std::collections::BTreeMap;

/// `(file, function, reads)`, file relative to `src/events`,
/// subdirectories included: every decision point and its one read (two
/// where one function holds two decisions, named in the inventory).
const DECISION_POINTS: &[(&str, &str, usize)] = &[
    ("admin.rs", "replay_dead", 2),
    ("client.rs", "post", 1),
    ("client.rs", "post_tracked", 1),
    ("fanout.rs", "fan_out", 1),
    ("fanout.rs", "hold_unserved", 1),
    ("fanout.rs", "revoke", 1),
    ("fanout.rs", "withdraw_rows", 1),
    ("governance.rs", "audit_lifecycle", 1),
    // A lease judges its token's expiry at install, a held lease's expiry
    // before each send, and whether a held generation is past its deadline
    // wherever it is read (delivery, fan-out, a listener's start and check).
    ("lease.rs", "held_generation", 1),
    ("lease.rs", "install", 1),
    ("lease.rs", "with_credential", 1),
    // A lease request judges its row live once.
    ("lease_rpc.rs", "lease", 1),
    ("lifecycle.rs", "live_keys", 1),
    ("mod.rs", "open_with", 1),
    ("operational_source.rs", "authorize", 1),
    ("reconcile.rs", "stop_expired_keys", 1),
    ("reconcile.rs", "sweep_lifecycle", 1),
    ("rpc.rs", "unsubscribe", 1),
    ("rpc/subscribe.rs", "subscribe", 1),
    ("rpc_held.rs", "refresh_held", 1),
    ("runtime.rs", "emit_dated", 1),
    ("runtime.rs", "new", 1),
    ("schedule_source.rs", "authorize", 1),
    ("schedule_source.rs", "install_schedule_source", 2),
    ("schedule_source.rs", "on_first_subscriber", 1),
    ("services.rs", "admission", 1),
    ("services.rs", "admits", 1),
    ("services.rs", "audit_evictions", 1),
    ("services.rs", "audit_outcome", 1),
    ("store.rs", "admit_granted", 1),
    ("upstream_listener.rs", "revoke_absent_uris", 1),
    ("upstream_session_notes.rs", "flush_at", 1),
    ("watch_source.rs", "audit_backoff", 1),
    ("watch_source.rs", "authorize", 1),
    ("watch_source.rs", "once", 1),
    ("watch_source/hold.rs", "judge_rows", 1),
    ("watch_source/hold.rs", "pin_classes", 1),
    ("webhook_source.rs", "webhook_received", 1),
    ("worker.rs", "attempt_once", 2),
    ("worker.rs", "record_and_send", 1),
    ("worker.rs", "settle_answer", 1),
    ("worker_dispatch.rs", "dispatch", 2),
    ("worker_dispatch.rs", "sweep_dead_letters", 1),
    ("worker_settle.rs", "settle_with", 1),
    ("worker_settle.rs", "settled_unsendable", 1),
];

const READS: &[&str] = &[
    "clock::utc_now",
    "clock::unix_secs",
    "clock::system_time_or_before_epoch",
    "clock::expired_by",
    "clock::stamp_audit_row",
    // Spelled in two halves, so the crate's own raw-read lint does not count
    // this list as reads.
    concat!("Now::", "read("),
    concat!("Utc::", "now("),
    concat!("SystemTime::", "now("),
];

/// The function a line sits in: the last `fn name` above it.
fn fn_name(line: &str) -> Option<&str> {
    let rest = line.trim_start();
    let rest = rest
        .strip_prefix("pub(crate) ")
        .or_else(|| rest.strip_prefix("pub(super) "))
        .or_else(|| rest.strip_prefix("pub "))
        .unwrap_or(rest);
    let rest = rest.strip_prefix("const ").unwrap_or(rest);
    let rest = rest.strip_prefix("async ").unwrap_or(rest);
    let rest = rest.strip_prefix("fn ")?;
    let end = rest.find(|c: char| !(c.is_alphanumeric() || c == '_'))?;
    Some(&rest[..end])
}

/// A `mod name {` line, the body a `#[cfg(test)]` above it compiles out.
fn opens_module(line: &str) -> bool {
    let rest = line.trim_start();
    let rest = rest
        .strip_prefix("pub(crate) ")
        .or_else(|| rest.strip_prefix("pub(super) "))
        .or_else(|| rest.strip_prefix("pub "))
        .unwrap_or(rest);
    rest.starts_with("mod ") && rest.trim_end().ends_with('{')
}

fn reads_in(source: &str) -> BTreeMap<String, usize> {
    let lines: Vec<&str> = source.lines().collect();
    let mut found = BTreeMap::new();
    let mut current = String::from("<top>");
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if line.trim() == "#[cfg(test)]" && lines.get(i + 1).is_some_and(|l| opens_module(l)) {
            let mut depth = 0_i64;
            i += 1;
            while i < lines.len() {
                depth += i64::try_from(lines[i].matches('{').count()).unwrap_or(0);
                depth -= i64::try_from(lines[i].matches('}').count()).unwrap_or(0);
                i += 1;
                if depth <= 0 {
                    break;
                }
            }
            continue;
        }
        if let Some(name) = fn_name(line) {
            current = name.to_owned();
        }
        if !line.trim_start().starts_with("//") {
            let n: usize = READS.iter().map(|r| line.matches(r).count()).sum();
            if n > 0 {
                *found.entry(current.clone()).or_default() += n;
            }
        }
        i += 1;
    }
    found
}

/// Every `.rs` product file under `root`, recursively, keyed by its
/// path relative to `root` with `/` separators. A file whose file name
/// contains "test", or under a directory named "tests" or ending in
/// "_tests", is skipped.
fn scanned_files(root: &std::path::Path) -> Vec<(String, std::path::PathBuf)> {
    fn walk(
        dir: &std::path::Path,
        rel: &std::path::Path,
        out: &mut Vec<(String, std::path::PathBuf)>,
    ) {
        let entries = std::fs::read_dir(dir).expect("read a src/events directory");
        for entry in entries {
            let entry = entry.expect("a directory entry");
            let path = entry.path();
            let name_owned = entry.file_name();
            let name = name_owned.to_str().expect("a UTF-8 file name");
            let child_rel = if rel.as_os_str().is_empty() {
                std::path::PathBuf::from(name)
            } else {
                rel.join(name)
            };
            if path.is_dir() {
                if !(name == "tests" || name.ends_with("_tests")) {
                    walk(&path, &child_rel, out);
                }
            } else if path.extension().is_some_and(|e| e == "rs")
                && !name.contains("test")
                && !rel.components().any(|c| {
                    c.as_os_str()
                        .to_str()
                        .is_some_and(|s| s == "tests" || s.ends_with("_tests"))
                })
            {
                let key = child_rel
                    .components()
                    .filter_map(|c| c.as_os_str().to_str())
                    .collect::<Vec<_>>()
                    .join("/");
                out.push((key, path));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, std::path::Path::new(""), &mut out);
    out.sort();
    out
}

/// `(file, function, reads)`, file relative to `src/events`,
/// subdirectories included.
#[test]
fn the_events_clock_is_read_only_at_its_decision_points() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/events");
    let mut found = BTreeMap::new();
    for (file, path) in scanned_files(&dir) {
        let source = std::fs::read_to_string(&path).expect("read");
        for (function, n) in reads_in(&source) {
            found.insert((file.clone(), function), n);
        }
    }
    let expected: BTreeMap<(String, String), usize> = DECISION_POINTS
        .iter()
        .map(|(file, function, n)| (((*file).to_owned(), (*function).to_owned()), *n))
        .collect();
    assert_eq!(
        found, expected,
        "a clock read outside a named decision point, or a second read in one: \
         thread the decision's `now` into the helper instead (MIK-8202)"
    );
}

/// The scanner itself: a read in a helper is found and attributed, a
/// `#[cfg(test)]` module is skipped, and a comment is not a read.
#[test]
fn the_scanner_finds_a_read_and_skips_test_code() {
    let source = "fn decide() {\n    let now = crate::clock::utc_now();\n}\n\
                  fn helper() {\n    // crate::clock::utc_now()\n    x.live(crate::clock::unix_secs());\n}\n\
                  #[cfg(test)]\nmod tests {\n    fn t() { crate::clock::utc_now(); }\n}\n";
    let found = reads_in(source);
    assert_eq!(found.get("decide"), Some(&1));
    assert_eq!(found.get("helper"), Some(&1));
    assert_eq!(found.get("t"), None);
}

#[test]
fn the_scanner_walks_subdirectories() {
    let root = tempfile::tempdir().expect("tempdir");
    let sub = root.path().join("sub");
    std::fs::create_dir_all(&sub).expect("create temp subdir");
    let latest = root.path().join("latest");
    std::fs::create_dir_all(&latest).expect("create temp latest dir");
    let tests = root.path().join("tests");
    std::fs::create_dir_all(&tests).expect("create temp tests dir");
    let body = "fn decide() {\n    let now = crate::clock::utc_now();\n}\n";
    std::fs::write(root.path().join("a.rs"), body).expect("write a.rs");
    std::fs::write(sub.join("b.rs"), body).expect("write sub/b.rs");
    std::fs::write(sub.join("c_tests.rs"), body).expect("write sub/c_tests.rs");
    std::fs::write(latest.join("d.rs"), body).expect("write latest/d.rs");
    std::fs::write(tests.join("e.rs"), body).expect("write tests/e.rs");
    let files = scanned_files(root.path());
    let keys: Vec<&str> = files.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(keys, vec!["a.rs", "latest/d.rs", "sub/b.rs"]);
    assert!(keys.contains(&"latest/d.rs"));
    assert!(!keys.contains(&"tests/e.rs"));
    assert!(!keys.contains(&"sub/c_tests.rs"));
    for (_, path) in &files {
        let source = std::fs::read_to_string(path).expect("read scanned file");
        assert_eq!(reads_in(&source).get("decide"), Some(&1));
    }
}
