// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The era probe cap override shared by the suites that drive shell-script peers.
#![allow(unsafe_code)] // `set_var` is unsafe in edition 2024; see `widen_probe_cap`

/// Debug builds read this to widen the era probe's 2 s cap (`src/backend/era.rs`).
/// The peers here are shell scripts that fork per request; on a stalled runner
/// one answer can take longer than 2 s, and the probe would read that as silence.
const PROBE_CAP_ENV: &str = "MCP_GATEWAY_TEST_ERA_PROBE_CAP_MS";

/// Widen the probe cap for every peer in this binary that is meant to answer.
/// A silent peer then waits out the whole cap, so it is set once, high enough to
/// absorb a stalled runner and low enough to keep that one wait short.
pub fn widen_probe_cap() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // SAFETY: tests run in parallel threads, so other backends may already
        // be probing. std serialises `set_var` against its own env reads
        // (`std::env::var`) and against `Command::spawn`, which holds the env
        // read lock. The peers are stdio children with no DNS, so no foreign
        // `getenv` runs in this test binary.
        unsafe { std::env::set_var(PROBE_CAP_ENV, "20000") };
    });
}

/// Run the calling test again as a child of this test binary whose
/// environment carries the cap from exec, so no test sets it while others
/// run. True in the parent, once the child ran this one test and passed (the
/// caller returns); false in the child (the caller runs its body). The child's
/// output is shown only when it fails, so no nested test summary reaches the
/// parent's log.
#[must_use]
pub fn in_child_with_cap() -> bool {
    if std::env::var_os(PROBE_CAP_ENV).is_some() {
        return false;
    }
    let test = std::thread::current()
        .name()
        .expect("a test runs on a thread named after it")
        .to_owned();
    let out = std::process::Command::new(std::env::current_exe().expect("this test binary"))
        .args([test.as_str(), "--exact", "--test-threads=1"])
        .env(PROBE_CAP_ENV, "20000")
        .output()
        .expect("the child run of this test started");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("test result: ok. 1 passed"),
        "the child run of {test} did not pass:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    true
}

/// Fail if `binary_source` or this file sets or removes an environment
/// variable: the cap reaches the gateway only from exec.
pub fn assert_no_set_var(binary_source: &str) {
    let own = include_str!("era_probe_cap.rs");
    for (what, source) in [("this binary", binary_source), ("era_probe_cap.rs", own)] {
        for needle in [concat!("set_", "var("), concat!("remove_", "var(")] {
            assert!(
                !source.contains(needle),
                "{what} calls {needle}: the cap must reach the gateway from exec only"
            );
        }
    }
}
