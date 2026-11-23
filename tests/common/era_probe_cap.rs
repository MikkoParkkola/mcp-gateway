// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The era probe cap override shared by the suites that drive shell-script peers.
//! The cap reaches the gateway from exec: each test re-runs itself as a child
//! with the cap on the child's command (`in_child_with_cap`), so no test sets
//! the environment while others run.

/// Debug builds read this to widen the era probe's 2 s cap (`src/backend/era.rs`).
/// The peers here are shell scripts that fork per request; on a stalled runner
/// one answer can take longer than 2 s, and the probe would read that as silence.
const PROBE_CAP_ENV: &str = "MCP_GATEWAY_TEST_ERA_PROBE_CAP_MS";

/// The widened cap for every peer in this binary that is meant to answer. A
/// silent peer then waits out the whole cap, so it is high enough to absorb a
/// stalled runner and low enough to keep that one wait short.
const PROBE_CAP_MS: &str = "20000";

/// The probe cap is widened: it came from exec. A test that builds a backend
/// without starting with `in_child_with_cap` fails here.
pub fn widen_probe_cap() {
    assert_eq!(
        std::env::var(PROBE_CAP_ENV).as_deref(),
        Ok(PROBE_CAP_MS),
        "start this test with `if in_child_with_cap() {{ return; }}`: the probe cap comes from exec"
    );
}

/// Run the calling test again as a child of this test binary whose
/// environment carries the cap from exec, so no test sets it while others
/// run. True in the parent, once the child ran this one test and passed (the
/// caller returns); false in the child (the caller runs its body). The child's
/// output is shown only when it fails, so no nested test summary reaches the
/// parent's log.
#[must_use]
pub fn in_child_with_cap() -> bool {
    // Only this helper's own value marks the child: a cap set from outside
    // (a forced 1 ms run) is replaced on the child's command, never kept.
    if std::env::var(PROBE_CAP_ENV).as_deref() == Ok(PROBE_CAP_MS) {
        return false;
    }
    let test = std::thread::current()
        .name()
        .expect("a test runs on a thread named after it")
        .to_owned();
    let out = std::process::Command::new(std::env::current_exe().expect("this test binary"))
        .args([test.as_str(), "--exact", "--test-threads=1"])
        .env(PROBE_CAP_ENV, PROBE_CAP_MS)
        .output()
        .expect("the child run of this test started");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success()
            && stdout.contains(&format!("test {test} ... ok"))
            && stdout.contains("test result: ok. 1 passed"),
        "the child run of {test} did not pass:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    true
}

#[path = "module_sources.rs"]
mod module_sources;

/// Fail if the test binary whose root file is `binary` (as `file!()` names
/// it, from the crate root), or any module it compiles in (this helper among
/// them, followed through `#[path]` and `mod` lines), sets or removes an
/// environment variable: the cap reaches the gateway from exec only.
pub fn assert_no_env_writes(binary: &str) {
    for (path, text) in module_sources::module_sources(binary) {
        for needle in [concat!("set_", "var("), concat!("remove_", "var(")] {
            assert!(
                !text.contains(needle),
                "{} calls {needle}: the cap must reach the gateway from exec only",
                path.display()
            );
        }
    }
}
