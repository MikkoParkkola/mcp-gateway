// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A capability file whose bytes stopped matching their pin while the gateway
//! was down is recorded at stdio startup, as the file watcher records one that
//! changes while it runs. Stdio has no decision set: the record is what it
//! keeps, and what the HTTP set reads.

use std::path::Path;

use super::stdio_startup_tests::startup;
use crate::capability::{compute_capability_hash, rewrite_with_pin};
use crate::config::Config;

const CHANGED: &str = "
name: changed_tool
description: Trusted when it was pinned
providers:
  primary:
    service: rest
    config:
      base_url: https://example.com
      path: /v1
";

const STEADY: &str = "
name: steady_tool
description: Pinned and unchanged
providers:
  primary:
    service: rest
    config:
      base_url: https://example.com
      path: /v2
";

/// Write `body` pinned to its own hash, then, when `change` is set, change
/// its bytes so the pin no longer matches: what an edit made while the
/// gateway was down leaves on disk.
fn pinned(dir: &Path, file: &str, body: &str, change: bool) -> String {
    let mut text = rewrite_with_pin(body, &compute_capability_hash(body));
    if change {
        text = text.replace("Trusted when it was pinned", "Changed while down");
    }
    let path = dir.join(file);
    std::fs::write(&path, text).expect("VOID: write the capability");
    path.display().to_string()
}

fn capabilities_in(dirs: &[&Path]) -> Config {
    let mut config = Config::default();
    config.capabilities.enabled = true;
    config.capabilities.directories = dirs.iter().map(|d| d.display().to_string()).collect();
    config
}

/// The stdio capability backend's pin-mismatch records after startup.
fn records(meta: &crate::gateway::meta_mcp::MetaMcp) -> Vec<String> {
    let backend = meta
        .capabilities
        .read()
        .clone()
        .expect("VOID: stdio installed the capability backend");
    backend
        .rug_pull_records()
        .into_iter()
        .map(|record| record.file)
        .collect()
}

/// PIN.1a / PIN.2a: a file changed while the gateway was down is a recorded
/// pin mismatch after a stdio startup, and its pinned neighbour is served
/// and not recorded.
/// Mutant: the startup detection dropped on stdio: no record.
#[tokio::test(flavor = "current_thread")]
async fn a_capability_changed_while_down_is_recorded_at_stdio_startup() {
    let dir = tempfile::tempdir().expect("VOID: a temp dir");
    let changed = pinned(dir.path(), "changed.yaml", CHANGED, true);
    let steady = pinned(dir.path(), "steady.yaml", STEADY, false);
    let (outcome, meta) = startup(capabilities_in(&[dir.path()])).await;
    outcome.expect("stdio startup with capabilities succeeds");
    let recorded = records(&meta);
    assert_eq!(recorded, vec![changed], "only the changed file is recorded");
    assert!(!recorded.contains(&steady), "the pinned neighbour is not");
    let backend = meta.capabilities.read().clone().expect("VOID: installed");
    assert!(
        backend.has_capability("steady_tool"),
        "the pinned neighbour is served"
    );
    assert!(
        !backend.has_capability("changed_tool"),
        "the changed file is not served"
    );
}

/// PIN.2a: a configured directory whose load fails (an unreadable
/// subdirectory in it) is still walked for pin mismatches at stdio startup.
/// Mutant: stdio not registering its directories before the load: the
/// directory that failed to load is never walked, no record.
#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn a_directory_that_failed_to_load_is_still_checked_at_stdio_startup() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().expect("VOID: a temp dir");
    let changed = pinned(dir.path(), "changed.yaml", CHANGED, true);
    let locked = dir.path().join("locked");
    std::fs::create_dir(&locked).expect("VOID: a subdirectory");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
        .expect("VOID: lock it");
    let (outcome, meta) = startup(capabilities_in(&[dir.path()])).await;
    // Unlocked before any assertion, so the temp dir is always removable.
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700))
        .expect("VOID: unlock it");
    outcome.expect("a failed optional directory does not stop stdio startup");
    assert_eq!(
        records(&meta),
        vec![changed],
        "the mismatch beside the unreadable subdirectory is recorded"
    );
}
