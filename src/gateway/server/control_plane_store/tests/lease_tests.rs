// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R3 for the governance log: another writer of its `audit.jsonl` refuses the
//! start, at the default and at an explicit store location. The store opens
//! only with auth on; with auth off there is no governance writer to refuse.

use std::path::Path;
use std::sync::Arc;

use super::{base, load, start};
use crate::security::transparency_log::{TransparencyLogConfig, TransparencyLogger};

fn hold(audit: &Path) -> TransparencyLogger {
    std::fs::create_dir_all(audit.parent().unwrap()).unwrap();
    TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: audit.to_string_lossy().into_owned(),
        lease_wait_secs: 0,
        ..Default::default()
    }))
    .expect("the first writer opens")
}

fn yaml(auth: bool, store_dir: Option<&Path>) -> String {
    let mut y =
        String::from("security:\n  transparency_log:\n    enabled: true\n    lease_wait_secs: 0\n");
    if auth {
        y.push_str("auth:\n  enabled: true\n  bearer_token: f6-test-token\n");
    }
    if let Some(dir) = store_dir {
        use std::fmt::Write as _;
        let _ = write!(
            y,
            // Single-quoted: a Windows path's backslashes stay literal.
            "control_plane:\n  store_dir: '{}'\n",
            dir.to_string_lossy().replace('\'', "''")
        );
    }
    y
}

#[track_caller]
fn assert_refused(outcome: Result<bool, String>, audit: &Path) {
    let err = outcome.expect_err("started beside another writer of the governance log");
    assert!(
        err.contains("another gateway process") && err.contains(&audit.display().to_string()),
        "{err}"
    );
}

fn case(auth: bool, explicit: bool) {
    let (cfg_dir, data) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let store_dir = data.path().join("cp");
    let (config, path) = load(
        cfg_dir.path(),
        &yaml(auth, explicit.then_some(store_dir.as_path())),
    );
    let audit = base(&config, &path).join("audit.jsonl");
    let _holder = hold(&audit);
    if auth {
        assert_refused(start(&config, &path), &audit);
    } else {
        // Auth off never opens the governance store (no governance writer,
        // so no second writer): the start proceeds without it.
        assert_eq!(start(&config, &path), Ok(false));
    }
}

#[test]
fn governance_default_location_refuses_with_auth_on() {
    case(true, false);
}

#[test]
fn governance_default_location_with_auth_off_opens_no_writer() {
    case(false, false);
}

#[test]
fn governance_explicit_location_refuses_with_auth_on() {
    case(true, true);
}

#[test]
fn governance_explicit_location_with_auth_off_opens_no_writer() {
    case(false, true);
}

/// The governance logger inherits `lease_wait_secs` (a non-default value, so
/// a hard-coded default cannot pass).
#[test]
fn governance_log_inherits_the_lease_wait() {
    let cfg_dir = tempfile::tempdir().unwrap();
    let (config, _) = load(
        cfg_dir.path(),
        "security:\n  transparency_log:\n    enabled: true\n    lease_wait_secs: 3\n",
    );
    let gov = super::super::governance_log_config(&config, cfg_dir.path());
    assert_eq!(gov.lease_wait_secs, 3);
}
