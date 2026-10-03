// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7787: `cap list` says why a keyed capability is not served.

use std::sync::Arc;

use super::super::CapabilityExecutor;
use crate::config::{EnvOverlay, LiveEnv, ResolvedEnvFiles};

fn executor_holding(vars: &str) -> (tempfile::TempDir, CapabilityExecutor) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.env");
    crate::gateway::test_helpers::write_owner_only(&path, vars).expect("write env file");
    let env = Arc::new(LiveEnv::new(
        Arc::new(EnvOverlay::from_paths(&[path])),
        ResolvedEnvFiles::default(),
    ));
    (dir, CapabilityExecutor::new().with_env(env))
}

fn cap(name: &str, key: &str) -> crate::capability::CapabilityDefinition {
    let yaml = format!(
        "name: {name}\ndescription: Keyed\nproviders:\n  primary:\n    service: rest\n    \
         config:\n      base_url: https://api.invalid\n      path: /k\nauth:\n  required: true\n  \
         type: bearer\n  key: \"{key}\"\n"
    );
    crate::capability::parse_capability(&yaml).unwrap()
}

#[test]
fn a_capability_whose_key_is_missing_is_marked_off_and_names_the_key() {
    let (_dir, executor) = executor_holding("MIK7787_PRESENT=x\n");
    let line = executor.list_line(&cap("gone", "env:MIK7787_ABSENT_KEY"));
    assert_eq!(line, "  gone - Keyed [bearer] off: needs MIK7787_ABSENT_KEY");
}

#[test]
fn a_capability_whose_key_is_set_is_listed_plainly() {
    let (_dir, executor) = executor_holding("MIK7787_PRESENT=x\n");
    let line = executor.list_line(&cap("here", "env:MIK7787_PRESENT"));
    assert_eq!(line, "  here - Keyed [bearer]");
}

#[test]
fn an_oauth_capability_without_a_login_says_which_login() {
    let (_dir, executor) = executor_holding("MIK7787_PRESENT=x\n");
    let line = executor.list_line(&cap("login", "oauth:mik7787-no-such-provider"));
    assert_eq!(
        line,
        "  login - Keyed [bearer] off: needs a mik7787-no-such-provider login"
    );
}
