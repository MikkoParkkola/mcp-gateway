// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tests for the configuration module.

use std::env;

use super::*;
use crate::gateway::test_helpers::write_owner_only;

mod env_files;
mod error_budget;
mod idle_and_agents;
mod loading;
mod pattern_grammar;
mod validate_config;

/// The child half of ENVFILE.19d. Computes its OWN `dirs::home_dir()` as the
/// expected value rather than a passwd entry, which keeps the case honest on
/// Windows, where the function reads a known folder and does not consult `HOME`
/// at all.
#[test]
#[ignore = "driven by envfile_19d_home_unset_and_home_empty_both_resolve_to_the_dirs_fallback"]
#[allow(
    clippy::disallowed_methods,
    reason = "the oracle is the platform answer, independent of the routed lookup"
)]
fn envfile_19d_child_resolves_against_dirs_home_dir() {
    assert!(
        env::var_os("MCP_GW_TEST_ENVFILE19D_VARIANT").is_some(),
        "child must be launched by its parent, not run directly"
    );

    // GIVEN: a `~/...` entry, and this process's own idea of home
    let expected_home = dirs::home_dir().expect("dirs must fall back when HOME is unset or empty");
    let expected = expected_home.join("mcp-gw-test-envfile19d.env");

    let cfg_dir = tempfile::tempdir().unwrap();
    let cfg_path = cfg_dir.path().join("gateway.yaml");
    write_owner_only(
        &cfg_path,
        "env_files:\n  - \"~/mcp-gw-test-envfile19d.env\"\n",
    )
    .unwrap();

    // WHEN: startup evaluates it. The file is deliberately NOT created — a
    // missing path is skipped, and the RESOLUTION is what this row is about;
    // writing into the real home directory is not the test's business.
    let startup = Config::load_evaluated(Some(&cfg_path)).unwrap();

    // THEN: it resolved against this process's own `dirs::home_dir()`
    assert_eq!(
        startup.env_paths.as_paths(),
        std::slice::from_ref(&expected),
        "startup must resolve `~` against dirs::home_dir()"
    );

    // AND: a reload opens the same path, taking it from what startup recorded
    let reloaded = Config::load_with_overlay(Some(&cfg_path), &startup.env_paths).unwrap();
    assert_eq!(
        reloaded.env_paths.as_paths(),
        &[expected],
        "a reload must open the path startup recorded, not resolve it again"
    );

    println!("ENVFILE.19d child ok");
}

#[path = "frame_limit_tests.rs"]
mod frame_limit_tests;

#[path = "webhook_base_path_tests.rs"]
mod webhook_base_path_tests;
