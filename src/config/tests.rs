// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tests for the configuration module.

use std::env;

use super::*;
use crate::gateway::test_helpers::write_owner_only;

mod capability_name;
mod env_files;
mod error_budget;
mod idle_and_agents;
mod load_error;
mod loading;
mod pattern_grammar;
mod server_name_refusal;
mod validate_config;

/// The child half of ENVFILE.19d: with `HOME` unset or empty, `~` still
/// resolves against the routed home, never against "" or the working dir. A
/// test build's routed home is its private test home, so the platform's own
/// fallback (`dirs::home_dir()` when `HOME` is unset) is not observable here.
#[test]
#[ignore = "driven by envfile_19d_home_unset_and_home_empty_both_resolve_to_the_routed_home"]
fn envfile_19d_child_resolves_against_the_routed_home() {
    assert!(
        env::var_os("MCP_GW_TEST_ENVFILE19D_VARIANT").is_some(),
        "child must be launched by its parent, not run directly"
    );

    // GIVEN: a `~/...` entry, and this process's own idea of home
    let expected_home = crate::home_dir::home_dir().expect("a test process always has a home");
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

    // THEN: it resolved against this process's routed home
    assert_eq!(
        startup.env_paths.as_paths(),
        std::slice::from_ref(&expected),
        "startup must resolve `~` against the routed home"
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
