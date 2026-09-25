// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The default capability directories name nothing outside the working tree.
//!
//! An earlier default appended a private capability checkout under
//! `$HOME/github` whenever it existed, so a gateway loaded every capability found
//! at one developer's checkout path without any configuration naming it.
//!
//! Lives in its own test binary because it sets `HOME`: `env::set_var` is
//! unsafe in edition 2024, the library forbids unsafe, and this is the only
//! test in the process, so no other thread reads the environment meanwhile.

use mcp_gateway::config::CapabilityConfig;

#[test]
fn default_capability_directories_ignore_a_private_checkout_under_home() {
    let home = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(home.path().join("github/mcp-gateway-private/capabilities"))
        .expect("create the private checkout path");
    // SAFETY: the only test in this binary; nothing else reads the environment.
    unsafe { std::env::set_var("HOME", home.path()) };

    assert_eq!(
        CapabilityConfig::default().directories,
        vec!["capabilities".to_string()],
        "a directory that merely exists under HOME must not become a capability source"
    );
}
