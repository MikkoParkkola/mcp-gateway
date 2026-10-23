// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8664 (DUPC-7.PR7.6): a credential path uses the gateway's one tilde rule.

use super::expand_home_dir;

/// Read, never set: setting the home is process-wide and would race other tests.
fn home() -> std::path::PathBuf {
    crate::home_dir::home_dir().expect("the test host has a home directory")
}

#[test]
fn a_bare_tilde_names_the_home_directory() {
    assert_eq!(expand_home_dir("~").unwrap(), home());
}

/// `home.join("/x")` would replace the home with the filesystem root.
#[test]
fn a_doubled_slash_after_the_tilde_stays_under_the_home() {
    assert_eq!(expand_home_dir("~//x.json").unwrap(), home().join("x.json"));
}
