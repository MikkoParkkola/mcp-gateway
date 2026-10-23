// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8664 (DUPC-7.PR7.6): a server path with `~//` stays under the home.

/// `home.join("/x")` would replace the home with the filesystem root, so a
/// configured `~//.mcp-gateway/events` would write under `/.mcp-gateway`.
#[test]
fn a_doubled_slash_after_the_tilde_stays_under_the_home() {
    let home = crate::home_dir::home_dir().expect("the test host has a home directory");
    assert_eq!(super::expand_home_path("~//x"), home.join("x"));
}
