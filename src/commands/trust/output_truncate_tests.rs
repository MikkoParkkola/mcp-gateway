// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8655.UTF8.2: a table cell is cut at a char boundary. Slicing inside a
//! multi-byte character panicked and ended the `trust` command.

use super::truncate;

#[test]
fn a_multi_byte_character_at_the_cut_is_not_split() {
    // The cut for 28 is byte 25, inside "é" (bytes 24..26).
    let name = format!("{}éxyz", "a".repeat(24));
    assert!(name.len() > 28);
    let cell = truncate(&name, 28);
    assert_eq!(cell, format!("{}...", "a".repeat(24)));
    assert!(cell.len() <= 28);
}

#[test]
fn ascii_is_cut_to_the_width_with_an_ellipsis() {
    assert_eq!(truncate(&"a".repeat(40), 28), format!("{}...", "a".repeat(25)));
    assert_eq!(truncate("short", 28), "short");
}
