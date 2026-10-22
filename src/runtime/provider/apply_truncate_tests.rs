// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8655.UTF8.1: child-process output is cut at a char boundary. A cut
//! inside a multi-byte character panicked, and the release profile aborts.

use std::borrow::Cow;

use super::truncate_process_text;

const SUFFIX: &str = "...[truncated]";

#[test]
fn a_multi_byte_character_at_the_cut_is_not_split() {
    // 4095 ASCII bytes, then a 3-byte character spanning bytes 4095..4098.
    let text = format!("{}€ and more", "a".repeat(4095));
    let out = truncate_process_text(Cow::Owned(text.clone()));
    let body = out.strip_suffix(SUFFIX).expect("the cut is marked");
    assert_eq!(
        body.len(),
        4095,
        "backs off to the boundary before the character"
    );
    assert!(text.starts_with(body));
}

#[test]
fn ascii_past_the_limit_is_cut_at_the_limit() {
    let out = truncate_process_text(Cow::Owned("a".repeat(5000)));
    assert_eq!(out, format!("{}{SUFFIX}", "a".repeat(4096)));
}

#[test]
fn text_within_the_limit_is_unchanged() {
    let text = format!("{}€", "a".repeat(4093));
    assert_eq!(text.len(), 4096);
    assert_eq!(truncate_process_text(Cow::Borrowed(&text)), text);
}
