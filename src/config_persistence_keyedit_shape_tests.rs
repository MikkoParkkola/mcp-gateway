// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The bytes proof on its own: every way an edit could disturb a line it
//! did not mean to touch must fail it.

use super::{Lines, Origin};

/// `original`'s lines, then `edit` applied to the record directly.
fn proven(original: &str, edit: impl FnOnce(&mut Vec<(String, Origin)>)) -> bool {
    let mut lines = Lines::new(original);
    edit(&mut lines.lines);
    lines.bytes_hold(original)
}

#[test]
fn an_untouched_record_holds() {
    assert!(proven("a: 1 # one\nb: 2\n", |_| {}));
}

#[test]
fn a_changed_kept_line_fails() {
    assert!(!proven("a: 1 # one\nb: 2\n", |l| l[0].0 = "a: 1 # two\n".to_owned()));
}

#[test]
fn a_changed_prefix_or_suffix_around_a_value_fails() {
    let replaced = Origin::Replaced {
        line: 0,
        before: 3,
        after: 6,
    };
    // `a: ` kept and ` # one` kept: holds.
    assert!(proven("a: 1 # one\n", |l| l[0] =
        ("a: 9 # one\n".to_owned(), replaced.clone())));
    assert!(!proven("a: 1 # one\n", |l| l[0] =
        ("b: 9 # one\n".to_owned(), replaced.clone())));
    assert!(!proven("a: 1 # one\n", |l| l[0] =
        ("a: 9 # two\n".to_owned(), replaced.clone())));
}

#[test]
fn an_interior_line_ending_flip_fails() {
    assert!(!proven("a: 1\nb: 2\n", |l| l[0].0 = "a: 1\r\n".to_owned()));
}

#[test]
fn reordered_lines_fail() {
    assert!(!proven("a: 1\nb: 2\n", |l| l.swap(0, 1)));
}

/// An unterminated last line may gain only the ending an insert adds (the
/// file's own, else `\n`), never another one.
#[test]
fn an_unterminated_last_line_gains_only_the_files_own_ending() {
    let gains = |ending: &str| {
        proven("a: 1\nb: 2", |l| {
            l[1].0 = format!("b: 2{ending}");
            l.push(("c: 3".to_owned(), Origin::Inserted));
        })
    };
    assert!(gains("\n"));
    assert!(!gains("\r\n"), "a CRLF flip on the last line passed");
}

/// A lone carriage return is text, not an ending, as the splice reads it.
#[test]
fn a_lone_carriage_return_is_not_an_ending() {
    assert!(!proven("a: 1\nb: 2\n", |l| l[1].0 = "b: 2\r".to_owned()));
}
