// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The first line of a segment is read without reading the window around it:
//! its allocation tracks the line, and its result for an empty file, a segment
//! with no newline within the cap, and blank or CRLF leading lines is the
//! one the 4 MiB window read gave.

use std::path::Path;

use super::read_first_line;
use crate::gateway::alloc_meter::measure;

const WINDOW: usize = 4 * 1024 * 1024;

fn file_with(dir: &tempfile::TempDir, body: &[u8]) -> std::path::PathBuf {
    let path = dir.path().join("segment.jsonl");
    std::fs::write(&path, body).unwrap();
    path
}

fn read(path: &Path) -> Option<String> {
    read_first_line(path).unwrap()
}

#[test]
fn first_line_allocates_on_the_order_of_the_line_not_the_window() {
    let dir = tempfile::tempdir().unwrap();
    let first = format!("{{\"event\":\"opened\",\"pad\":\"{}\"}}", "x".repeat(170));
    let mut body = format!("{first}\n").into_bytes();
    body.extend(std::iter::repeat_n(b'y', 6 * 1024 * 1024));
    let path = file_with(&dir, &body);
    let (line, measured) = measure(|| read(&path));
    assert_eq!(line.as_deref(), Some(first.as_str()));
    assert!(measured.bytes <= 64 * 1024, "{measured}");
}

#[test]
fn first_line_of_an_empty_file_is_none() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(read(&file_with(&dir, b"")), None);
}

#[test]
fn first_line_with_no_newline_within_the_cap_is_the_cap() {
    let dir = tempfile::tempdir().unwrap();
    let line = read(&file_with(&dir, &vec![b'a'; WINDOW + 4096])).unwrap();
    assert_eq!(line.len(), WINDOW);
}

#[test]
fn first_line_skips_blank_lines_and_strips_a_carriage_return() {
    let dir = tempfile::tempdir().unwrap();
    let path = file_with(&dir, b"\n  \r\nsecond\r\nthird\n");
    assert_eq!(read(&path).as_deref(), Some("second"));
}

#[test]
fn first_line_of_a_file_of_blank_lines_is_none() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(read(&file_with(&dir, b"\n \n\r\n")), None);
}

#[test]
fn first_line_keeps_a_bare_carriage_return_at_eof() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(read(&file_with(&dir, b"abc\r")).as_deref(), Some("abc\r"));
}

#[test]
fn first_line_keeps_a_carriage_return_at_the_window_cap_boundary() {
    let dir = tempfile::tempdir().unwrap();
    // The window ends on the `\r`; its `\n` lies beyond the cap, so the cap
    // cut the line and no terminating newline was removed.
    let mut body = vec![b'a'; WINDOW - 1];
    body.extend_from_slice(b"\r\nnext\n");
    let line = read(&file_with(&dir, &body)).unwrap();
    assert_eq!(line.len(), WINDOW);
    assert!(line.ends_with('\r'));
}
