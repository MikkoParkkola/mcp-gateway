// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Controls for the allocator's free scan (MIK-9070): it must see a copy of a
//! marker freed unwiped, must not see one wiped on drop, and must see the old
//! block a growing holder leaves behind. Without these, a scan that reads
//! nothing would pass every row that uses it.

use std::hint::black_box;

use zeroize::Zeroizing;

use super::alloc_meter::{MIN_MARKER, isolate, scan_frees};

/// A marker no other test writes, longer than any inline storage.
const MARKER: &[u8] =
    b"free-scan-marker:7f3a9c2e-4b1d-4e8a-9c6f-2d5b8e1a7c30:credential-shaped-bytes";

const _: () = assert!(MARKER.len() >= MIN_MARKER);

fn test_path(name: &str) -> String {
    let module = module_path!();
    let module = module
        .split_once("::")
        .map_or(module, |(_crate, rest)| rest);
    format!("{module}::{name}")
}

fn marker() -> String {
    String::from_utf8(MARKER.to_vec()).expect("the marker is ASCII")
}

/// Positive control: a credential held in a plain vector and dropped goes
/// back to the allocator still holding it, and the scan counts it.
#[test]
fn a_plain_copy_dropped_is_seen() {
    if isolate(&test_path("a_plain_copy_dropped_is_seen")) {
        return;
    }
    let ((), scanned) = scan_frees(MARKER, || {
        let held = vec![("Authorization".to_string(), marker())];
        drop(black_box(held));
    });
    assert!(
        scanned.hits >= 1,
        "an unwiped copy was freed and the scan saw none: {scanned:?}"
    );
}

/// Negative control: the same credential in the zeroizing holder is wiped
/// before its blocks are freed, so the scan counts nothing.
#[test]
fn a_wiped_copy_dropped_is_not_seen() {
    if isolate(&test_path("a_wiped_copy_dropped_is_not_seen")) {
        return;
    }
    let ((), scanned) = scan_frees(MARKER, || {
        let held = Zeroizing::new(vec![("Authorization".to_string(), marker())]);
        drop(black_box(held));
    });
    assert!(
        scanned.searched >= 1,
        "no block was freed, so a zero proves nothing: {scanned:?}"
    );
    assert_eq!(scanned.hits, 0, "a wiped copy was counted as unwiped");
}

/// A zeroizing holder wipes only the block it owns when dropped: a block it
/// outgrew was freed by the move, still holding the marker. The scan sees it.
#[test]
fn a_wiped_holder_that_grew_leaves_its_old_block() {
    if isolate(&test_path("a_wiped_holder_that_grew_leaves_its_old_block")) {
        return;
    }
    let (moved, scanned) = scan_frees(MARKER, || {
        let mut held = Zeroizing::new(MARKER.to_vec());
        let before = held.as_ptr();
        // Far past any allocator's in-place growth: the buffer must move, and
        // the move frees the old block still holding the marker.
        held.reserve(1 << 22);
        let moved = held.as_ptr() != before;
        drop(black_box(held));
        moved
    });
    assert!(moved, "premise: the holder's buffer moved when it grew");
    assert!(
        scanned.hits >= 1,
        "the block a growing holder left behind was not seen: {scanned:?}"
    );
}
