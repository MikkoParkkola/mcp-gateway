// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A suspended search when the log moves under it: a rotation continues, any
//! change the resume cannot prove harmless restarts from the delivered id.

use super::*;

#[path = "forward_handles_tests.rs"]
mod handles;

/// A log with its cursor (record 2) past a junk run, in the active file, and
/// one call's suspended search on it.
struct Suspended {
    _dir: tempfile::TempDir,
    path: PathBuf,
    w: Written,
    search: Search,
    first: ForwardPage,
}

fn suspended(lead: Vec<Rec>) -> Suspended {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("inv.jsonl");
    let mut recs = lead;
    recs.push(junk(64 * 1024));
    recs.extend(calls(3));
    let w = write(&path, &[recs]);
    let mut search = Search::default();
    let first = suspend(&log(&path, StreamKind::Activity), &w.marks[w.marks.len() - 3], w.marks.last().unwrap(), &mut search);
    Suspended { _dir: dir, path, w, search, first }
}

impl Suspended {
    fn cursor(&self) -> Mark {
        self.w.marks[self.w.marks.len() - 3].clone()
    }

    fn resume(&mut self) -> ForwardPage {
        let (cursor, stop) = (self.cursor(), self.w.marks.last().unwrap().clone());
        rows_after(&log(&self.path, StreamKind::Activity), Some(&cursor), Some(&stop), &Access::All, SMALL, &mut self.search).unwrap()
    }

    /// Rename the active file to a sealed name and start an empty one.
    fn rotate(&self) {
        std::fs::rename(&self.path, sealed_path(&self.path, 1)).unwrap();
        std::fs::write(&self.path, b"").unwrap();
    }

    /// Replace the active file with a copy of its bytes: a new identity.
    fn replace_same_bytes(&self) {
        let bytes = std::fs::read(&self.path).unwrap();
        std::fs::remove_file(&self.path).unwrap();
        std::fs::write(&self.path, bytes).unwrap();
    }

    /// Rewrite the record before the run in place, same length: a decoy
    /// where the anchor was.
    fn change_anchor_in_place(&self) {
        let (_, start, end) = self.w.at[0].clone();
        let mut bytes = std::fs::read(&self.path).unwrap();
        let line = &mut bytes[usize::try_from(start).unwrap()..usize::try_from(end).unwrap()];
        let at = line.windows(4).position(|w| w == b"srv\"").unwrap();
        line[at..at + 3].copy_from_slice(b"vrs");
        std::fs::write(&self.path, bytes).unwrap();
    }
}

#[test]
fn f9_a_resumed_search_continues_where_the_last_call_stopped() {
    let mut s = suspended(calls(1));
    let saved = s.first.read_end.expect("the suspended call read");
    let next = s.resume();
    assert_eq!(next.first_read, Some(saved), "resumed, not searched again");
    assert!(!next.restarted);
}

#[test]
fn f9b_rotation_keeps_the_identity_and_continues() {
    let mut s = suspended(calls(1));
    let saved = s.first.read_end.unwrap();
    s.rotate();
    let next = s.resume();
    assert_eq!(next.first_read, Some(saved), "the renamed file is read on");
    assert!(!next.restarted, "a rotation is not a restart");
}

#[test]
fn f9b_a_replaced_file_restarts_and_still_serves_every_row() {
    let mut s = suspended(calls(1));
    s.replace_same_bytes();
    let next = s.resume();
    assert!(next.restarted, "a new identity is a restart");
    let mut pages = vec![next];
    while pages.last().unwrap().more && pages.len() < 1000 {
        pages.push(s.resume());
    }
    assert_eq!(counters(&pages), vec![3, 4], "no row skipped after the restart");
}

#[test]
fn f9b_an_in_place_change_to_the_anchor_record_restarts() {
    let mut s = suspended(calls(1));
    s.change_anchor_in_place();
    assert!(s.resume().restarted, "the anchor no longer hashes the same");
}

#[test]
fn f9b_a_shrink_below_the_offset_restarts() {
    let mut s = suspended(calls(1));
    let file = std::fs::OpenOptions::new().write(true).open(&s.path).unwrap();
    file.set_len(s.w.at[0].2 + 10).unwrap();
    let next = s.resume();
    assert!(next.restarted, "shorter than the offset");
    assert!(next.first_read.is_some_and(|o| o < s.first.read_end.unwrap()), "read from the search start");
}

#[test]
fn f9b_an_unreadable_identity_restarts() {
    let mut s = suspended(calls(1));
    IDENTITY_FAILS.with(|f| f.set(true));
    let next = s.resume();
    IDENTITY_FAILS.with(|f| f.set(false));
    assert!(next.restarted, "an identity that cannot be read is never trusted");
}

#[test]
fn f9b_retention_removing_the_segment_restarts_into_a_reset() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("inv.jsonl");
    let mut sealed = calls(1);
    sealed.push(junk(64 * 1024));
    sealed.extend(calls(1));
    let w = write(&path, &[sealed, calls(2)]);
    let l = log(&path, StreamKind::Activity);
    let mut search = Search::default();
    suspend(&l, &w.marks[1], w.marks.last().unwrap(), &mut search);
    std::fs::remove_file(sealed_path(&path, 1)).unwrap();
    // A decoy in a file at the removed name: the cursor's counter, another hash.
    write_from(&sealed_path(&path, 1), &[calls(2)], 1, 1);
    let next = rows_after(&l, Some(&w.marks[1]), w.marks.last(), &Access::All, SMALL, &mut search).unwrap();
    assert!(next.restarted, "the segment's identity is gone");
}

#[test]
fn e2_with_no_anchor_yet_a_rotation_continues_and_a_replacement_restarts() {
    let mut rotated = suspended(Vec::new());
    let saved = rotated.first.read_end.unwrap();
    rotated.rotate();
    let next = rotated.resume();
    assert_eq!((next.first_read, next.restarted), (Some(saved), false), "rotation");
    let mut replaced = suspended(Vec::new());
    replaced.replace_same_bytes();
    assert!(replaced.resume().restarted, "replacement");
}
