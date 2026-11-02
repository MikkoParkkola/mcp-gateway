// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The cursor's search: bounded per call, suspended between calls, and
//! resumed only on bytes proven the same.

use super::*;

#[path = "forward_moves_tests.rs"]
mod moves;

/// The cap on one record, as the logger enforces it.
const CAP: usize = 4 * 1024 * 1024;
const SMALL: Limits = Limits {
    matches: 200,
    bytes: 4096,
};

/// A log whose cursor (record 2) sits past `run` bytes of junk lines, so a
/// search for it takes several calls of [`SMALL`].
fn far_cursor(path: &Path, run: Rec, tail: usize) -> Written {
    far_cursor_of(path, run, tail, &Rec::Call(Some((X, "s"))))
}

/// [`far_cursor`] with records of `rec`'s kind.
fn far_cursor_of(path: &Path, run: Rec, tail: usize, rec: &Rec) -> Written {
    let mut recs = vec![rec.clone()];
    recs.push(run);
    recs.extend(vec![rec.clone(); 1 + tail]);
    write(path, &[recs])
}

/// A malformed run of about `bytes`, as many short lines: longer than a
/// budget, so a search across it suspends.
fn junk(bytes: usize) -> Rec {
    Rec::Junks(bytes.div_ceil(2048), 2047)
}

/// The per-call bound: the budget, one record within the cap, and the
/// anchor's re-read, which is itself within the cap.
fn bound(b: Limits) -> u64 {
    b.bytes + 2 * (CAP as u64 + 1)
}

/// Suspend a search for `cursor` with one call; the call must not finish it.
fn suspend(l: &Log<'_>, cursor: &Mark, stop: &Mark, search: &mut Search) -> ForwardPage {
    let page = rows_after(l, Some(cursor), Some(stop), &Access::All, SMALL, search).unwrap();
    assert!(
        page.searching && page.more,
        "the fixture suspends the search"
    );
    page
}

#[test]
fn f5b_a_search_across_a_malformed_run_spends_one_budget_per_call_and_completes() {
    for kind in [StreamKind::Activity, StreamKind::Config] {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("log.jsonl");
        let rec = if kind == StreamKind::Activity {
            Rec::Call(None)
        } else {
            Rec::Config
        };
        let w = far_cursor_of(&path, junk(64 * 1024), 2, &rec);
        let l = log(&path, kind);
        let mut search = Search::default();
        let pages = drain(
            &l,
            Some(&w.marks[1]),
            w.marks.last(),
            &Access::All,
            SMALL,
            &mut search,
        );
        assert!(pages.len() > 2, "{kind:?}: the search took several calls");
        for p in &pages {
            assert!(
                p.diag.bytes_read <= bound(SMALL),
                "{kind:?}: {} over the bound",
                p.diag.bytes_read
            );
        }
        assert!(
            pages.iter().all(|p| !p.reset),
            "{kind:?}: a found cursor never resets"
        );
        assert_eq!(
            counters(&pages),
            vec![3, 4],
            "{kind:?}: rows after the cursor"
        );
    }
}

#[test]
fn f5b_a_newline_free_run_past_the_budget_and_the_cap_is_crossed_in_bounded_calls() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("inv.jsonl");
    let w = far_cursor(&path, Rec::Junk(CAP + 1024 * 1024), 1);
    let l = log(&path, StreamKind::Activity);
    let mut search = Search::default();
    let pages = drain(
        &l,
        Some(&w.marks[1]),
        w.marks.last(),
        &Access::All,
        SMALL,
        &mut search,
    );
    assert!(pages.iter().all(|p| p.diag.bytes_read <= bound(SMALL)));
    assert!(
        pages.iter().all(|p| p.diag.bytes_read > 0 || !p.more),
        "every call progresses"
    );
    assert_eq!(counters(&pages), vec![3]);
}

#[test]
fn f5c_a_resumed_search_that_finds_the_cursor_gone_resets_and_forgets_its_offset() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("inv.jsonl");
    let w = far_cursor(&path, junk(64 * 1024), 1);
    let l = log(&path, StreamKind::Activity);
    let wrong = Mark {
        counter: 2,
        hash16: "0000000000000000".into(),
    };
    let mut search = Search::default();
    let first = suspend(&l, &wrong, w.marks.last().unwrap(), &mut search);
    let stale = first.diag.bytes_read;
    let pages = drain(
        &l,
        Some(&wrong),
        w.marks.last(),
        &Access::All,
        SMALL,
        &mut search,
    );
    assert!(
        pages.iter().any(|p| p.reset),
        "a mismatched prefix found on resume resets"
    );
    let after = rows_after(&l, None, w.marks.last(), &Access::All, SMALL, &mut search).unwrap();
    assert!(
        after.diag.first_read.is_some_and(|o| o < stale),
        "the next search starts afresh"
    );
}

#[test]
fn f5d_a_cursor_in_a_segment_whose_first_line_is_unreadable_is_found() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("inv.jsonl");
    // Segment 1 starts with a torn line; the cursor is its first record.
    let w = write(
        &path,
        &[
            vec![Rec::Junk(100), Rec::Call(None), Rec::Call(None)],
            calls(2),
        ],
    );
    let l = log(&path, StreamKind::Activity);
    let mut search = Search::default();
    let pages = drain(
        &l,
        Some(&w.marks[0]),
        w.marks.last(),
        &Access::All,
        WIDE,
        &mut search,
    );
    assert!(
        pages.iter().all(|p| !p.reset),
        "the cursor is kept, not gone"
    );
    assert_eq!(counters(&pages), vec![2, 3, 4]);
}

#[test]
fn f5d_the_cursor_record_straddling_the_budget_or_a_segment_is_found() {
    for budget in [1000_u64, 1023, 1024, 1025, 1100] {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("inv.jsonl");
        let w = write(
            &path,
            &[
                vec![Rec::Junk(900), Rec::Call(None), Rec::Call(None)],
                calls(2),
            ],
        );
        let l = log(&path, StreamKind::Activity);
        let b = Limits {
            matches: 200,
            bytes: budget,
        };
        let mut search = Search::default();
        let pages = drain(
            &l,
            Some(&w.marks[1]),
            w.marks.last(),
            &Access::All,
            b,
            &mut search,
        );
        assert!(
            pages.iter().all(|p| !p.reset),
            "budget {budget}: never reset"
        );
        assert_eq!(
            counters(&pages),
            vec![3, 4],
            "budget {budget}: crosses into the next segment"
        );
    }
}

#[test]
fn f5e_an_oversized_visible_record_is_delivered_alone_then_paging_resumes() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("inv.jsonl");
    let w = write(
        &path,
        &[vec![Rec::Call(None), Rec::Big(64 * 1024), Rec::Call(None)]],
    );
    let l = log(&path, StreamKind::Activity);
    let pages = drain(
        &l,
        Some(&w.marks[0]),
        w.marks.last(),
        &Access::All,
        SMALL,
        &mut Search::default(),
    );
    assert_eq!(counters(&pages), vec![2, 3]);
}

#[test]
fn f5e_an_oversized_record_hidden_from_the_caller_is_passed() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("inv.jsonl");
    let w = write(
        &path,
        &[vec![
            Rec::Call(Some((X, "s"))),
            Rec::Big(64 * 1024),
            Rec::Call(Some((X, "s"))),
        ]],
    );
    let own = Access::Own {
        issuer: X.into(),
        subject: "s".into(),
    };
    let l = log(&path, StreamKind::Activity);
    let pages = drain(
        &l,
        Some(&w.marks[0]),
        w.marks.last(),
        &own,
        SMALL,
        &mut Search::default(),
    );
    assert_eq!(counters(&pages), vec![3]);
}

#[test]
fn f5e_an_oversized_cursor_record_is_validated_in_one_call() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("inv.jsonl");
    let w = write(&path, &[vec![Rec::Big(64 * 1024), Rec::Call(None)]]);
    let l = log(&path, StreamKind::Activity);
    let mut search = Search::default();
    let page = rows_after(
        &l,
        Some(&w.marks[0]),
        w.marks.last(),
        &Access::All,
        SMALL,
        &mut search,
    )
    .unwrap();
    assert!(
        !page.reset && !page.searching,
        "validated in its first call"
    );
    let next = page.next.clone();
    let rest = drain(
        &l,
        next.as_ref(),
        w.marks.last(),
        &Access::All,
        SMALL,
        &mut search,
    );
    let mut got = counters(&[page]);
    got.extend(counters(&rest));
    assert_eq!(got, vec![2]);
}

#[test]
fn f5e_a_cursor_record_over_the_cap_is_gone() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("inv.jsonl");
    let w = write(
        &path,
        &[vec![Rec::Call(None), Rec::Big(CAP + 16), Rec::Call(None)]],
    );
    let l = log(&path, StreamKind::Activity);
    let pages = drain(
        &l,
        Some(&w.marks[1]),
        w.marks.last(),
        &Access::All,
        SMALL,
        &mut Search::default(),
    );
    assert!(
        pages.iter().any(|p| p.reset),
        "a record the log cannot hold is not a cursor"
    );
    assert!(pages.len() < 2_000, "and it does not stall");
}

#[test]
fn f5f_records_at_the_cap_each_move_a_call_forward() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("inv.jsonl");
    let mut recs = calls(1);
    recs.extend(vec![Rec::Big(CAP - 1024); 3]);
    let w = write(&path, &[recs]);
    let l = log(&path, StreamKind::Activity);
    let mut search = Search::default();
    let pages = drain(
        &l,
        Some(&w.marks[0]),
        w.marks.last(),
        &Access::All,
        SMALL,
        &mut search,
    );
    assert_eq!(counters(&pages), vec![2, 3, 4]);
    let mut last = Some(w.marks[0].clone());
    for p in &pages {
        assert!(p.diag.bytes_read <= bound(SMALL), "within the bound");
        assert_ne!(p.next, last, "every call delivers or passes one record");
        last = p.next.clone();
    }
    assert!(
        pages.iter().skip(1).any(|p| p.diag.anchor_bytes > 0),
        "anchor re-reads are counted"
    );
}

/// A log of three calls whose second line, newline included, is `len` bytes.
fn with_second_line_of(path: &Path, len: usize) -> Written {
    // A padded record grows by one byte per pad byte: measure it once unpadded.
    let probe = write(path, &[vec![Rec::Call(None), Rec::Big(0), Rec::Call(None)]]);
    let unpadded = usize::try_from(probe.at[1].2 - probe.at[1].1).unwrap();
    let w = write(
        path,
        &[vec![
            Rec::Call(None),
            Rec::Big(len - unpadded),
            Rec::Call(None),
        ]],
    );
    assert_eq!(
        usize::try_from(w.at[1].2 - w.at[1].1).unwrap(),
        len,
        "fixture line length"
    );
    w
}

#[test]
fn a_record_at_the_cap_is_read_and_one_byte_over_is_refused() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("inv.jsonl");
    let l = log(&path, StreamKind::Activity);

    let w = with_second_line_of(&path, CAP);
    let pages = drain(
        &l,
        Some(&w.marks[0]),
        w.marks.last(),
        &Access::All,
        WIDE,
        &mut Search::default(),
    );
    assert_eq!(
        counters(&pages),
        vec![2, 3],
        "a record of exactly the cap is a record"
    );

    let w = with_second_line_of(&path, CAP + 1);
    let pages = drain(
        &l,
        Some(&w.marks[0]),
        w.marks.last(),
        &Access::All,
        WIDE,
        &mut Search::default(),
    );
    assert!(
        !counters(&pages).contains(&2),
        "a record one byte over the cap is never served"
    );
}
