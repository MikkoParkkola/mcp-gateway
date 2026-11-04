// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A resume reads the handle it proved, and each connection resumes its own
//! search.

use super::*;

#[test]
fn f9c_a_file_swapped_onto_the_path_after_the_identity_check_is_not_read() {
    let mut s = suspended(calls(1));
    let path = s.path.clone();
    set_after_identity(move || {
        let other = path.with_extension("other");
        write_from(&other, &[vec![Rec::Admin; 8]], 1, 1);
        std::fs::rename(&other, &path).unwrap();
    });
    // The call that proved the handle reads to the end on it; a later call
    // would restart, since the path now names another file.
    let page = s.resume_with(WIDE);
    assert!(
        !page.diag.restarted && !page.reset,
        "the proven handle is read"
    );
    assert_eq!(
        counters(std::slice::from_ref(&page)),
        vec![3, 4],
        "its rows, not the swapped file's"
    );
    assert!(
        page.rows.iter().all(|r| r.row["kind"] == "call"),
        "no row from the swapped file"
    );
}

#[test]
fn f9c_a_rename_or_unlink_after_the_open_leaves_the_read_on_the_same_bytes() {
    for unlink in [false, true] {
        let mut s = suspended(calls(1));
        let path = s.path.clone();
        set_after_identity(move || {
            if unlink {
                std::fs::remove_file(&path).unwrap();
            } else {
                std::fs::rename(&path, path.with_extension("moved")).unwrap();
            }
        });
        let page = s.resume_with(WIDE);
        assert!(
            !page.diag.restarted,
            "unlink {unlink}: no restart in that call"
        );
        assert_eq!(
            counters(std::slice::from_ref(&page)),
            vec![3, 4],
            "unlink {unlink}: the handle's bytes"
        );
    }
}

#[test]
fn f9e_a_resume_in_a_rotated_segment_crosses_into_the_next_without_restarting() {
    let mut s = suspended(calls(1));
    s.rotate();
    // The rotated file ends at record 4; the new active file goes on.
    // A run inside the next segment, so the search suspends there too.
    let next = vec![Rec::Call(None), junk(64 * 1024), Rec::Call(None)];
    let w = write_from(&s.path, &[next], 2, 5);
    let stop = w.marks.last().unwrap().clone();
    let l = log(&s.path, StreamKind::Activity);
    // Each call passes the last page's `next`, as the merge loop does.
    let cursor = s.cursor();
    let pages = drain(
        &l,
        Some(&cursor),
        Some(&stop),
        &Access::All,
        SMALL,
        &mut s.search,
    );
    assert!(
        pages.iter().all(|p| !p.diag.restarted),
        "no restart on crossing"
    );
    assert_eq!(counters(&pages), vec![3, 4, 5, 6]);
}

#[test]
fn f11_two_connections_each_resume_their_own_search() {
    let mut a = suspended(calls(1));
    // A second connection on the same log and cursor, suspended at another
    // offset by a smaller first budget.
    let path = a.path.clone();
    let l = log(&path, StreamKind::Activity);
    let stop = a.w.marks.last().unwrap().clone();
    let cursor = a.cursor();
    let half = Limits {
        matches: 200,
        bytes: SMALL.bytes / 2,
    };
    let mut b_search = Search::default();
    let b_first = rows_after(
        &l,
        Some(&cursor),
        Some(&stop),
        &Access::All,
        half,
        &mut b_search,
    )
    .unwrap();
    assert!(b_first.searching, "b is suspended too");
    assert_ne!(
        b_first.diag.read_end, a.first.diag.read_end,
        "at another offset"
    );
    let a_next = a.resume();
    let b_next = rows_after(
        &l,
        Some(&cursor),
        Some(&stop),
        &Access::All,
        SMALL,
        &mut b_search,
    )
    .unwrap();
    assert_eq!(
        a_next.diag.first_read, a.first.diag.read_end,
        "a resumes at its own offset"
    );
    assert_eq!(
        b_next.diag.first_read, b_first.diag.read_end,
        "b resumes at its own offset"
    );
}

#[test]
fn f12_a_new_connection_searches_from_its_cursor_not_an_old_offset() {
    let s = suspended(calls(1));
    let l = log(&s.path, StreamKind::Activity);
    let stop = s.w.marks.last().unwrap().clone();
    let mut fresh = Search::default();
    let first = rows_after(
        &l,
        Some(&s.cursor()),
        Some(&stop),
        &Access::All,
        SMALL,
        &mut fresh,
    )
    .unwrap();
    assert!(first.diag.first_read.is_some(), "the new connection read");
    assert!(
        first.diag.first_read < s.first.diag.read_end,
        "from the search's start, not the old offset"
    );
    let mut pages = vec![first];
    while pages.last().unwrap().more && pages.len() < 1000 {
        pages.push(
            rows_after(
                &l,
                Some(&s.cursor()),
                Some(&stop),
                &Access::All,
                SMALL,
                &mut fresh,
            )
            .unwrap(),
        );
    }
    assert!(pages.iter().all(|p| p.diag.bytes_read <= bound(SMALL)));
    assert_eq!(counters(&pages), vec![3, 4]);
}

#[test]
fn f9d_a_file_replaced_on_every_call_restarts_at_most_max_restarts_then_resets() {
    let mut s = suspended(calls(1));
    let mut pages = Vec::new();
    loop {
        s.replace_same_bytes();
        let p = s.resume();
        let done = p.reset || !p.more;
        pages.push(p);
        if done || pages.len() > 20 {
            break;
        }
    }
    let restarts = pages.iter().filter(|p| p.diag.restarted).count();
    assert!(restarts >= 1, "a replacement restarts");
    assert!(restarts <= usize::from(MAX_RESTARTS), "{restarts} restarts");
    assert!(pages.last().unwrap().reset, "then the page resets");
    assert!(
        pages.len() <= usize::from(MAX_RESTARTS) + 1,
        "{} calls",
        pages.len()
    );
}

#[test]
fn f9d_a_file_rotated_on_every_call_never_restarts_and_progresses() {
    let mut s = suspended(calls(1));
    let mut pages = Vec::new();
    let mut seq = 1;
    loop {
        std::fs::rename(&s.path, sealed_path(&s.path, seq)).unwrap();
        std::fs::write(&s.path, b"").unwrap();
        seq += 1;
        let p = s.resume();
        let more = p.more;
        pages.push(p);
        if !more || pages.len() > 1000 {
            break;
        }
    }
    assert!(pages.iter().all(|p| !p.diag.restarted && !p.reset));
    assert_eq!(counters(&pages), vec![3, 4]);
}
