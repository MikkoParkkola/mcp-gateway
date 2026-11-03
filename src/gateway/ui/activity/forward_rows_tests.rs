// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Order, keep, paging and the stop, against fixture logs.

use super::*;

fn dir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

#[test]
fn f1_rows_arrive_in_counter_order_across_segments_none_lost_or_repeated() {
    let d = dir();
    let path = d.path().join("inv.jsonl");
    let w = write(&path, &[calls(3), calls(4), calls(5)]);
    let l = log(&path, StreamKind::Activity);
    let tight = Limits {
        matches: 2,
        bytes: 8 << 20,
    };
    let pages = drain(
        &l,
        None,
        w.marks.last(),
        &Access::All,
        tight,
        &mut Search::default(),
    );
    assert_eq!(counters(&pages), (1..=12).collect::<Vec<_>>());
}

#[test]
fn f1b_a_clock_rollback_keeps_counter_order() {
    let d = dir();
    let path = d.path().join("inv.jsonl");
    let w = write(&path, &[calls(4)]);
    // Rewrite record 3's time earlier than record 2's; the chain is the order.
    let text = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<String> = text
        .lines()
        .enumerate()
        .map(|(i, l)| {
            if i == 2 {
                l.replace("2026-11-02T10:00:00", "2026-11-02T09:00:00")
            } else {
                l.to_owned()
            }
        })
        .collect();
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();
    let l = log(&path, StreamKind::Activity);
    let pages = drain(
        &l,
        None,
        w.marks.last(),
        &Access::All,
        WIDE,
        &mut Search::default(),
    );
    assert_eq!(counters(&pages), vec![1, 2, 3, 4]);
}

#[test]
fn f2_a_missing_cursor_starts_at_the_oldest_kept_record() {
    let d = dir();
    let path = d.path().join("inv.jsonl");
    let w = write_from(&path, &[calls(3)], 7, 40);
    let l = log(&path, StreamKind::Activity);
    let pages = drain(
        &l,
        None,
        w.marks.last(),
        &Access::All,
        WIDE,
        &mut Search::default(),
    );
    assert_eq!(counters(&pages), vec![40, 41, 42]);
}

#[test]
fn f2_a_hash_prefix_mismatch_resets() {
    let d = dir();
    let path = d.path().join("inv.jsonl");
    let w = write(&path, &[calls(5)]);
    let wrong = Mark {
        counter: 2,
        hash16: "0000000000000000".into(),
    };
    let l = log(&path, StreamKind::Activity);
    let pages = drain(
        &l,
        Some(&wrong),
        w.marks.last(),
        &Access::All,
        WIDE,
        &mut Search::default(),
    );
    assert!(pages.iter().any(|p| p.reset), "a mismatched prefix resets");
}

#[test]
fn f2_a_counter_past_retention_resets() {
    let d = dir();
    let path = d.path().join("inv.jsonl");
    let w = write_from(&path, &[calls(3)], 9, 50);
    let gone = Mark {
        counter: 10,
        hash16: w.marks[0].hash16.clone(),
    };
    let l = log(&path, StreamKind::Activity);
    let pages = drain(
        &l,
        Some(&gone),
        w.marks.last(),
        &Access::All,
        WIDE,
        &mut Search::default(),
    );
    assert!(
        pages.iter().any(|p| p.reset),
        "a counter no longer kept resets"
    );
}

#[test]
fn f3_own_gets_only_its_own_calls_and_next_moves_past_refused_rows() {
    let d = dir();
    let path = d.path().join("inv.jsonl");
    let recs = vec![
        Rec::Call(Some((X, "s"))),
        Rec::Call(Some((X, "t"))),
        Rec::Call(None),
        Rec::Admin,
        Rec::Call(Some((X, "s"))),
        Rec::Call(Some((X, "t"))),
    ];
    let w = write(&path, &[recs]);
    let own = Access::Own {
        issuer: X.into(),
        subject: "s".into(),
    };
    let l = log(&path, StreamKind::Activity);
    let page = rows_after(&l, None, w.marks.last(), &own, WIDE, &mut Search::default()).unwrap();
    assert_eq!(
        page.rows.iter().map(|r| r.mark.counter).collect::<Vec<_>>(),
        vec![1, 5]
    );
    assert_eq!(
        page.next.as_ref(),
        w.marks.last(),
        "next is past the refused tail"
    );
    let again = rows_after(
        &l,
        page.next.as_ref(),
        w.marks.last(),
        &own,
        WIDE,
        &mut Search::default(),
    )
    .unwrap();
    assert!(
        again.rows.is_empty() && !again.reset,
        "the refused rows never return"
    );
}

#[test]
fn f4_the_row_limit_ends_a_page_with_more_and_the_next_resumes() {
    let d = dir();
    let path = d.path().join("inv.jsonl");
    let w = write(&path, &[calls(5)]);
    let l = log(&path, StreamKind::Activity);
    let two = Limits {
        matches: 2,
        bytes: 8 << 20,
    };
    let first = rows_after(
        &l,
        None,
        w.marks.last(),
        &Access::All,
        two,
        &mut Search::default(),
    )
    .unwrap();
    assert_eq!(first.rows.len(), 2);
    assert!(first.more);
    let pages = drain(
        &l,
        first.next.as_ref(),
        w.marks.last(),
        &Access::All,
        two,
        &mut Search::default(),
    );
    assert_eq!(counters(&pages), vec![3, 4, 5]);
}

#[test]
fn f4_the_byte_budget_ends_a_page_with_no_visible_rows_with_more() {
    let d = dir();
    let path = d.path().join("inv.jsonl");
    let mut recs = vec![Rec::Call(Some((X, "t"))); 40];
    recs.push(Rec::Call(Some((X, "s"))));
    let w = write(&path, &[recs]);
    let own = Access::Own {
        issuer: X.into(),
        subject: "s".into(),
    };
    let l = log(&path, StreamKind::Activity);
    let small = Limits {
        matches: 200,
        bytes: 1024,
    };
    let first = rows_after(
        &l,
        None,
        w.marks.last(),
        &own,
        small,
        &mut Search::default(),
    )
    .unwrap();
    assert!(
        first.rows.is_empty() && first.more,
        "a budget-ended empty page says more"
    );
    assert!(first.next.is_some(), "and still moves on");
    let pages = drain(
        &l,
        first.next.as_ref(),
        w.marks.last(),
        &own,
        small,
        &mut Search::default(),
    );
    assert_eq!(counters(&pages), vec![41]);
}

#[test]
fn f5_an_unreadable_run_longer_than_the_budget_is_crossed_and_never_served() {
    let d = dir();
    let path = d.path().join("inv.jsonl");
    let mut recs = calls(1);
    recs.extend(vec![Rec::Junk(500); 20]);
    recs.extend(calls(1));
    let w = write(&path, &[recs]);
    let l = log(&path, StreamKind::Activity);
    let small = Limits {
        matches: 200,
        bytes: 2048,
    };
    let mut search = Search::default();
    let pages = drain(
        &l,
        Some(&w.marks[0]),
        w.marks.last(),
        &Access::All,
        small,
        &mut search,
    );
    assert_eq!(counters(&pages), vec![2]);
    assert!(pages.len() > 1, "the run took more than one call");
    assert!(
        pages.iter().all(|p| p.diag.bytes_read <= 2048 + 4096),
        "each call within its bound"
    );
}

#[test]
fn f7_activity_carries_calls_and_admin_actions_only() {
    let d = dir();
    let path = d.path().join("inv.jsonl");
    let w = write(
        &path,
        &[vec![Rec::Call(None), Rec::Grant, Rec::Admin, Rec::Config]],
    );
    let l = log(&path, StreamKind::Activity);
    let pages = drain(
        &l,
        None,
        w.marks.last(),
        &Access::All,
        WIDE,
        &mut Search::default(),
    );
    assert_eq!(counters(&pages), vec![1, 3]);
}

#[test]
fn f7_config_carries_config_rows_only() {
    let d = dir();
    let path = d.path().join("gov.jsonl");
    let w = write(&path, &[vec![Rec::Config, Rec::Grant, Rec::Config]]);
    let l = log(&path, StreamKind::Config);
    let pages = drain(
        &l,
        None,
        w.marks.last(),
        &Access::All,
        WIDE,
        &mut Search::default(),
    );
    assert_eq!(counters(&pages), vec![1, 3]);
    let own = Access::Own {
        issuer: X.into(),
        subject: "s".into(),
    };
    let mine = drain(&l, None, w.marks.last(), &own, WIDE, &mut Search::default());
    assert!(counters(&mine).is_empty(), "a config row is no one's own");
    assert_eq!(
        mine.last().unwrap().next.as_ref(),
        w.marks.last(),
        "but the scan passes it"
    );
}

#[test]
fn f14_stop_is_inclusive_and_rows_after_it_wait_for_the_live_feed() {
    for kind in [StreamKind::Activity, StreamKind::Config] {
        let d = dir();
        let path = d.path().join("log.jsonl");
        let rec = if kind == StreamKind::Activity {
            Rec::Call(None)
        } else {
            Rec::Config
        };
        let w = write(&path, &[vec![rec; 6]]);
        let l = log(&path, kind);
        let stop = &w.marks[3];
        let pages = drain(
            &l,
            None,
            Some(stop),
            &Access::All,
            WIDE,
            &mut Search::default(),
        );
        assert_eq!(
            counters(&pages),
            vec![1, 2, 3, 4],
            "{kind:?}: the row at stop is delivered"
        );
        assert!(
            !pages.last().unwrap().more,
            "{kind:?}: more is judged against stop"
        );
    }
}

#[test]
fn f15_a_counter_ahead_of_the_head_resets() {
    for kind in [StreamKind::Activity, StreamKind::Config] {
        let d = dir();
        let path = d.path().join("log.jsonl");
        let rec = if kind == StreamKind::Activity {
            Rec::Call(None)
        } else {
            Rec::Config
        };
        let w = write(&path, &[vec![rec; 3]]);
        let ahead = Mark {
            counter: 99,
            hash16: w.marks[0].hash16.clone(),
        };
        let l = log(&path, kind);
        let pages = drain(
            &l,
            Some(&ahead),
            w.marks.last(),
            &Access::All,
            WIDE,
            &mut Search::default(),
        );
        assert!(pages.len() <= 2, "{kind:?}: no stall");
        assert!(
            pages.iter().any(|p| p.reset),
            "{kind:?}: ahead of the head resets"
        );
    }
}

#[test]
fn a_missing_middle_segment_resets_rather_than_skipping_its_rows() {
    // Three segments with the middle one gone: the active file takes the next
    // number, so only the counter jump shows it. Four with the second gone:
    // the next sealed number itself is missing.
    for (count, form) in [(3, "counter jump"), (4, "missing number")] {
        let d = dir();
        let path = d.path().join("inv.jsonl");
        let w = write(&path, &vec![calls(2); count]);
        std::fs::remove_file(sealed_path(&path, 2)).unwrap();
        let l = log(&path, StreamKind::Activity);
        let pages = drain(
            &l,
            Some(&w.marks[0]),
            w.marks.last(),
            &Access::All,
            WIDE,
            &mut Search::default(),
        );
        assert!(pages.iter().any(|p| p.reset), "{form}: a gap resets");
        assert!(
            !counters(&pages).contains(&5),
            "{form}: no row past the gap is served as the cursor's successor"
        );
    }
}

#[test]
fn head_of_a_log_ending_in_a_long_unreadable_tail_is_an_error_not_empty() {
    let d = dir();
    let path = d.path().join("inv.jsonl");
    let mut recs = calls(2);
    recs.push(Rec::Junks(1500, 2047));
    write(&path, &[recs]);
    let l = log(&path, StreamKind::Activity);
    assert!(
        super::super::head(&l).is_err(),
        "a tail of junk past one read is neither a record nor an empty log"
    );
    // A short tail still finds the newest record.
    let mut recs = calls(2);
    recs.push(Rec::Junks(4, 100));
    let w = write(&path, &[recs]);
    assert_eq!(super::super::head(&l).unwrap().as_ref(), w.marks.last());
}

#[test]
fn a_gap_that_holds_the_stop_resets() {
    let d = dir();
    let path = d.path().join("inv.jsonl");
    // Three segments with the middle one gone: the active file takes the next
    // number, so only the counter jump shows the gap, and the stop (counter 4)
    // was in it.
    let w = write(&path, &vec![calls(2); 3]);
    std::fs::remove_file(sealed_path(&path, 2)).unwrap();
    let l = log(&path, StreamKind::Activity);
    let pages = drain(
        &l,
        Some(&w.marks[0]),
        Some(&w.marks[3]),
        &Access::All,
        WIDE,
        &mut Search::default(),
    );
    assert!(pages.iter().any(|p| p.reset), "not Done past a lost stop");
    assert!(
        !counters(&pages).contains(&5),
        "no row past the gap is served"
    );
}

#[test]
fn a_cursor_at_the_stop_is_done_whatever_follows_it() {
    // The client is caught up: a gap past the stop is not its concern.
    let d = dir();
    let path = d.path().join("inv.jsonl");
    let w = write(&path, &vec![calls(2); 3]);
    std::fs::remove_file(sealed_path(&path, 2)).unwrap();
    let l = log(&path, StreamKind::Activity);
    let page = rows_after(
        &l,
        Some(&w.marks[1]),
        Some(&w.marks[1]),
        &Access::All,
        WIDE,
        &mut Search::default(),
    )
    .unwrap();
    assert!(!page.reset, "a caught-up cursor does not reset");
    assert!(page.rows.is_empty());
    assert_eq!(page.next.as_ref(), Some(&w.marks[1]));
}

#[test]
fn a_fresh_read_never_starts_past_an_unreadable_oldest_segment() {
    let d = dir();
    let path = d.path().join("inv.jsonl");
    let w = write(&path, &[calls(2), calls(2)]);
    let l = log(&path, StreamKind::Activity);
    IDENTITY_FAILS.with(|f| f.set(1));
    let page = rows_after(
        &l,
        None,
        w.marks.last(),
        &Access::All,
        WIDE,
        &mut Search::default(),
    );
    IDENTITY_FAILS.with(|f| f.set(0));
    let page = page.unwrap();
    assert!(page.reset, "an unreadable segment is not skipped");
    assert!(page.rows.is_empty());
}
