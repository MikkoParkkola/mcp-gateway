// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The read history's own rules (design §4.5; rows 16 and 17, and the ticket
//! lifecycle behind 2i).

use std::time::Duration;

use super::*;

const KEY: &str = "api_key:one";
const WINDOW: Duration = Duration::from_secs(3600);

fn tenant(id: &str) -> ReadAttribution {
    ReadAttribution::of([id.to_string()].into(), false)
}

fn unread() -> ReadAttribution {
    ReadAttribution {
        uninspected: true,
        ..ReadAttribution::default()
    }
}

fn reserve(history: &Arc<ReadHistory>, read: &ReadAttribution) -> Reservation {
    history
        .reserve(KEY, read, WINDOW, false)
        .expect("room for the principal")
}

/// Row 16: an unread frame is a fresh tenant in either order; alone it is
/// ordinary, and two unread frames conflict with each other.
#[test]
fn uninspected_both_orders() {
    let history = ReadHistory::shared();
    let a = reserve(&history, &tenant("a"));
    assert!(!a.over);
    assert!(reserve(&history, &unread()).over, "A then unread");

    let history = ReadHistory::shared();
    let u = reserve(&history, &unread());
    assert!(!u.over, "a lone unread frame is ordinary");
    assert!(reserve(&history, &tenant("b")).over, "unread then B");
    assert!(reserve(&history, &unread()).over, "unread then unread");
}

/// The same tenant again is never over.
#[test]
fn one_tenant_repeated_is_ordinary() {
    let history = ReadHistory::shared();
    let first = reserve(&history, &tenant("a"));
    first.ticket.as_ref().unwrap().emitted();
    for _ in 0..5 {
        assert!(!reserve(&history, &tenant("a")).over);
    }
}

/// A refused frame reserves nothing.
#[test]
fn a_refused_frame_reserves_nothing() {
    let history = ReadHistory::shared();
    let _a = reserve(&history, &tenant("a"));
    let b = history.reserve(KEY, &tenant("b"), WINDOW, true).unwrap();
    assert!(b.over);
    assert!(b.ticket.is_none());
    assert_eq!(history.tenants_held(KEY), (0, 1), "only A is pending");
}

/// 2i at the ticket: a copy written refreshes last-seen, the last copy
/// releases; a dropped unwritten copy commits nothing; a drop of the last
/// copy after an earlier write keeps that write.
#[test]
fn ticket_lifecycle() {
    let history = ReadHistory::shared();
    let a = reserve(&history, &tenant("a")).ticket.unwrap();
    let copy = a.clone();
    a.emitted();
    drop(a);
    assert_eq!(
        history.tenants_held(KEY),
        (1, 1),
        "the other copy is pending"
    );
    drop(copy);
    assert_eq!(
        history.tenants_held(KEY),
        (1, 0),
        "last copy released, write kept"
    );

    let history = ReadHistory::shared();
    let a = reserve(&history, &tenant("a")).ticket.unwrap();
    drop(a);
    assert_eq!(
        history.tenants_held(KEY),
        (0, 0),
        "unwritten drop commits nothing"
    );
    assert!(!reserve(&history, &tenant("b")).over, "so B is ordinary");
}

/// Row 17: 10,000 tenants keep at most 256 hashes; overlapping tickets keep
/// their own counts; a drop keeps a committed A.
#[test]
fn history_bounds_and_ownership() {
    let history = ReadHistory::shared();
    let mut tickets = Vec::new();
    for n in 0..10_000 {
        if let Some(t) = reserve(&history, &tenant(&format!("t{n}"))).ticket {
            tickets.push(t);
        }
    }
    let (committed, pending) = history.tenants_held(KEY);
    assert!(committed + pending <= MAX_TENANTS_PER_PRINCIPAL);
    drop(tickets);
    assert_eq!(history.tenants_held(KEY), (0, 0));

    let history = ReadHistory::shared();
    let first = reserve(&history, &tenant("a")).ticket.unwrap();
    let second = reserve(&history, &tenant("a")).ticket.unwrap();
    first.emitted();
    drop(first);
    assert_eq!(
        history.tenants_held(KEY),
        (1, 1),
        "the second ticket's count stays"
    );
    drop(second);
    assert!(reserve(&history, &tenant("b")).over, "A stays committed");
}

/// Past the bound, an overflow conflicts with every other tenant.
#[test]
fn overflow_conflicts() {
    let history = ReadHistory::shared();
    let mut held = Vec::new();
    for n in 0..=MAX_TENANTS_PER_PRINCIPAL {
        held.push(reserve(&history, &tenant(&format!("t{n}"))));
    }
    assert!(reserve(&history, &tenant("t0")).over);
}

/// Expiry is measured from the last write.
#[test]
fn expiry_from_the_last_write() {
    let history = ReadHistory::shared();
    let window = Duration::from_millis(50);
    let a = history.reserve(KEY, &tenant("a"), window, false).unwrap();
    a.ticket.as_ref().unwrap().emitted();
    drop(a);
    std::thread::sleep(Duration::from_millis(80));
    let b = history.reserve(KEY, &tenant("b"), window, false).unwrap();
    assert!(!b.over, "A expired");
}
