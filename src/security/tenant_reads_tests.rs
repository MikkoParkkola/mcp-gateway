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

/// Row 17 (review): the bound counts a tenant held both committed and
/// pending once, so 200 such tenants leave room under 256.
#[test]
fn a_tenant_committed_and_pending_counts_once() {
    let history = ReadHistory::shared();
    let mut held = Vec::new();
    for n in 0..200 {
        let t = reserve(&history, &tenant(&format!("t{n}"))).ticket.unwrap();
        t.emitted();
        held.push(t);
        held.push(reserve(&history, &tenant(&format!("t{n}"))).ticket.unwrap());
    }
    let next = reserve(&history, &tenant("t200")).ticket.unwrap();
    next.emitted();
    drop(held);
    let (committed, _) = history.tenants_held(KEY);
    assert_eq!(
        committed, 201,
        "the 201st tenant was pushed to overflow by a double count"
    );
}

/// `n` live principals, each holding tenant "a" under a held ticket, so none
/// is idle to evict.
fn fill_live(history: &Arc<ReadHistory>, n: usize) -> Vec<Reservation> {
    (0..n)
        .map(|i| {
            history
                .reserve(&format!("live-{i}"), &tenant("a"), WINDOW, false)
                .expect("room below the cap")
        })
        .collect()
}

/// MIK-7975 CAP.1: the principal map never holds more than `MAX_PRINCIPALS`
/// under concurrent first frames for distinct keys. One below the cap, with
/// every principal live so nothing is idle to evict, 64 threads released
/// together each bring a new key; at most one may be admitted.
#[test]
fn concurrent_new_principals_never_pass_the_cap() {
    const RACERS: usize = 64;
    for round in 0..4 {
        let history = ReadHistory::shared();
        let held = fill_live(&history, MAX_PRINCIPALS - 1);
        let start = Arc::new(std::sync::Barrier::new(RACERS));
        let racers: Vec<_> = (0..RACERS)
            .map(|n| {
                let (history, start) = (Arc::clone(&history), Arc::clone(&start));
                std::thread::spawn(move || {
                    start.wait();
                    history.reserve(&format!("new-{n}"), &tenant("a"), WINDOW, false)
                })
            })
            .collect();
        let admitted: Vec<_> = racers.into_iter().map(|r| r.join().unwrap()).collect();
        assert!(
            history.principals.len() <= MAX_PRINCIPALS,
            "round {round}: {} principals, cap {MAX_PRINCIPALS}",
            history.principals.len()
        );
        assert_eq!(
            admitted.iter().filter(|a| a.is_some()).count(),
            1,
            "round {round}: the one free place is taken exactly once"
        );
        drop((held, admitted));
    }
}

/// MIK-7975 CAP.1: a key another first frame admitted meanwhile is found, not
/// counted again, when the map is full: the cap applies only to a new key.
#[test]
fn a_key_admitted_meanwhile_is_found_at_a_full_cap() {
    let history = ReadHistory::shared();
    let mut held = fill_live(&history, MAX_PRINCIPALS - 1);
    let a = tenant("a");
    held.push(reserve(&history, &a));
    let hash = a.tenants.first().expect("one hashed tenant");
    let found = history
        .admit(KEY, history.now(), WINDOW)
        .map(|principal| principal.holds(hash));
    assert_eq!(found, Some(true), "KEY is present and live");
    assert_eq!(history.principals.len(), MAX_PRINCIPALS);
    drop(held);
}
