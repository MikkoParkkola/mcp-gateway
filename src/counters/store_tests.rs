// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Store rules (test plan T1-T11, T45-T55): buckets, rings, local
//! days, caps, labels and classification, all on explicit times and zones.

use chrono::TimeZone;
use chrono_tz::{Asia::Kathmandu, Europe::Amsterdam, UTC};

use super::*;

/// 2026-10-20T00:00:00Z, a Tuesday well clear of any DST change.
const T0: u64 = 1_792_454_400;
const HALF: u64 = 1800;
const HOUR: u64 = 3600;
const DAY: u64 = 86_400;

fn ok(caller: &str, server: &str, tool: &str) -> Call<'static> {
    Call {
        caller: leak(caller),
        server: Label::Known(leak(server)),
        tool: Label::Known(leak(tool)),
        tally: Tally::default(),
    }
}

fn leak(s: &str) -> &'static str {
    Box::leak(s.to_owned().into_boxed_str())
}

fn calls_24h(store: &CounterStore, filter: Filter<'_>, now: u64) -> Vec<Point> {
    store
        .series(&Query::new(Metric::Calls, Window::Day, filter), now, &UTC)
        .points
}

fn nonzero(points: &[Point]) -> Vec<(u64, u64)> {
    points
        .iter()
        .filter(|p| p.v > 0)
        .map(|p| (p.t, p.v))
        .collect()
}

#[test]
fn t1_records_land_in_their_half_hour_bucket() {
    let store = CounterStore::new(T0);
    for _ in 0..3 {
        store.record(&ok("key:a", "s", "t"), T0 + 10, &UTC);
    }
    store.record(&ok("key:a", "s", "t"), T0 + HALF + 10, &UTC);
    let points = calls_24h(&store, Filter::All, T0 + HALF + 20);
    assert_eq!(nonzero(&points), vec![(T0, 3), (T0 + HALF, 1)]);
}

#[test]
fn t2_the_half_hour_ring_holds_48_hours_and_the_day_ring_keeps_the_count() {
    let store = CounterStore::new(T0);
    store.record(&ok("key:a", "s", "t"), T0 + 10, &UTC);
    let later = T0 + 48 * HOUR + HALF + 10;
    store.record(&ok("key:a", "s", "t"), later, &UTC);
    let two_days = store
        .series(
            &Query::new(Metric::Calls, Window::TwoDays, Filter::All),
            later,
            &UTC,
        )
        .points;
    assert_eq!(two_days.len(), 96);
    assert_eq!(nonzero(&two_days), vec![(later - later % HALF, 1)]);
    let month = store
        .series(
            &Query::new(Metric::Calls, Window::Month, Filter::All),
            later,
            &UTC,
        )
        .points;
    assert_eq!(nonzero(&month), vec![(T0, 1), (T0 + 2 * DAY, 1)]);
}

#[test]
fn t3_a_clock_stepping_back_lands_in_its_own_bucket_and_never_widens_the_window() {
    let store = CounterStore::new(T0);
    let now = T0 + 10 * HOUR;
    store.record(&ok("key:a", "s", "t"), now, &UTC);
    store.record(&ok("key:a", "s", "t"), now - 2 * HOUR, &UTC);
    let points = calls_24h(&store, Filter::All, now);
    assert_eq!(
        nonzero(&points),
        vec![
            (now - 2 * HOUR - (now - 2 * HOUR) % HALF, 1),
            (now - now % HALF, 1)
        ]
    );
    // A record far behind the window is kept nowhere in the half-hour ring.
    store.record(&ok("key:a", "s", "t"), now - 72 * HOUR, &UTC);
    let points = calls_24h(&store, Filter::All, now);
    assert_eq!(points.iter().map(|p| p.v).sum::<u64>(), 2);
}

#[test]
fn t4a_the_25_hour_day_is_one_local_date() {
    // 2026-10-25 in Amsterdam: 00:00 CEST is 2026-10-24T22:00Z, the next
    // midnight (CET) is 2026-10-25T23:00Z, 25 hours later.
    let start = Amsterdam.with_ymd_and_hms(2026, 10, 25, 0, 0, 0).unwrap();
    let start = u64::try_from(start.timestamp()).unwrap();
    let store = CounterStore::new(start);
    for h in 0..25 {
        store.record(&ok("key:a", "s", "t"), start + h * HOUR + 60, &Amsterdam);
    }
    let end = start + 25 * HOUR + 60;
    store.record(&ok("key:a", "s", "t"), end, &Amsterdam);
    let month = store
        .series(
            &Query::new(Metric::Calls, Window::Month, Filter::All),
            end,
            &Amsterdam,
        )
        .points;
    assert_eq!(nonzero(&month), vec![(start, 25), (start + 25 * HOUR, 1)]);
}

#[test]
fn t4b_the_23_hour_day_is_one_local_date() {
    let start = Amsterdam.with_ymd_and_hms(2027, 3, 28, 0, 0, 0).unwrap();
    let start = u64::try_from(start.timestamp()).unwrap();
    let store = CounterStore::new(start);
    for h in 0..23 {
        store.record(&ok("key:a", "s", "t"), start + h * HOUR + 60, &Amsterdam);
    }
    let end = start + 23 * HOUR + 60;
    store.record(&ok("key:a", "s", "t"), end, &Amsterdam);
    let month = store
        .series(
            &Query::new(Metric::Calls, Window::Month, Filter::All),
            end,
            &Amsterdam,
        )
        .points;
    assert_eq!(nonzero(&month), vec![(start, 23), (start + 23 * HOUR, 1)]);
}

#[test]
fn t5_a_quarter_hour_zone_cuts_the_day_at_its_own_midnight() {
    let before = Kathmandu.with_ymd_and_hms(2026, 10, 20, 23, 50, 0).unwrap();
    let after = Kathmandu.with_ymd_and_hms(2026, 10, 21, 0, 10, 0).unwrap();
    let (before, after) = (
        u64::try_from(before.timestamp()).unwrap(),
        u64::try_from(after.timestamp()).unwrap(),
    );
    let store = CounterStore::new(before);
    store.record(&ok("key:a", "s", "t"), before, &Kathmandu);
    store.record(&ok("key:a", "s", "t"), after, &Kathmandu);
    let month = store
        .series(
            &Query::new(Metric::Calls, Window::Month, Filter::All),
            after,
            &Kathmandu,
        )
        .points;
    let days: Vec<u64> = nonzero(&month).iter().map(|(_, v)| *v).collect();
    assert_eq!(days, vec![1, 1], "23:50 and 00:10 local are two dates");
}

#[test]
fn t6_tools_past_the_cap_count_in_overflow_and_totals_stay_exact() {
    let store = CounterStore::new(T0);
    for i in 0..10_000 {
        store.record(&ok("key:a", "s", &format!("tool-{i}")), T0 + 10, &UTC);
    }
    assert_eq!(store.labels(Dim::Tool), MAX_LABELS);
    let overflow = calls_24h(&store, Filter::Overflow(Dim::Tool), T0 + 20);
    assert_eq!(
        overflow.iter().map(|p| p.v).sum::<u64>(),
        10_000 - MAX_LABELS as u64
    );
    let global = calls_24h(&store, Filter::All, T0 + 20);
    assert_eq!(global.iter().map(|p| p.v).sum::<u64>(), 10_000);
}

#[test]
fn t6_a_store_at_every_cap_serializes_under_the_ceiling_from_the_constants() {
    let store = CounterStore::new(T0);
    let long = |i: usize| format!("{i:0>200}");
    // Every ring full: one record in every half-hour bucket and every day.
    for b in 0..30 * 48_usize {
        let at = T0 + u64::try_from(b).unwrap() * HALF;
        let i = b % MAX_PAIRS;
        store.record(
            &Call {
                caller: leak(&format!("key:{}", long(i % MAX_LABELS))),
                server: Label::Known(leak(&long(i % MAX_LABELS))),
                tool: Label::Known(leak(&long(i))),
                tally: Tally::default(),
            },
            at,
            &UTC,
        );
    }
    for i in 0..MAX_PAIRS {
        store.record(
            &Call {
                caller: leak(&format!("key:{}", long(i % MAX_LABELS))),
                server: Label::Known(leak(&long(i / MAX_LABELS))),
                tool: Label::Known(leak(&long(i))),
                tally: Tally::default(),
            },
            T0 + 30 * DAY - 10,
            &UTC,
        );
    }
    for i in 0..MAX_MARKERS {
        store.mark(MarkerKind::Pause, Some(&long(i)), T0 + 30 * DAY - 5);
    }
    let bytes = store.encode("4.0.0", T0 + 30 * DAY);
    let series = 1 + 3 * MAX_LABELS + MAX_PAIRS;
    let per_series = 6 * MAX_LABEL_BYTES + (HALF_BUCKETS + DAYS) * (21 + 5 * 21);
    // A pair's key holds two labels.
    let ceiling = series * per_series
        + MAX_PAIRS * 6 * MAX_LABEL_BYTES
        + MAX_MARKERS * (6 * MAX_LABEL_BYTES + 64)
        + 4096;
    assert!(
        bytes.len() <= ceiling,
        "{} bytes over the {ceiling}-byte ceiling",
        bytes.len()
    );
    // The bytes are the whole store, not a stand-in: restored, every cap is
    // there again.
    let (back, _) = CounterStore::from_bytes(&bytes, T0 + 30 * DAY, "4.0.0", &UTC).unwrap();
    for (dim, cap) in [
        (Dim::Server, MAX_LABELS),
        (Dim::Tool, MAX_LABELS),
        (Dim::Caller, MAX_LABELS),
        (Dim::CallerServer, MAX_PAIRS),
    ] {
        assert_eq!(back.labels(dim), cap, "{dim:?}");
    }
    assert_eq!(back.markers(0).len(), MAX_MARKERS);
}

#[test]
fn t7_caller_server_pairs_past_their_cap_count_in_overflow() {
    let store = CounterStore::new(T0);
    for i in 0..3_000 {
        store.record(
            &ok(&format!("key:c{}", i % 500), &format!("s{}", i / 500), "t"),
            T0 + 10,
            &UTC,
        );
    }
    assert_eq!(store.labels(Dim::CallerServer), MAX_PAIRS);
    let overflow = calls_24h(&store, Filter::Overflow(Dim::CallerServer), T0 + 20);
    assert_eq!(
        overflow.iter().map(|p| p.v).sum::<u64>(),
        3_000 - MAX_PAIRS as u64
    );
}

#[test]
fn t7a_callers_and_servers_have_their_own_caps() {
    let store = CounterStore::new(T0);
    for i in 0..600 {
        store.record(
            &ok(&format!("key:c{i}"), &format!("s{i}"), "t"),
            T0 + 10,
            &UTC,
        );
    }
    assert_eq!(store.labels(Dim::Caller), MAX_LABELS);
    assert_eq!(store.labels(Dim::Server), MAX_LABELS);
    for dim in [Dim::Caller, Dim::Server] {
        let overflow = calls_24h(&store, Filter::Overflow(dim), T0 + 20);
        assert_eq!(
            overflow.iter().map(|p| p.v).sum::<u64>(),
            600 - MAX_LABELS as u64
        );
    }
}

#[test]
fn t8_a_long_label_is_cut_on_a_character_boundary_with_a_hash_suffix() {
    let a = format!("{}{}", "é".repeat(60), "x".repeat(180));
    let b = format!("{}{}", "é".repeat(60), "y".repeat(180));
    let (la, lb) = (normalize(&a), normalize(&b));
    assert!(la.len() <= MAX_LABEL_BYTES, "{} bytes", la.len());
    assert!(la.is_char_boundary(la.len()));
    let suffix = &la[la.len() - 8..];
    assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()), "{la}");
    assert_ne!(la, lb, "labels sharing a prefix stay distinct");
    assert_eq!(normalize("short"), "short");
}

#[test]
fn t9_aged_series_free_their_slot_and_the_sweep_is_throttled() {
    let store = CounterStore::new(T0);
    for i in 0..MAX_LABELS {
        store.record(&ok("key:a", "s", &format!("old-{i}")), T0 + 10, &UTC);
    }
    assert_eq!(store.sweeps(), 0, "no sweep while the cap was not met");
    let aged = T0 + 31 * DAY;
    store.record(&ok("key:a", "s", "new-1"), aged, &UTC);
    assert_eq!(store.sweeps(), 1);
    assert_eq!(
        calls_24h(&store, Filter::Tool("s", "new-1"), aged)
            .iter()
            .map(|p| p.v)
            .sum::<u64>(),
        1,
        "the new label got its own series"
    );
    // Fill the freed slots, then two more new labels in the same bucket:
    // one sweep at most.
    for i in 0..MAX_LABELS - 1 {
        store.record(&ok("key:a", "s", &format!("fresh-{i}")), aged + 1, &UTC);
    }
    store.record(&ok("key:a", "s", "over-1"), aged + 2, &UTC);
    store.record(&ok("key:a", "s", "over-2"), aged + 3, &UTC);
    assert_eq!(
        store.sweeps(),
        1,
        "one sweep per dimension per half-hour bucket"
    );
}

#[test]
fn t10_each_outcome_moves_exactly_its_counters() {
    let cases: [(Tally, [u64; 5]); 6] = [
        (Tally::default(), [1, 0, 0, 0, 0]),
        (
            Tally {
                error: true,
                ..Tally::default()
            },
            [1, 0, 1, 0, 0],
        ),
        (
            Tally {
                blocked: true,
                ..Tally::default()
            },
            [1, 1, 0, 0, 0],
        ),
        (
            Tally {
                blocked: true,
                firewall: true,
                ..Tally::default()
            },
            [1, 1, 0, 1, 0],
        ),
        (
            Tally {
                cache_hit: true,
                ..Tally::default()
            },
            [1, 0, 0, 0, 1],
        ),
        (
            Tally {
                replay: true,
                ..Tally::default()
            },
            [0, 0, 0, 0, 0],
        ),
    ];
    for (tally, want) in cases {
        let store = CounterStore::new(T0);
        let mut call = ok("key:a", "s", "t");
        call.tally = tally;
        store.record(&call, T0 + 10, &UTC);
        let got = Metric::ALL.map(|metric| {
            store
                .series(&Query::new(metric, Window::Day, Filter::All), T0 + 20, &UTC)
                .points
                .iter()
                .map(|p| p.v)
                .sum::<u64>()
        });
        assert_eq!(got, want, "{tally:?}");
    }
}

#[test]
fn t10_audit_outcomes_map_to_tallies() {
    use crate::security::audit::AuditOutcome as A;
    let t = |o, fw| {
        Tally::from_outcome(Outcome::Audited {
            outcome: o,
            firewall: fw,
            cache_hit: false,
        })
    };
    assert_eq!(t(A::Ok, false), Tally::default());
    assert_eq!(
        t(A::ToolError, false),
        Tally {
            error: true,
            ..Tally::default()
        }
    );
    assert_eq!(
        t(A::Error(-32603), false),
        Tally {
            error: true,
            ..Tally::default()
        }
    );
    assert_eq!(
        t(A::Invalid(-32602), false),
        Tally {
            error: true,
            ..Tally::default()
        }
    );
    assert_eq!(
        t(A::Denied(-32003), false),
        Tally {
            blocked: true,
            ..Tally::default()
        }
    );
    // Firewall provenance wins over the audit outcome: a direct response-
    // firewall refusal is answered 200 with an error code (`Error`).
    let fw = Tally {
        blocked: true,
        firewall: true,
        ..Tally::default()
    };
    assert_eq!(t(A::Denied(-32002), true), fw);
    assert_eq!(t(A::Error(-32002), true), fw);
    assert!(Tally::from_outcome(Outcome::Replay).is_empty());
    assert_eq!(
        Tally::from_outcome(Outcome::AdmissionRefused),
        Tally {
            error: true,
            ..Tally::default()
        }
    );
}

#[test]
fn t11_untrusted_names_count_in_overflow_and_are_stored_nowhere() {
    let store = CounterStore::new(T0);
    let sentinel = "sk-live-SENTINEL-4f1d";
    store.record(
        &Call {
            caller: "key:a",
            server: Label::Untrusted,
            tool: Label::Untrusted,
            tally: Tally::default(),
        },
        T0 + 10,
        &UTC,
    );
    store.record(
        &Call {
            caller: "key:a",
            server: Label::Known("s"),
            tool: Label::Untrusted,
            tally: Tally::default(),
        },
        T0 + 11,
        &UTC,
    );
    let sum = |f| {
        calls_24h(&store, f, T0 + 20)
            .iter()
            .map(|p| p.v)
            .sum::<u64>()
    };
    assert_eq!(sum(Filter::Overflow(Dim::Server)), 1);
    assert_eq!(sum(Filter::Overflow(Dim::Tool)), 2);
    assert_eq!(sum(Filter::Server("s")), 1);
    let bytes = store.encode("4.0.0", T0 + 20);
    assert!(!String::from_utf8_lossy(&bytes).contains(sentinel));
    assert_eq!(store.labels(Dim::Tool), 0);
}

#[test]
fn t45_a_restored_file_is_cut_back_to_the_caps() {
    let big = CounterStore::new_unbounded_for_test(T0);
    for i in 0..5_000 {
        big.record(
            &ok(&format!("key:c{i}"), &format!("s{i}"), "t"),
            T0 + 10,
            &UTC,
        );
    }
    for i in 0..5_000 {
        big.mark(MarkerKind::ConfigReload, Some(&"z".repeat(1024)), T0 + i);
    }
    let bytes = big.encode("4.0.0", T0 + 10);
    let (restored, warned) = CounterStore::from_bytes(&bytes, T0 + 20, "4.0.0", &UTC).unwrap();
    assert!(warned, "an oversized file is reported");
    assert_eq!(restored.labels(Dim::Caller), MAX_LABELS);
    assert_eq!(restored.labels(Dim::Server), MAX_LABELS);
    assert_eq!(restored.labels(Dim::CallerServer), MAX_PAIRS);
    let markers = restored.markers(0);
    assert_eq!(markers.len(), MAX_MARKERS);
    assert!(
        markers
            .iter()
            .all(|m| m.subject.as_deref().unwrap_or("").len() <= MAX_LABEL_BYTES)
    );
    let month = restored
        .series(
            &Query::new(Metric::Calls, Window::Month, Filter::All),
            T0 + 20,
            &UTC,
        )
        .points;
    assert_eq!(
        month.iter().map(|p| p.v).sum::<u64>(),
        5_000,
        "global never folds"
    );
    // Restored 40 days on, every bucket is outside both windows.
    let (late, _) = CounterStore::from_bytes(&bytes, T0 + 40 * DAY, "4.0.0", &UTC).unwrap();
    for window in [Window::Day, Window::TwoDays, Window::Month] {
        let points = late
            .series(
                &Query::new(Metric::Calls, window, Filter::All),
                T0 + 40 * DAY,
                &UTC,
            )
            .points;
        assert_eq!(points.iter().map(|p| p.v).sum::<u64>(), 0, "{window:?}");
    }
}

#[test]
fn t46_a_key_named_bearer_and_the_bearer_are_two_callers() {
    use crate::security::audit::CredentialKind as K;
    assert_eq!(caller_label(K::ApiKey, "bearer"), "key:bearer");
    assert_eq!(caller_label(K::StaticBearer, "bearer"), "bearer");
    assert_eq!(caller_label(K::None, ""), "anonymous");
    let store = CounterStore::new(T0);
    store.record(
        &ok(&caller_label(K::ApiKey, "bearer"), "s", "t"),
        T0 + 10,
        &UTC,
    );
    store.record(
        &ok(&caller_label(K::StaticBearer, "bearer"), "s", "t"),
        T0 + 10,
        &UTC,
    );
    assert_eq!(store.labels(Dim::Caller), 2);
}

/// The day cache moves at local midnight: a record a minute after it is on
/// the next date, not the cached one.
#[test]
fn t47_the_cached_day_moves_at_midnight() {
    let before = Amsterdam.with_ymd_and_hms(2026, 10, 20, 23, 59, 0).unwrap();
    let before = u64::try_from(before.timestamp()).unwrap();
    let store = CounterStore::new(before);
    store.record(&ok("key:a", "s", "t"), before, &Amsterdam);
    store.record(&ok("key:a", "s", "t"), before + 120, &Amsterdam);
    let month = store
        .series(
            &Query::new(Metric::Calls, Window::Month, Filter::All),
            before + 120,
            &Amsterdam,
        )
        .points;
    let days: Vec<u64> = nonzero(&month).iter().map(|(_, v)| *v).collect();
    assert_eq!(days, vec![1, 1], "23:59 and 00:01 are two dates");
}

/// A clock stepping back across midnight lands on its own date, and the next
/// record after it lands on today again.
#[test]
fn t48_the_cached_day_follows_a_clock_stepping_back() {
    let after = Amsterdam.with_ymd_and_hms(2026, 10, 21, 0, 10, 0).unwrap();
    let after = u64::try_from(after.timestamp()).unwrap();
    let store = CounterStore::new(after - 3600);
    store.record(&ok("key:a", "s", "t"), after, &Amsterdam);
    store.record(&ok("key:a", "s", "t"), after - 1200, &Amsterdam);
    store.record(&ok("key:a", "s", "t"), after + 600, &Amsterdam);
    let month = store
        .series(
            &Query::new(Metric::Calls, Window::Month, Filter::All),
            after + 600,
            &Amsterdam,
        )
        .points;
    let days: Vec<u64> = nonzero(&month).iter().map(|(_, v)| *v).collect();
    assert_eq!(days, vec![1, 2], "23:50 on the 20th, then two on the 21st");
}

#[test]
fn t49_a_bucket_older_than_the_window_is_kept_nowhere() {
    let mut half = ring::Ring::<{ HALF_BUCKETS as u64 }>::default();
    let newest = 1_000;
    half.add(newest, [1, 0, 0, 0, 0]);
    let first = half.window_start(newest);
    half.add(first, [1, 0, 0, 0, 0]);
    half.add(first - 1, [7, 0, 0, 0, 0]);
    assert_eq!(half.get(first - 1), None);
    assert_eq!(
        half.buckets().collect::<Vec<_>>(),
        vec![(first, [1, 0, 0, 0, 0]), (newest, [1, 0, 0, 0, 0])]
    );
}

/// A store whose tool dimension filled, sent `late` to the overflow on day
/// 5, then swept every old label free 31 days on: `late` is not held, the
/// dimension is no longer full, and its one call is in the overflow, inside
/// the 30-day window.
fn swept_after_overflow() -> (CounterStore, u64) {
    let store = CounterStore::new(T0);
    for i in 0..MAX_LABELS {
        store.record(&ok("key:a", "s", &format!("old-{i}")), T0 + 10, &UTC);
    }
    store.record(&ok("key:a", "s", "late"), T0 + 5 * DAY, &UTC);
    let swept = T0 + 31 * DAY;
    store.record(&ok("key:a", "s", "new-1"), swept, &UTC);
    assert_eq!(store.labels(Dim::Tool), 1, "the old labels were swept");
    (store, swept)
}

fn month(store: &CounterStore, filter: Filter<'_>, now: u64) -> SeriesView {
    store.series(&Query::new(Metric::Calls, Window::Month, filter), now, &UTC)
}

#[test]
fn t50_a_label_swept_past_its_overflow_reads_as_folded() {
    let (store, now) = swept_after_overflow();
    let view = month(&store, Filter::Tool("s", "late"), now);
    assert!(
        view.folded,
        "its call is in the overflow, so zeros would read as exact"
    );
    assert!(view.points.is_empty());
}

#[test]
fn t51_a_label_admitted_after_its_overflow_starts_at_its_own_first_bucket() {
    let (store, now) = swept_after_overflow();
    store.record(&ok("key:a", "s", "late"), now + 10, &UTC);
    let view = month(&store, Filter::Tool("s", "late"), now + 20);
    assert!(!view.folded);
    let today = day::local_day(&UTC, now + 10).start;
    assert_eq!(view.since, today, "coverage starts at its own first count");
    assert_eq!(
        nonzero(&view.points),
        vec![(today, 1)],
        "nothing drawn before it, and its own count"
    );
    assert!(view.points.iter().all(|p| p.t >= today));
    let server = month(&store, Filter::Server("s"), now + 20);
    assert_eq!(server.since, T0, "a dimension with no overflow keeps since");
}

#[test]
fn t52_a_label_held_before_the_window_keeps_its_exact_zeros() {
    let store = CounterStore::new(T0);
    store.record(&ok("key:a", "s", "held"), T0 + 10, &UTC);
    let now = T0 + 3 * DAY;
    let stray = Call {
        caller: "key:a",
        server: Label::Known("s"),
        tool: Label::Untrusted,
        tally: Tally::default(),
    };
    store.record(&stray, now, &UTC);
    let view = store.series(
        &Query::new(Metric::Calls, Window::Day, Filter::Tool("s", "held")),
        now,
        &UTC,
    );
    assert!(!view.folded);
    assert_eq!(view.since, T0, "held through the whole window");
    assert_eq!(view.points.len(), 48, "exact zeros, every bucket");
}

#[test]
fn t53_a_long_held_label_called_again_keeps_its_exact_zeros() {
    let store = CounterStore::new(T0);
    store.record(&ok("key:a", "s", "held"), T0 + 10, &UTC);
    let now = T0 + 3 * DAY;
    let stray = Call {
        caller: "key:a",
        server: Label::Known("s"),
        tool: Label::Untrusted,
        tally: Tally::default(),
    };
    store.record(&stray, now - 2 * HOUR, &UTC);
    // Its ring drops the day-old bucket as it takes this one.
    store.record(&ok("key:a", "s", "held"), now, &UTC);
    let view = store.series(
        &Query::new(Metric::Calls, Window::Day, Filter::Tool("s", "held")),
        now + 10,
        &UTC,
    );
    assert!(!view.folded);
    assert_eq!(view.since, T0, "held since before the window");
    assert_eq!(view.points.len(), 48, "exact zeros before its new call");
    assert_eq!(nonzero(&view.points), vec![(now, 1)]);
}

#[test]
fn t54_a_ring_gives_its_buckets_oldest_first() {
    let mut half = ring::Ring::<{ HALF_BUCKETS as u64 }>::default();
    for bucket in [30, 10, 20, 40] {
        half.add(bucket, [1, 0, 0, 0, 0]);
    }
    let order: Vec<u64> = half.buckets().map(|(b, _)| b).collect();
    assert_eq!(order, vec![10, 20, 30, 40]);
}

#[test]
fn t55_a_late_label_keeps_its_admission_across_a_restart() {
    let (store, now) = swept_after_overflow();
    store.record(&ok("key:a", "s", "late"), now + 10, &UTC);
    let before = month(&store, Filter::Tool("s", "late"), now + 20);
    let bytes = store.encode("4.0.0", now + 20);
    let (back, _) = CounterStore::from_bytes(&bytes, now + 20, "4.0.0", &UTC).unwrap();
    let after = month(&back, Filter::Tool("s", "late"), now + 20);
    assert!(before.since > T0, "the fixture moved since");
    assert_eq!(after.since, before.since, "the admission survived");
    assert_eq!(after.points, before.points);
}

/// A full marker ring: the newest-first read returns only the rows asked
/// for, counts every marker in the window, and takes the lock once.
#[test]
fn newest_markers_returns_the_cap_and_counts_the_window() {
    let store = CounterStore::new(0);
    for i in 0..MAX_MARKERS as u64 {
        store.mark(
            MarkerKind::ConfigReload,
            Some(&format!("m{i:04}")),
            1_000 + i,
        );
    }
    let before = store.reads_for_test();

    let (rows, total) = store.newest_markers(1_500, 51);

    assert_eq!(store.reads_for_test() - before, 1);
    assert_eq!(rows.len(), 51);
    assert_eq!(rows[0].subject.as_deref(), Some("m0999"));
    assert_eq!(rows[50].subject.as_deref(), Some("m0949"));
    assert_eq!(total, 500);
}
