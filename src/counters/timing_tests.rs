// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What one `record` costs on the invoke path, with the store at
//! every cap, and the latency record's cost at a slot change and under
//! contention. Ignored: it only prints numbers. Run on the bench host:
//! `cargo test --release --lib -- --ignored --exact counters::timing_tests::record_timing --nocapture`.

use chrono_tz::Europe::Amsterdam;

use super::*;

const T0: u64 = 1_792_454_400;
const ROUNDS: usize = 21;
const PER_ROUND: u32 = 10_000;

/// Median nanoseconds per call of `run` over [`ROUNDS`] rounds.
fn median_ns(mut run: impl FnMut(u32)) -> u128 {
    let mut per_call: Vec<u128> = (0..ROUNDS)
        .map(|_| {
            let started = std::time::Instant::now();
            for i in 0..PER_ROUND {
                run(i);
            }
            started.elapsed().as_nanos() / u128::from(PER_ROUND)
        })
        .collect();
    per_call.sort_unstable();
    per_call[ROUNDS / 2]
}

#[test]
#[ignore = "timing: prints the per-call cost of a record"]
fn record_timing() {
    let names: Vec<String> = (0..MAX_PAIRS).map(|i| format!("label-{i:0>120}")).collect();
    let store = CounterStore::new(T0);
    for (i, name) in names.iter().enumerate() {
        let call = Call {
            caller: &names[i % MAX_LABELS],
            server: Label::Known(&names[i / 4 % MAX_LABELS]),
            tool: Label::Known(name),
            tally: Tally::default(),
        };
        store.record(&call, T0 + 10, &Amsterdam);
    }
    let held = Call {
        caller: &names[0],
        server: Label::Known(&names[0]),
        tool: Label::Known(&names[0]),
        tally: Tally::default(),
    };
    let hit = median_ns(|i| store.record(&held, T0 + 20 + u64::from(i % 1800), &Amsterdam));
    let fresh: Vec<String> = (0..PER_ROUND).map(|i| format!("new-{i:0>120}")).collect();
    let overflow = median_ns(|i| {
        let call = Call {
            caller: &names[1],
            server: Label::Known(&names[1]),
            tool: Label::Known(&fresh[usize::try_from(i).unwrap()]),
            tally: Tally::default(),
        };
        store.record(&call, T0 + 30, &Amsterdam);
    });
    println!("counters record_hit_ns={hit} record_overflow_ns={overflow}");
}

/// Latency, test plan row 40: a timed record in a steady slot, and at a slot
/// change, where each held server's oldest live slot finalizes as the server
/// is first recorded in the new slot (every call of a rollover round does).
#[test]
#[ignore = "timing: prints the latency record cost at a slot rollover"]
fn latency_rollover_timing() {
    let names: Vec<String> = (0..MAX_LABELS).map(|i| format!("label-{i:0>120}")).collect();
    let sample = Some((std::time::Duration::from_millis(40), End::Answered));
    let call = |i: usize| Call {
        caller: &names[0],
        server: Label::Known(&names[i % MAX_LABELS]),
        tool: Label::Known(&names[0]),
        tally: Tally::default(),
    };
    let store = CounterStore::new(T0);
    for i in 0..MAX_LABELS {
        store.record_timed(&call(i), T0 + 10, &Amsterdam, sample);
    }
    let steady = median_ns(|i| {
        let i = usize::try_from(i).unwrap();
        store.record_timed(&call(i), T0 + 20, &Amsterdam, sample);
    });
    let mut per_call: Vec<u128> = (1..=u64::try_from(ROUNDS).unwrap())
        .map(|round| {
            let at = T0 + 10 + round * HALF;
            let started = std::time::Instant::now();
            for i in 0..MAX_LABELS {
                store.record_timed(&call(i), at, &Amsterdam, sample);
            }
            started.elapsed().as_nanos() / u128::try_from(MAX_LABELS).unwrap()
        })
        .collect();
    per_call.sort_unstable();
    let rollover = per_call[ROUNDS / 2];
    println!("latency record_steady_ns={steady} record_rollover_ns={rollover}");
}

/// Latency, test plan row 40: 8 writers record timed calls while one reader
/// reads the Overview's latency hour and a server's day series in a loop.
/// Prints the writers' per-call cost alone and beside the reader, and the
/// reader's median read.
#[test]
#[ignore = "timing: prints the store lock under 8 writers and a latency reader"]
fn latency_reader_with_8_writers_timing() {
    const WRITERS: usize = 8;
    const CALLS: usize = 200_000;
    let names: Vec<String> = (0..MAX_LABELS).map(|i| format!("label-{i:0>120}")).collect();
    let sample = Some((std::time::Duration::from_millis(40), End::Answered));
    let store = CounterStore::new(T0);
    let write = |w: usize| {
        for i in 0..CALLS {
            let call = Call {
                caller: &names[w],
                server: Label::Known(&names[(w * CALLS + i) % MAX_LABELS]),
                tool: Label::Known(&names[0]),
                tally: Tally::default(),
            };
            store.record_timed(&call, T0 + 20, &Amsterdam, sample);
        }
    };
    let writers = |reader: bool| {
        let done = std::sync::atomic::AtomicBool::new(false);
        let mut reads = Vec::new();
        let started = std::time::Instant::now();
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..WRITERS).map(|w| scope.spawn(move || write(w))).collect();
            let reading = reader.then(|| {
                scope.spawn(|| {
                    let mut took = Vec::new();
                    while !done.load(std::sync::atomic::Ordering::Relaxed) {
                        let read = std::time::Instant::now();
                        let hour = store.latency_hour(T0 + 30);
                        let day = store.latency_series(
                            Some(&names[0]),
                            Window::Day,
                            false,
                            T0 + 30,
                            &Amsterdam,
                        );
                        took.push(read.elapsed().as_nanos());
                        assert!(!hour.servers.is_empty() && !day.points.is_empty());
                    }
                    took
                })
            });
            for handle in handles {
                handle.join().expect("a writer");
            }
            done.store(true, std::sync::atomic::Ordering::Relaxed);
            if let Some(reading) = reading {
                reads = reading.join().expect("the reader");
            }
        });
        let per_call = started.elapsed().as_nanos() / u128::try_from(WRITERS * CALLS).unwrap();
        reads.sort_unstable();
        (per_call, reads.get(reads.len() / 2).copied(), reads.len())
    };
    let (alone, _, _) = writers(false);
    let (beside, read, count) = writers(true);
    println!(
        "latency writers8_ns_per_call_alone={alone} writers8_ns_per_call_with_reader={beside} \
         reader_median_ns={} reads={count}",
        read.unwrap_or(0)
    );
}
