// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8854: what one `record` costs on the invoke path, with the store at
//! every cap. Ignored: it only prints numbers. Run on the bench host:
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
    println!("MIK-8854 record_hit_ns={hit} record_overflow_ns={overflow}");
}
