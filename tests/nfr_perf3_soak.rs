// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! NFR.PERF.3 — sustained load over the two tables that grow without a client.
//!
//! **What is driven and what is genuine, said first, because a soak test that
//! blurs the two proves nothing.**
//!
//! DRIVEN: the clock. Both tables take `now: u64` from their caller, so this
//! test supplies it from an `AtomicU64` and advances it far faster than the
//! wall. That is the only way to cross a 300-second TTL inside a test that runs
//! for seconds. Every deadline, every reclaim and every lag figure below is in
//! *clock-seconds*, never wall-seconds, and is labelled so.
//!
//! GENUINE: everything else. Real `tokio` tasks on a real multi-threaded
//! runtime, real contention on both tables' locks, real allocations churned per
//! iteration, real wall-clock duration, real resident-set measurement of this
//! process. The load is not simulated and the memory figure is not modelled.
//!
//! **What is being soaked.** Both tables fill from a client that starts work
//! and walks away — the specification permits exactly that — and neither has a
//! client-driven exit:
//!
//! * [`InFlight`] reclaims lazily, inside the lock, on every access. Nothing
//!   sweeps it on a timer, so its occupancy is bounded only if an access
//!   happens; this test is the access.
//! * `SessionLifecycle` reclaims on an explicit `reap(now)` that the host
//!   reaper tick calls in production. Worst-case reclamation latency is
//!   therefore `IDLE_TTL` plus one tick, and the lag measured here is the
//!   second term.
//!
//! Every exchange this test starts is ABANDONED: `complete` and `untrack` are
//! never called. The only thing that can empty either table is expiry.
//!
//! Duration comes from `PERF3_SOAK_SECS` (default 5, so `cargo test
//! --all-features` stays fast; CI's `perf3-soak` job sets 60).

// A soak test is one linear run: setup, load, drain, report, assert. Splitting
// it would put the measurement and the bound it feeds in different places,
// which is the one thing a reader of this file must not have to reassemble.
#![allow(clippy::too_many_lines)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use mcp_gateway::gateway::session_lifecycle::{IDLE_TTL, SessionLifecycle};
use mcp_gateway::protocol::continuation::InFlight;

/// Mirror of the private `IN_FLIGHT_CAPACITY`, pinned by the unit test
/// `row_08_capacity_is_the_documented_bound` in `src/protocol/continuation.rs`. A test
/// outside the crate cannot name the constant, and copying it here with the
/// pin named is honest; guessing at it would not be.
const IN_FLIGHT_CAPACITY: usize = 4_096;

/// Mirror of the private `CONTINUATION_LIFETIME_SECS`, same reasoning.
const CONTINUATION_LIFETIME_SECS: u64 = 300;

/// Clock-seconds the driven clock advances per sweep.
///
/// Chosen so a whole TTL spans several sweeps rather than one: a step of a full
/// TTL would make "reclaimed within one sweep" true by construction and measure
/// nothing.
const SWEEP_CLOCK_STEP: u64 = 60;

/// Wall-time between sweeps. The sweeper is the host reaper tick's stand-in.
const SWEEP_WALL: Duration = Duration::from_millis(50);

/// Concurrent abandoning callers.
const WORKERS: usize = 4;

/// Wall-time a worker pauses between iterations, so arrival rate stays under
/// the drain rate and the run measures reclamation rather than capacity
/// refusals. Reported either way — see `holds_refused`.
const WORKER_PACE: Duration = Duration::from_millis(1);

/// Resident set size of this process in kibibytes, or `None` where unmeasurable.
fn rss_kib() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        // statm field 2 is resident pages.
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
        Some(pages * 4) // 4 KiB pages on every platform this runs on.
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .ok()?;
        String::from_utf8_lossy(&out.stdout).trim().parse().ok()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

/// Sustained abandonment against both tables, with the clock driven past their
/// deadlines and every occupancy figure asserted rather than printed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nfr_perf3_abandoned_state_stays_bounded_under_sustained_load() {
    let secs: u64 = std::env::var("PERF3_SOAK_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);
    let duration = Duration::from_secs(secs);

    let clock = Arc::new(AtomicU64::new(1_000_000));
    let in_flight = Arc::new(InFlight::new("soak-replica", IN_FLIGHT_CAPACITY));
    let lifecycle = Arc::new(SessionLifecycle::new());

    // Reclamation lag, in clock-seconds, measured where the reclaim actually
    // happens rather than inferred from the sweep schedule. The key carries its
    // own deadline so the handler can subtract without a second map to contend
    // on. Only sampled during the steady-state phase: the drain at the end
    // jumps the clock deliberately and its lag would say nothing about the run.
    let max_lag = Arc::new(AtomicU64::new(0));
    let measuring = Arc::new(std::sync::atomic::AtomicBool::new(true));
    {
        let clock = Arc::clone(&clock);
        let max_lag = Arc::clone(&max_lag);
        let measuring = Arc::clone(&measuring);
        lifecycle.register("perf3-lag", move |key| {
            if !measuring.load(Ordering::Relaxed) {
                return;
            }
            if let Some(deadline) = key
                .rsplit_once("-d")
                .and_then(|(_, d)| d.parse::<u64>().ok())
            {
                max_lag.fetch_max(
                    clock.load(Ordering::Relaxed).saturating_sub(deadline),
                    Ordering::Relaxed,
                );
            }
        });
    }

    let holds_ok = Arc::new(AtomicU64::new(0));
    let holds_refused = Arc::new(AtomicU64::new(0));
    let tracks = Arc::new(AtomicU64::new(0));

    let rss_before = rss_kib();
    let started = Instant::now();

    let workers: Vec<_> = (0..WORKERS)
        .map(|w| {
            let clock = Arc::clone(&clock);
            let in_flight = Arc::clone(&in_flight);
            let lifecycle = Arc::clone(&lifecycle);
            let (holds_ok, holds_refused, tracks) = (
                Arc::clone(&holds_ok),
                Arc::clone(&holds_refused),
                Arc::clone(&tracks),
            );
            tokio::spawn(async move {
                let backend = format!("soak-backend-{w}");
                let mut seq: u64 = 0;
                while started.elapsed() < duration {
                    let now = clock.load(Ordering::Relaxed);
                    // Abandoned on purpose: no `complete`, ever. The deadline is
                    // the only thing that may retire this hold.
                    if in_flight
                        .hold(&backend, now + CONTINUATION_LIFETIME_SECS, now)
                        .await
                        .is_some()
                    {
                        holds_ok.fetch_add(1, Ordering::Relaxed);
                    } else {
                        holds_refused.fetch_add(1, Ordering::Relaxed);
                    }

                    // Abandoned on purpose: no `untrack`, ever.
                    let deadline = now + IDLE_TTL.as_secs();
                    lifecycle.track(format!("w{w}-s{seq}-d{deadline}"), deadline);
                    tracks.fetch_add(1, Ordering::Relaxed);

                    // Real allocation, touched so it cannot be optimised away:
                    // the resident-set figure below is only worth reading if the
                    // run actually churns the allocator.
                    let mut churn = vec![0u8; 1024];
                    churn[(seq % 1024) as usize] = 1;
                    std::hint::black_box(&churn);

                    seq += 1;
                    tokio::time::sleep(WORKER_PACE).await;
                }
                seq
            })
        })
        .collect();

    // The sweeper stands in for the host reaper tick: it is the only thing that
    // advances the clock, and the only thing that touches `InFlight` outside the
    // workers — which matters, because `InFlight` reclaims only when accessed.
    let mut peak_in_flight = 0usize;
    let mut peak_tracked = 0usize;
    let mut sweeps = 0u64;
    // (tracked_count after this sweep, total tracks observed after that read).
    let mut samples: Vec<(usize, u64)> = Vec::new();
    while started.elapsed() < duration {
        tokio::time::sleep(SWEEP_WALL).await;
        let now = clock.fetch_add(SWEEP_CLOCK_STEP, Ordering::Relaxed) + SWEEP_CLOCK_STEP;
        sweeps += 1;
        peak_in_flight = peak_in_flight.max(in_flight.len(now).await);
        lifecycle.reap(now);
        let tracked = lifecycle.tracked_count();
        // Total read AFTER the count so the window bound below cannot be
        // undercounted by a key tracked between the two reads.
        samples.push((tracked, tracks.load(Ordering::Relaxed)));
        peak_tracked = peak_tracked.max(tracked);
    }

    let mut iterations = 0u64;
    for w in workers {
        iterations += w.await.expect("worker task must not panic");
    }
    let wall = started.elapsed();

    // Drain: nothing arrives any more, so advancing past every outstanding
    // deadline and sweeping once must empty both tables. This is the assertion
    // the whole run exists to make — a table that never empties is the leak.
    measuring.store(false, Ordering::Relaxed);
    let drained_at =
        clock.load(Ordering::Relaxed) + IDLE_TTL.as_secs() + CONTINUATION_LIFETIME_SECS + 1;
    clock.store(drained_at, Ordering::Relaxed);
    let final_in_flight = in_flight.len(drained_at).await;
    lifecycle.reap(drained_at);
    let final_tracked = lifecycle.tracked_count();

    let rss_after = rss_kib();
    let rss_delta = match (rss_before, rss_after) {
        (Some(b), Some(a)) => i64::try_from(a)
            .ok()
            .zip(i64::try_from(b).ok())
            .map(|(a, b)| a - b),
        _ => None,
    };

    // Arrival-rate x TTL bound, computed from this run rather than asserted as a
    // round number: a key still tracked at sweep `i` was tracked no earlier than
    // `IDLE_TTL` clock-seconds before it, which is `IDLE_TTL / SWEEP_CLOCK_STEP`
    // sweeps. One extra sweep of slack absorbs the workers racing the sweeper.
    let window = usize::try_from(IDLE_TTL.as_secs() / SWEEP_CLOCK_STEP).unwrap_or(1) + 1;
    let mut worst_window = 0u64;
    for i in window..samples.len() {
        let arrived = samples[i].1 - samples[i - window].1;
        let tracked = u64::try_from(samples[i].0).unwrap_or(u64::MAX);
        assert!(
            tracked <= arrived,
            "sweep {i}: {tracked} keys tracked but only {arrived} arrived in the last {window} \
             sweeps ({IDLE_TTL:?} of clock) — the lifecycle table is retaining keys past their \
             deadline"
        );
        worst_window = worst_window.max(arrived);
    }

    let lag = max_lag.load(Ordering::Relaxed);
    println!("--- NFR.PERF.3 soak ---");
    println!(
        "wall duration      : {:.2}s ({WORKERS} workers, {sweeps} sweeps)",
        wall.as_secs_f64()
    );
    println!(
        "clock advanced     : {} clock-seconds ({SWEEP_CLOCK_STEP}/sweep)",
        sweeps * SWEEP_CLOCK_STEP
    );
    let ops_per_sec = iterations * 1000 / u64::try_from(wall.as_millis()).unwrap_or(1).max(1);
    println!("iterations         : {iterations} ({ops_per_sec} ops/s wall)");
    println!(
        "holds started      : {} (abandoned, never completed)",
        holds_ok.load(Ordering::Relaxed)
    );
    println!(
        "holds refused      : {} (capacity {IN_FLIGHT_CAPACITY})",
        holds_refused.load(Ordering::Relaxed)
    );
    println!(
        "keys tracked       : {} (abandoned, never untracked)",
        tracks.load(Ordering::Relaxed)
    );
    println!("peak in_flight     : {peak_in_flight} / {IN_FLIGHT_CAPACITY}");
    println!("final in_flight    : {final_in_flight}");
    println!("peak tracked       : {peak_tracked} (worst {window}-sweep arrival {worst_window})");
    println!("final tracked      : {final_tracked}");
    println!("max reclaim lag    : {lag} clock-seconds (sweep step {SWEEP_CLOCK_STEP})");
    match rss_delta {
        Some(d) => println!("RSS delta          : {d} KiB ({rss_before:?} -> {rss_after:?})"),
        None => println!("RSS delta          : unmeasured on this platform"),
    }

    assert!(
        peak_in_flight <= IN_FLIGHT_CAPACITY,
        "in-flight occupancy {peak_in_flight} exceeded the capacity bound {IN_FLIGHT_CAPACITY}"
    );
    assert_eq!(
        final_in_flight, 0,
        "every hold was abandoned and every deadline has passed, so the table must be empty"
    );
    assert_eq!(
        final_tracked, 0,
        "every key was abandoned and every deadline has passed, so nothing may remain tracked"
    );
    assert!(
        lag <= SWEEP_CLOCK_STEP,
        "a key survived {lag} clock-seconds past its deadline; one sweep is {SWEEP_CLOCK_STEP}"
    );
    // A smoke bound, not a tuned one: the tables are capped at a few thousand
    // small entries, so a run that grows the resident set by a quarter of a
    // gibibyte has leaked something this test was built to catch. Deliberately
    // far above any plausible honest figure — a tight bound here would fail on
    // runner noise and teach everyone to ignore it.
    if let Some(d) = rss_delta {
        assert!(
            d < 256 * 1024,
            "resident set grew by {d} KiB over the run; the bounded tables cannot account for that"
        );
    }
}
