// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7855.RACE.2: a backend start and a hardened pairing on two threads.

use std::time::Instant;

use super::*;

/// What the start races: a hardened `ReloadContext` over the registry holding
/// the backend, or registration into a registry already paired.
#[derive(Clone, Copy, Debug)]
enum Pairing {
    Context,
    Register,
}

/// How a round orders the two threads.
#[derive(Clone, Copy, Debug)]
enum Order {
    /// The start is held before it builds; the pairing lands first.
    Held,
    /// The pairing waits until the start has marked; the start lands first.
    Marked,
    /// The pairing is delayed by a sweep across twice the slowest
    /// start-to-mark time a `Marked` round saw, so either may land first.
    Raced,
}

/// Wait `delay` on this thread: spin below a millisecond, where a sleep's
/// granularity would flatten the sweep.
fn wait(delay: Duration) {
    if delay > Duration::from_millis(1) {
        std::thread::sleep(delay);
        return;
    }
    let until = Instant::now() + delay;
    while Instant::now() < until {
        std::hint::spin_loop();
    }
}

// Both lock orders are forced on every platform, so coverage does not hang on
// scheduler timing; the raced rounds add real contention near the boundary.
// Whichever takes the publish lock first decides: the start marks and the
// pairing is refused, stamping nothing, while the start connects unpinned; or
// the pairing stamps and the start is refused or pinned, connecting nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_start_racing_a_pairing_on_another_thread_never_connects_unpinned() {
    for pairing in [Pairing::Context, Pairing::Register] {
        let mut mark_latency = Duration::ZERO;
        for round in 0..30_u32 {
            let order = match round % 3 {
                0 => Order::Held,
                1 => Order::Marked,
                _ => Order::Raced,
            };
            let at = format!("{pairing:?} {order:?} round {round}");
            let (backend, accepted) = started_at_loopback().await;
            let registry = Arc::new(BackendRegistry::new());
            match pairing {
                Pairing::Context => assert!(registry.register(Arc::clone(&backend))),
                Pairing::Register => registry
                    .enforce_destinations(DestinationPolicy::Public, &[])
                    .expect("an empty registry pairs"),
            }
            let gate = Arc::new(super::super::MarkWindowGate::default());
            if matches!(order, Order::Held) {
                *backend.mark_window_gate.lock() = Some(Arc::clone(&gate));
            }
            let spawned = Instant::now();
            let start = tokio::spawn({
                let backend = Arc::clone(&backend);
                async move { backend.ensure_started().await }
            });
            if matches!(order, Order::Held) {
                within("the start reaching the window", gate.reached.notified()).await;
            }
            let delay = mark_latency * 2 * (round / 3 % 8) / 7;
            let (paired, waited) = tokio::task::spawn_blocking({
                let (registry, backend) = (Arc::clone(&registry), Arc::clone(&backend));
                move || {
                    match order {
                        Order::Held => {}
                        Order::Marked => {
                            while !backend.started_unpinned() {
                                assert!(spawned.elapsed() < Duration::from_secs(30), "no mark");
                                std::hint::spin_loop();
                            }
                        }
                        Order::Raced => wait(delay),
                    }
                    let waited = spawned.elapsed();
                    let paired = match pairing {
                        Pairing::Context => pair_hardened(registry).is_ok(),
                        Pairing::Register => registry.register(backend),
                    };
                    (paired, waited)
                }
            })
            .await
            .expect("pairing thread");
            gate.release.notify_one();
            // The listener drops every connection, so a start that connected
            // fails only after the accept was counted.
            let _ = within("the start returning", start)
                .await
                .expect("start task");
            match order {
                Order::Held => assert!(paired, "{at}: held before marking"),
                Order::Marked => {
                    assert!(!paired, "{at}: marked before pairing");
                    mark_latency = mark_latency.max(waited);
                }
                Order::Raced => {}
            }
            if paired {
                assert_eq!(backend.destination(), DestinationPolicy::Public, "{at}");
                assert_eq!(
                    accepted.load(Ordering::SeqCst),
                    0,
                    "{at}: the pairing succeeded and the start connected unpinned"
                );
            } else {
                assert!(backend.started_unpinned(), "{at}: refused, nothing marked");
                assert_eq!(
                    backend.destination(),
                    DestinationPolicy::Configured,
                    "{at}: a refused pairing stamped"
                );
                // The witness that the zero-accept oracle can see a connection.
                assert!(
                    accepted.load(Ordering::SeqCst) > 0,
                    "{at}: the unpinned start never reached the listener"
                );
            }
        }
    }
}
