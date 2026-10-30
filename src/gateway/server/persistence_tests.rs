// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tests for `persistence.rs`: data-dir and load/save helpers, the cost and
//! protocol-telemetry savers, and the shutdown saves. Moved from the parent's
//! inline `mod tests` for the file-size ceiling.

use super::*;
use std::cell::Cell;

#[test]
fn standard_data_dir_uses_gateway_subdir() {
    match std::env::var("MCP_GATEWAY_CONFIG_DIR") {
        Ok(path) => assert_eq!(standard_data_dir(), PathBuf::from(path)),
        Err(_) => assert_eq!(
            standard_data_dir()
                .file_name()
                .and_then(|name| name.to_str()),
            Some(".mcp-gateway")
        ),
    }
}

#[test]
fn load_if_exists_skips_missing_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing.json");
    let called = Cell::new(false);

    load_if_exists(
        &path,
        |_| {
            called.set(true);
            Ok::<(), std::io::Error>(())
        },
        "load failed",
        "loaded",
    );

    assert!(!called.get());
}

#[test]
fn save_with_logging_runs_callback() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    let called = Cell::new(false);

    save_with_logging(
        &path,
        |_| {
            called.set(true);
            Ok::<(), std::io::Error>(())
        },
        "save failed",
        "saved",
    );

    assert!(called.get());
}

#[cfg(feature = "cost-governance")]
fn enforcer_with_spend(usd: f64) -> Arc<BudgetEnforcer> {
    let cfg = CostGovernanceConfig {
        enabled: true,
        ..CostGovernanceConfig::default()
    };
    let registry = Arc::new(CostRegistry::new(&cfg));
    let enforcer = Arc::new(BudgetEnforcer::new(cfg, registry));
    enforcer.record_spend("tool", Some("key"), usd);
    enforcer
}

/// What `boot_cost_governance` would restore from `dir`, as global spend.
#[cfg(feature = "cost-governance")]
fn restored_global(dir: &Path) -> f64 {
    let cfg = CostGovernanceConfig {
        enabled: true,
        ..CostGovernanceConfig::default()
    };
    let (_, enforcer) = boot_cost_governance(&cfg, dir);
    enforcer.expect("enabled").snapshot().global_daily_usd
}

#[cfg(feature = "cost-governance")]
#[test]
fn save_costs_writes_what_the_next_boot_restores() {
    let global = crate::test_day::same_utc_day(|| {
        let dir = tempfile::tempdir().unwrap();
        save_costs(&enforcer_with_spend(0.25), dir.path());
        restored_global(dir.path())
    });
    assert!((global - 0.25).abs() < 1e-9, "the next boot reads {global}");
}

/// A save on a clock before 1970 leaves the last valid snapshot,
/// so the next boot on the real clock keeps the day's spend.
#[cfg(feature = "cost-governance")]
#[test]
fn a_clock_before_the_epoch_keeps_the_last_valid_snapshot() {
    let (control, global) = crate::test_day::same_utc_day(|| {
        let dir = tempfile::tempdir().unwrap();
        let enforcer = enforcer_with_spend(0.25);
        save_costs(&enforcer, dir.path());
        let control = restored_global(dir.path());
        enforcer.record_spend("tool", Some("key"), 0.15);
        {
            let _clock = crate::clock::test_clock::before_epoch();
            save_costs(&enforcer, dir.path());
        }
        (control, restored_global(dir.path()))
    });
    assert!(
        (control - 0.25).abs() < 1e-9,
        "control: the next boot reads {control}, not the saved 0.25"
    );
    assert!(
        (global - 0.25).abs() < 1e-9,
        "an unreadable clock overwrote the last valid snapshot: the next boot reads {global}"
    );
}

/// A periodic save that finds the previous write still holding
/// the lock writes nothing, and a later one writes the cumulative spend,
/// so a skipped interval is caught up and nothing is lost.
#[cfg(feature = "cost-governance")]
#[test]
fn a_save_skipped_while_a_write_holds_the_lock_is_caught_up_later() {
    let (written_while_held, caught_up, global) = crate::test_day::same_utc_day(|| {
        let dir = tempfile::tempdir().unwrap();
        let costs = dir.path().join("costs.json");
        let enforcer = enforcer_with_spend(0.25);
        {
            let _writing = COST_WRITE.lock().unwrap_or_else(PoisonError::into_inner);
            save_costs_unless_busy(&enforcer, dir.path());
        }
        let written_while_held = costs.exists();
        enforcer.record_spend("tool", Some("key"), 0.15);
        // Successive ticks. COST_WRITE is process-wide, so another test's
        // save may hold it at one of them: each retry first waits for that
        // holder to let go, so the count bounds lost races, not anyone's speed.
        for _ in 0..100 {
            drop(COST_WRITE.lock().unwrap_or_else(PoisonError::into_inner));
            save_costs_unless_busy(&enforcer, dir.path());
            if costs.exists() {
                break;
            }
        }
        (
            written_while_held,
            costs.exists(),
            restored_global(dir.path()),
        )
    });
    assert!(
        !written_while_held,
        "a periodic save wrote while the previous write held the lock"
    );
    assert!(caught_up, "no catch-up save landed in 100 ticks");
    assert!(
        (global - 0.4).abs() < 1e-9,
        "the catch-up save lost spend from the skipped interval: the next boot reads {global}"
    );
}

/// The losing order, forced. Another holder has `COST_WRITE`
/// when the first periodic tick fires and lets go only once that tick is
/// recorded as skipped, so the helper's next tick is the one that saves. One advance alone would leave no save at all:
/// the reported flake.
#[cfg(feature = "cost-governance")]
#[tokio::test(start_paused = true)]
async fn the_catch_up_helper_recovers_a_tick_skipped_under_a_held_lock() {
    // The single `yield_now` below lets the saver start its interval
    // before the first advance only because a current-thread runtime runs
    // the spawned task at that yield. On a multi-thread runtime it might
    // not, and the row would then wait out its hang bound instead of
    // failing at once, so the flavour is pinned here.
    assert_eq!(
        tokio::runtime::Handle::current().runtime_flavor(),
        tokio::runtime::RuntimeFlavor::CurrentThread,
        "this row's ordering relies on a current-thread runtime"
    );
    let (holder_joined, landed, global) = crate::test_day::same_utc_day_async(|| async {
        let dir = tempfile::tempdir().unwrap();
        let costs = dir.path().join("costs.json");
        let enforcer = enforcer_with_spend(0.25);
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let skipped_dir = dir.path().to_path_buf();
        let holder = std::thread::spawn(move || {
            let _writing = COST_WRITE.lock().unwrap_or_else(PoisonError::into_inner);
            held_tx
                .send(())
                .expect("the test waits for the lock to be held");
            // Released only once this test's first tick has been skipped:
            // the catch-up is then required, not a matter of timing. The
            // bound is a hang guard; the skip lands within milliseconds.
            let observed = std::time::Instant::now() + std::time::Duration::from_secs(30);
            while !SKIPPED_SAVES
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(&skipped_dir)
            {
                assert!(
                    std::time::Instant::now() < observed,
                    "the first tick was never skipped under the held lock"
                );
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        });
        held_rx.recv().expect("the holder took the lock");
        let saver = spawn_cost_saver(
            Arc::clone(&enforcer),
            dir.path().to_path_buf(),
            COST_SAVE_INTERVAL,
            None,
        );
        // Let the saver start its interval and take the immediate first tick
        // before the helper advances; otherwise the interval begins after the
        // first advance and that tick makes no save attempt at all.
        tokio::task::yield_now().await;
        let landed = advance_until_saved(&costs).await;
        let holder_joined = holder.join();
        saver.abort();
        (holder_joined, landed, restored_global(dir.path()))
    })
    .await;
    holder_joined.expect("the holder does not panic");
    assert!(
        landed.is_ok(),
        "the helper did not recover a tick skipped under a held lock: {}",
        landed.err().unwrap_or_default()
    );
    assert!(
        (global - 0.25).abs() < 1e-9,
        "the caught-up save lost spend: the next boot reads {global}"
    );
}

/// The saver writes on its interval and ends when shutdown is sent.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn cost_saver_stops_on_shutdown() {
    // Per phase: the spend expected on disk, whether it landed in time,
    // and what the next boot read. Then: shutdown sent, and the task's end.
    let (phases, listening, stopped) = crate::test_day::same_utc_day_async(|| async {
        let dir = tempfile::tempdir().unwrap();
        let costs = dir.path().join("costs.json");
        let (tx, rx) = tokio::sync::broadcast::channel(1);
        let enforcer = enforcer_with_spend(0.2);
        let task = spawn_cost_saver(
            Arc::clone(&enforcer),
            dir.path().to_path_buf(),
            std::time::Duration::from_millis(50),
            Some(rx),
        );
        // Each tick saves the spend as it is then, not a snapshot taken once.
        let mut phases = Vec::new();
        for (spent, expected) in [(0.0, 0.2), (0.3, 0.5)] {
            enforcer.record_spend("tool", Some("key"), spent);
            let saved = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while !costs.exists() || (restored_global(dir.path()) - expected).abs() > 1e-9 {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await;
            phases.push((expected, saved.is_ok(), restored_global(dir.path())));
            if saved.is_err() {
                break;
            }
        }
        let listening = tx.send(()).is_ok();
        let stopped = tokio::time::timeout(crate::test_wait::HANG_BOUND, task).await;
        (phases, listening, stopped)
    })
    .await;
    for (expected, saved, read) in phases {
        assert!(
            saved,
            "the saver never wrote {expected}; the next boot reads {read}"
        );
    }
    assert!(listening, "the saver is listening");
    stopped
        .expect("the saver kept running after shutdown")
        .expect("the saver panicked");
}

/// A day's spend counts only on its own UTC day. Spend recorded
/// at 23:59:59 and saved at 00:00:01 snapshots the new day's 0, and a file
/// saved at 23:59:59 restores its spend that day but not after midnight:
/// restore discards a file saved on an earlier day. Each figure comes from
/// a boot that restored the file. One guard per step: dropping any guard
/// clears the forced clock.
#[cfg(feature = "cost-governance")]
#[test]
fn a_save_and_restore_across_midnight_keep_each_day_apart() {
    use crate::clock::test_clock::at_secs;
    const D: u64 = 20_000;
    let late = D * 86_400 + 86_399;
    let early = (D + 1) * 86_400 + 1;

    // Recorded before midnight, saved after it.
    let dir = tempfile::tempdir().unwrap();
    let enforcer = {
        let _clock = at_secs(late);
        enforcer_with_spend(0.25)
    };
    {
        let _clock = at_secs(early);
        save_costs(&enforcer, dir.path());
    }
    let saved_after_midnight = {
        let _clock = at_secs(early);
        restored_global(dir.path())
    };
    assert!(
        saved_after_midnight.abs() < 1e-9,
        "a save after midnight carried the earlier day's spend: the next boot reads {saved_after_midnight}"
    );

    // Recorded and saved before midnight, restored on both sides of it.
    let dir = tempfile::tempdir().unwrap();
    {
        let _clock = at_secs(late);
        save_costs(&enforcer_with_spend(0.25), dir.path());
    }
    let same_day = {
        let _clock = at_secs(late);
        restored_global(dir.path())
    };
    assert!(
        (same_day - 0.25).abs() < 1e-9,
        "control: a boot on the save's own day reads {same_day}, not the saved 0.25"
    );
    let next_day = {
        let _clock = at_secs(early);
        restored_global(dir.path())
    };
    assert!(
        next_day.abs() < 1e-9,
        "a file saved before midnight counted on the next day: the next boot reads {next_day}"
    );
}

/// `stop` returns only once the aborted task's future has been dropped.
#[tokio::test]
async fn stop_waits_for_the_aborted_task() {
    let held = Arc::new(());
    let inside = Arc::clone(&held);
    let guard = super::super::AbortOnDrop::new(tokio::spawn(async move {
        std::future::pending::<()>().await;
        drop(inside);
    }));
    // Let the task start and take its clone.
    tokio::task::yield_now().await;
    guard.stop().await;
    assert_eq!(
        Arc::strong_count(&held),
        1,
        "stop returned while the aborted task still held its state"
    );
}

/// `MIK-8157.SAVE.3`: an abandoned cost save is logged by its step name,
/// so that name must point the operator at the file left stale.
#[cfg(feature = "cost-governance")]
#[test]
fn an_abandoned_cost_save_names_costs_json() {
    assert!(COST_SAVE_STEP.contains("costs.json"));
}
