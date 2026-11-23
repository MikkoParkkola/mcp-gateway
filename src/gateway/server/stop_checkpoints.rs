// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The stop's checkpoints. From the stop signal until the drains
//! end, every class of state the stop saves is saved once a second, each class
//! on its own thread and skipped while an earlier write of its file still runs;
//! then one last pass, each class waiting its turn, before the backend stage. A
//! kill inside a container's stop grace loses at most the last second of
//! records, and nothing recorded before the signal.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::{Instant, MissedTickBehavior};
use tracing::{info, warn};

use super::persistence::{CostShutdown, ShutdownSave, run_shutdown_saves};
use crate::gateway::stop_budget::{DRAIN_CAP, StopBudget};
use crate::ranking::SearchRanker;
use crate::transition::TransitionTracker;

/// How often a pass runs while the stop waits: a kill loses at most this,
/// plus one write.
pub(super) const EVERY: Duration = Duration::from_secs(1);

/// The last pass's own slice of the post-listener reserve: the drains end this
/// long before Dp and the last pass ends by Dp, so the backend stage still
/// starts by Dp and its reserve is untouched.
pub(super) const LAST_SAVE: Duration = Duration::from_millis(100);

/// A save that reports whether it wrote its file.
pub(super) type Save = Arc<dyn Fn() -> bool + Send + Sync>;

/// What a pass's write reports as when its class's root is in a temp dir no
/// test kept (`crate::spawn_keep::kept_at_spawn`).
const CHECKPOINT_KIND: &str = "stop checkpoint";

/// One class of state: its name in the log, the checkpoint save (skips while
/// its file is being written) and the last pass's save (waits its turn).
pub(super) struct Class {
    pub(super) name: &'static str,
    /// The file or dir its saves write: the root a detached write keeps for a
    /// test while it runs (`crate::spawn_keep`). None for a class that writes
    /// no file.
    pub(super) root: Option<PathBuf>,
    pub(super) checkpoint: Save,
    pub(super) last: Save,
}

/// The checkpoints of one stop: started at the trigger, ended by the last pass.
pub(super) struct Checkpoints {
    classes: Arc<[Class]>,
    running: parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Checkpoints {
    pub(super) fn new(classes: Vec<Class>) -> Self {
        Self {
            classes: classes.into(),
            running: parking_lot::Mutex::new(None),
        }
    }

    /// Start the passes, the first at once. Detached: nothing in a pass can
    /// delay the caller. A second call while they run does nothing.
    pub(super) fn start(&self) {
        let mut running = self.running.lock();
        if running.is_none() {
            *running = Some(tokio::spawn(passes(Arc::clone(&self.classes))));
        }
    }

    /// Stop the passes, then run the last one: every class waits its turn and
    /// writes, all ending by `deadline`; a write still running then is
    /// abandoned and logged by name.
    pub(super) async fn finish(&self, deadline: Instant) {
        let running = self.running.lock().take();
        if let Some(task) = running {
            task.abort();
            let _ = task.await;
        }
        info!("stop checkpoint pass=last started");
        let saves = self
            .classes
            .iter()
            .map(|class| {
                let (name, save) = (class.name, Arc::clone(&class.last));
                ShutdownSave::new(
                    name,
                    class.root.clone(),
                    Box::new(move || {
                        if save() {
                            info!("stop checkpoint saved class={name} pass=last");
                        }
                    }),
                )
            })
            .collect();
        run_shutdown_saves(deadline, saves).await;
    }
}

/// One pass every [`EVERY`], the first at once. A pass never waits for its
/// writes: each runs on its own detached thread, so a write stalled on one file
/// makes later passes skip that class only.
async fn passes(classes: Arc<[Class]>) {
    let mut every = tokio::time::interval(EVERY);
    every.set_missed_tick_behavior(MissedTickBehavior::Skip);
    for pass in 1_u64..=u64::MAX {
        every.tick().await;
        info!("stop checkpoint pass={pass} started");
        for class in classes.iter() {
            let (name, save) = (class.name, Arc::clone(&class.checkpoint));
            // Taken here, before the thread exists, while a test still holds
            // its share of the dir; the write's thread holds it to its end.
            let kept = class
                .root
                .as_deref()
                .map(|root| crate::spawn_keep::kept_at_spawn(CHECKPOINT_KIND, root))
                .unwrap_or_default();
            let spawned = std::thread::Builder::new()
                .name(format!("stop checkpoint: {name}"))
                .spawn(move || {
                    if crate::spawn_keep::holding(kept, save.as_ref()) {
                        info!("stop checkpoint saved class={name} pass={pass}");
                    }
                });
            if let Err(error) = spawned {
                warn!(%error, class = name, "stop checkpoint could not start a thread; skipped");
            }
        }
    }
}

/// Where the drains end: [`LAST_SAVE`] before Dp.
pub(super) fn drains_end(budget: &StopBudget) -> Instant {
    let dp = budget.post_listener_end();
    dp.checked_sub(LAST_SAVE).unwrap_or(dp)
}

/// What a drain starting at `now` may wait: [`DRAIN_CAP`], or what is left to
/// [`drains_end`] if that is less.
pub(super) fn drain_window(budget: &StopBudget, now: Instant) -> Duration {
    drains_end(budget)
        .saturating_duration_since(now)
        .min(DRAIN_CAP)
}

/// Where the last pass ends: Dp, where the backend stage starts at the latest.
pub(super) fn last_deadline(budget: &StopBudget) -> Instant {
    budget.post_listener_end()
}

/// Whether a save landed; a failed one is logged and the last landed file
/// stands.
fn landed(class: &'static str, result: Option<std::io::Result<()>>) -> bool {
    match result {
        Some(Ok(())) => true,
        Some(Err(error)) => {
            warn!(%error, class, "stop checkpoint write failed; the last saved file stands");
            false
        }
        None => false,
    }
}

/// The usage file's class.
fn usage(ranker: Arc<SearchRanker>, path: PathBuf) -> Class {
    let (last_ranker, last_path) = (Arc::clone(&ranker), path.clone());
    Class {
        name: "usage",
        root: Some(path.clone()),
        checkpoint: Arc::new(move || landed("usage", ranker.save_unless_busy(&path))),
        last: Arc::new(move || landed("usage", Some(last_ranker.save(&last_path)))),
    }
}

/// The transitions file's class.
fn transitions(tracker: Arc<TransitionTracker>, path: PathBuf) -> Class {
    let (last_tracker, last_path) = (Arc::clone(&tracker), path.clone());
    Class {
        name: "transitions",
        root: Some(path.clone()),
        checkpoint: Arc::new(move || landed("transitions", tracker.save_unless_busy(&path))),
        last: Arc::new(move || landed("transitions", Some(last_tracker.save(&last_path)))),
    }
}

/// Today's spend's class.
#[cfg(feature = "cost-governance")]
fn cost((enforcer, costs, data_dir): CostShutdown) -> Class {
    use super::persistence::{save_costs, save_costs_unless_busy};
    let (last_enforcer, last_dir) = (Arc::clone(&enforcer), data_dir.clone());
    let last_costs = Arc::clone(&costs);
    Class {
        name: "cost",
        root: Some(data_dir.clone()),
        checkpoint: Arc::new(move || save_costs_unless_busy(&enforcer, &costs, &data_dir)),
        last: Arc::new(move || save_costs(&last_enforcer, &last_costs, &last_dir)),
    }
}

/// Every class the stop saves, in the order a pass starts them: usage,
/// transitions, cost (with cost governance on), counters, health.
pub(super) fn classes(
    (ranker, ranker_path): (Arc<SearchRanker>, PathBuf),
    (tracker, transition_path): (Arc<TransitionTracker>, PathBuf),
    cost_state: Option<CostShutdown>,
    counters: &super::counter_wiring::Counters,
    health: &super::health_wiring::Health,
) -> Vec<Class> {
    let mut all = vec![
        usage(ranker, ranker_path),
        transitions(tracker, transition_path),
    ];
    #[cfg(feature = "cost-governance")]
    all.extend(cost_state.map(cost));
    #[cfg(not(feature = "cost-governance"))]
    let _ = cost_state;
    all.push(counters.checkpoint_class());
    all.push(health.checkpoint_class());
    all
}

#[cfg(tp4)]
#[cfg(test)]
#[path = "stop_checkpoints_tests.rs"]
mod tests;
