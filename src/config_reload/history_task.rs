// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The record path's task (design D-1): the record a swap hands back, and the
//! slot one reload keeps it in, with the guard it took before anything changed.

use std::sync::Arc;

use super::Source;
#[cfg(test)]
use super::seams;
use crate::config_reload::revision::RawInputs;

/// One record, built under the swap locks from the publish's own inputs and
/// run by the record task once the locks are released (design D-1).
pub(crate) enum PendingRecord {
    Publish {
        raw: RawInputs,
        revision: String,
        pending_restart: Vec<&'static str>,
        previous: Option<String>,
        /// The served version after this publish (the live config's recorded
        /// revision): what the record's eviction keeps.
        pin: String,
        source: Source,
    },
    Refused {
        source: Source,
        served: Option<String>,
        line: Option<u32>,
    },
}

/// One reload's record: the guard it took before anything changed, and the
/// record task it spawned (design D-1). Built at the entry of the reload
/// transaction, under `lock_reload`.
pub(crate) struct RecordSlot {
    guard: Option<tokio::sync::OwnedMutexGuard<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl RecordSlot {
    /// Take `live`'s record guard, waiting for the previous reload's record
    /// to finish; a holder with no history takes nothing.
    pub(crate) async fn take(live: &crate::config_reload::LiveConfig) -> Self {
        let guard = match live.history_hook() {
            Some(hook) => {
                let lock = hook.store.record_guard();
                #[cfg(test)]
                if lock.try_lock().is_err()
                    && let Some(seams) = seams::for_file(&hook.store.file())
                {
                    seams.note_guard_wait();
                }
                Some(lock.lock_owned().await)
            }
            None => None,
        };
        Self { guard, task: None }
    }

    /// Spawn the record task for `pending`, moving the guard into it. There
    /// is no await here, so a dropped reload cannot separate its swap from
    /// its record: the task runs on, and the next reload waits for it.
    pub(crate) fn spawn(
        &mut self,
        live: &Arc<crate::config_reload::LiveConfig>,
        pending: Option<PendingRecord>,
    ) {
        let Some(pending) = pending else {
            return;
        };
        let guard = self.guard.take();
        let live = Arc::clone(live);
        // One record per reload; were there a second, it waits for the first,
        // so records stay in order without the guard (code review r2).
        let previous = self.task.take();
        self.task = Some(tokio::spawn(async move {
            let _guard = guard;
            if let Some(previous) = previous {
                let _ = previous.await;
            }
            #[cfg(test)]
            let reached = live
                .history_hook()
                .and_then(|hook| seams::for_file(&hook.store.file()))
                .and_then(|seams| seams.take_record_park());
            #[cfg(test)]
            if let Some(gate) = &reached {
                gate.park_async().await;
            }
            if let Some(hook) = live.history_hook() {
                #[cfg(test)]
                if let Some(pause) = live.record_pause() {
                    let _ = tokio::task::spawn_blocking(move || pause()).await;
                }
                let record = hook.build(pending, crate::clock::unix_secs().unwrap_or(0));
                // Bounded by the save deadline (design D-2).
                hook.store.save_bounded(record).await;
            }
            #[cfg(test)]
            if let Some(gate) = reached {
                gate.finished();
            }
        }));
    }

    /// Wait for the record task, when one was spawned.
    pub(crate) async fn finish(self) {
        if let Some(task) = self.task
            && let Err(error) = task.await
        {
            tracing::warn!(%error, "the config history record task stopped before its record was kept");
        }
    }
}
