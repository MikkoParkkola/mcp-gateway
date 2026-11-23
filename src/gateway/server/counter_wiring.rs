// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The HTTP server's call counters. Restored from
//! `<data_dir>/counters.json` before anything is served, saved every
//! [`COUNTER_SAVE_INTERVAL`] and once more at shutdown. A stdio gateway does
//! not build them: their readers are HTTP routes.

use std::path::Path;
use std::sync::Arc;

use crate::counters::persist::{CounterFile, Restored};
use crate::counters::{CounterStore, VersionChange};
use crate::gateway::meta_mcp::MetaMcp;

use super::persistence::{ShutdownSave, spawn_periodic_save};

/// How often the counters are saved: a hard kill loses at most this much,
/// as for `costs.json`. Not the cost saver's constant, which only a
/// cost-governance build has.
pub(super) const COUNTER_SAVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);

/// The version written into the file, so the next start can mark an upgrade.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The store and the file it saves to.
pub(super) struct Counters {
    pub(super) store: Arc<CounterStore>,
    file: Arc<CounterFile>,
    /// Where `file` saves (`<data_dir>/counters.json`): the root a detached
    /// save keeps for a test while it writes (`crate::spawn_keep`).
    path: std::path::PathBuf,
    /// The version change this start's restore marked, kept as a value for
    /// `GET /ui/api/gateway` rather than read back from marker history.
    pub(super) upgrade: Option<VersionChange>,
}

/// Restore the counters from `data_dir`, attach them to `meta_mcp`, and start
/// the periodic save, which ends on `shutdown`.
pub(super) fn start(
    data_dir: &Path,
    meta_mcp: &MetaMcp,
    shutdown: tokio::sync::broadcast::Receiver<()>,
) -> (Counters, tokio::task::JoinHandle<()>) {
    let counters = restore(data_dir);
    meta_mcp.set_counters(Arc::clone(&counters.store));
    // The saver's root is the file it writes, so a test's kept dir covers it between ticks.
    let root = Some(data_dir.join("counters.json"));
    let saver = spawn_periodic_save(
        "counter save",
        COUNTER_SAVE_INTERVAL,
        Some(shutdown),
        root,
        {
            let (store, file) = (Arc::clone(&counters.store), Arc::clone(&counters.file));
            move || {
                if let Ok(now) = crate::clock::unix_secs() {
                    file.save_unless_busy(&store, VERSION, now);
                }
            }
        },
    );
    (counters, saver)
}

/// Restore the counters from `data_dir`: everything `start` does before it
/// attaches them and starts their periodic save.
pub(super) fn restore(data_dir: &Path) -> Counters {
    // An unreadable clock starts coverage at the epoch; nothing is counted
    // until the clock reads again (every recorder skips on `Err`).
    let now = crate::clock::unix_secs().unwrap_or_default();
    let path = data_dir.join("counters.json");
    let Restored {
        store,
        file,
        upgrade,
        ..
    } = CounterFile::restore(path.clone(), now, VERSION, &crate::local_day::host_zone());
    Counters {
        store: Arc::new(store),
        file: Arc::new(file),
        path,
        upgrade,
    }
}

impl Counters {
    /// Save `counters.json` now, at startup, so this start's restore count
    /// and Restart marker are on disk before anything is served (best
    /// effort: a failure is logged by the save).
    pub(super) fn save_now(&self, now: u64) {
        self.file.save(&self.store, VERSION, now);
    }

    /// The stop checkpoints' counters entry: the periodic save, and for the
    /// last pass the shutdown's waiting save.
    pub(super) fn checkpoint_class(&self) -> super::stop_checkpoints::Class {
        let (store, file) = (Arc::clone(&self.store), Arc::clone(&self.file));
        let (last_store, last_file) = (Arc::clone(&self.store), Arc::clone(&self.file));
        super::stop_checkpoints::Class {
            name: "counters",
            root: Some(self.path.clone()),
            checkpoint: Arc::new(move || {
                crate::clock::unix_secs()
                    .is_ok_and(|now| file.save_unless_busy(&store, VERSION, now))
            }),
            last: Arc::new(move || {
                crate::clock::unix_secs().is_ok_and(|now| last_file.save(&last_store, VERSION, now))
            }),
        }
    }

    /// The shutdown step that writes `counters.json`.
    pub(super) fn shutdown_save(&self) -> ShutdownSave {
        let (store, file) = (Arc::clone(&self.store), Arc::clone(&self.file));
        ShutdownSave::new(
            "counter save (counters.json)",
            Some(self.path.clone()),
            Box::new(move || {
                if let Ok(now) = crate::clock::unix_secs() {
                    file.save(&store, VERSION, now);
                }
            }),
        )
    }
}
