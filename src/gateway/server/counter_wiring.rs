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
    // An unreadable clock starts coverage at the epoch; nothing is counted
    // until the clock reads again (every recorder skips on `Err`).
    let now = crate::clock::unix_secs().unwrap_or_default();
    let Restored {
        store,
        file,
        upgrade,
        ..
    } = CounterFile::restore(
        data_dir.join("counters.json"),
        now,
        VERSION,
        &crate::local_day::host_zone(),
    );
    let (store, file) = (Arc::new(store), Arc::new(file));
    meta_mcp.set_counters(Arc::clone(&store));
    let saver = spawn_periodic_save("counter save", COUNTER_SAVE_INTERVAL, Some(shutdown), {
        let (store, file) = (Arc::clone(&store), Arc::clone(&file));
        move || {
            if let Ok(now) = crate::clock::unix_secs() {
                file.save_unless_busy(&store, VERSION, now);
            }
        }
    });
    (
        Counters {
            store,
            file,
            upgrade,
        },
        saver,
    )
}

impl Counters {
    /// The shutdown step that writes `counters.json`.
    pub(super) fn shutdown_save(&self) -> ShutdownSave {
        let (store, file) = (Arc::clone(&self.store), Arc::clone(&self.file));
        (
            "counter save (counters.json)",
            Box::new(move || {
                if let Ok(now) = crate::clock::unix_secs() {
                    file.save(&store, VERSION, now);
                }
            }),
        )
    }
}
