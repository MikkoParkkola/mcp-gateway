// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8854 red stub for `counters.json`: restores nothing, quarantines
//! nothing, writes `{}` with the default mode and never skips a save.

use std::path::PathBuf;

use super::CounterStore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    Serializing,
    Writing,
}

#[derive(Debug)]
pub(crate) struct CounterFile {
    path: PathBuf,
    busy: parking_lot::Mutex<()>,
}

#[derive(Debug)]
pub(crate) struct Restored {
    pub store: CounterStore,
    pub file: CounterFile,
    pub warnings: usize,
}

impl CounterFile {
    pub(crate) fn restore<Tz: chrono::TimeZone>(
        path: PathBuf,
        now: u64,
        _binary_version: &str,
        _zone: &Tz,
    ) -> Restored {
        Restored {
            store: CounterStore::new(now),
            file: Self {
                path,
                busy: parking_lot::Mutex::new(()),
            },
            warnings: 0,
        }
    }

    pub(crate) fn disabled(&self) -> bool {
        false
    }

    pub(crate) fn save(&self, store: &CounterStore, binary_version: &str, now: u64) {
        let _ = std::fs::write(&self.path, store.to_bytes(binary_version, now));
    }

    pub(crate) fn save_unless_busy(
        &self,
        store: &CounterStore,
        binary_version: &str,
        now: u64,
    ) -> bool {
        self.save(store, binary_version, now);
        true
    }

    #[cfg(test)]
    pub(crate) fn save_with(
        &self,
        store: &CounterStore,
        binary_version: &str,
        now: u64,
        _hook: &dyn Fn(Stage),
    ) {
        self.save(store, binary_version, now);
    }

    #[cfg(test)]
    pub(crate) fn hold_for_test(&self) -> parking_lot::MutexGuard<'_, ()> {
        self.busy.lock()
    }
}
