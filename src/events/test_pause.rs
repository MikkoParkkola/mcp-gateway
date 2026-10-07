// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-only pause points: the first caller to reach an armed point stops
//! there until the test releases it, so a race can be laid out step by step.

use std::sync::Arc;

use tokio::sync::Notify;

/// One pause point; idle until [`Slot::arm`].
#[derive(Default)]
pub(crate) struct Slot(parking_lot::Mutex<Option<(Arc<Notify>, Arc<Notify>)>>);

impl Slot {
    /// Arm the point for one caller. Returns `(reached, release)`: the caller
    /// signals `reached` on arrival and waits for `release`.
    pub(crate) fn arm(&self) -> (Arc<Notify>, Arc<Notify>) {
        let pair = (Arc::new(Notify::new()), Arc::new(Notify::new()));
        *self.0.lock() = Some(pair.clone());
        pair
    }

    /// Stop here if armed. One-shot: the first caller takes the point, so a
    /// second caller passes straight through.
    pub(crate) async fn pause(&self) {
        let armed = self.0.lock().take();
        if let Some((reached, release)) = armed {
            reached.notify_one();
            release.notified().await;
        }
    }
}
