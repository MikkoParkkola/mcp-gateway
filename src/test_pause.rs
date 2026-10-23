// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-only pause points: the first caller to reach an armed point stops
//! there until the test releases it, so a race can be laid out step by step.

use std::sync::Arc;

use tokio::sync::Notify;

/// One pause point; idle until [`Slot::arm`].
#[derive(Debug, Default)]
pub(crate) struct Slot(parking_lot::Mutex<Option<(Arc<Notify>, Arc<Notify>)>>);

impl Slot {
    /// Arm the point for one caller. Returns `(reached, release)`: the caller
    /// signals `reached` on arrival and waits for `release`.
    pub(crate) fn arm(&self) -> (Arc<Notify>, Arc<Notify>) {
        let pair = (Arc::new(Notify::new()), Arc::new(Notify::new()));
        let earlier = self.0.lock().replace(pair.clone());
        assert!(earlier.is_none(), "pause point armed twice");
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

    /// [`Self::pause`] for synchronous code on a blocking thread. Only an
    /// armed point blocks, so an unarmed caller on a runtime thread passes.
    pub(crate) fn pause_blocking(&self) {
        let armed = self.0.lock().take();
        if let Some((reached, release)) = armed {
            reached.notify_one();
            tokio::runtime::Handle::current().block_on(release.notified());
        }
    }
}

/// Await `step`, failing the test after 30 s so a broken handshake shows as
/// a named failure, not a CI timeout.
pub(crate) async fn within<T>(what: &str, step: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(std::time::Duration::from_secs(30), step)
        .await
        .unwrap_or_else(|_| panic!("{what} did not finish within 30 s"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn slot_pause_is_one_shot() {
        let slot = Arc::new(Slot::default());
        let (reached, release) = slot.arm();
        let parked = Arc::clone(&slot);
        let a = tokio::spawn(async move { parked.pause().await });
        within("A reached", reached.notified()).await;
        within("second pause passes", slot.pause()).await;
        // Release has not been sent, so the first caller must still be parked.
        assert!(
            !a.is_finished(),
            "the armed caller must stay parked until release"
        );
        release.notify_one();
        let done = within("A finishes", a).await;
        assert!(done.is_ok(), "parked task panicked: {done:?}");
        within("third pause passes", slot.pause()).await;
    }

    #[tokio::test]
    async fn slot_rearms_after_a_take() {
        let slot = Arc::new(Slot::default());
        let (reached, release) = slot.arm();
        let parked = Arc::clone(&slot);
        let a = tokio::spawn(async move { parked.pause().await });
        within("first reached", reached.notified()).await;
        release.notify_one();
        let done = within("first finishes", a).await;
        assert!(done.is_ok(), "first parked task panicked: {done:?}");
        let (reached, release) = slot.arm();
        let parked = Arc::clone(&slot);
        let b = tokio::spawn(async move { parked.pause().await });
        within("second reached", reached.notified()).await;
        release.notify_one();
        let done = within("second finishes", b).await;
        assert!(done.is_ok(), "second parked task panicked: {done:?}");
    }

    #[tokio::test]
    async fn slot_unarmed_pause_passes() {
        let slot = Slot::default();
        within("unarmed", slot.pause()).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn slot_pause_blocking_is_one_shot() {
        let slot = Arc::new(Slot::default());
        let (reached, release) = slot.arm();
        let parked = Arc::clone(&slot);
        let first = tokio::task::spawn_blocking(move || parked.pause_blocking());
        within("blocking reached", reached.notified()).await;
        let second_caller = Arc::clone(&slot);
        let second = tokio::task::spawn_blocking(move || second_caller.pause_blocking());
        let passed = within("second blocking passes", second).await;
        assert!(
            passed.is_ok(),
            "pass-through blocking task panicked: {passed:?}"
        );
        release.notify_one();
        let done = within("first blocking finishes", first).await;
        assert!(done.is_ok(), "parked blocking task panicked: {done:?}");
    }
}
