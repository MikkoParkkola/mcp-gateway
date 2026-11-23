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

    /// [`Self::pause`] for a plain thread with no Tokio runtime, such as a
    /// detached save thread. Only an armed point blocks, and for at most 30 s:
    /// a row that fails before its release never parks the thread for good.
    pub(crate) fn pause_on_thread(&self) {
        let armed = self.0.lock().take();
        if let Some((reached, release)) = armed {
            reached.notify_one();
            let waiter = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .expect("a pause runtime builds");
            // The timeout is built inside block_on: creating its timer needs
            // the runtime's context, which a plain thread has only there.
            let _ = waiter.block_on(async {
                tokio::time::timeout(std::time::Duration::from_secs(30), release.notified()).await
            });
        }
    }
}

/// Releases a pause point when dropped, so a row that fails before its own
/// release never leaves a writer parked.
pub(crate) struct Release(pub(crate) Arc<Notify>);

impl Release {
    /// Release now; dropping it later is then a no-op for the writer.
    pub(crate) fn now(&self) {
        self.0.notify_one();
    }
}

impl Drop for Release {
    fn drop(&mut self) {
        self.0.notify_one();
    }
}

/// Wait for `reached` without a runtime, or with the caller's runtime
/// thread blocked (so a paused clock cannot auto-advance meanwhile), failing
/// after 30 s. A helper thread turns the notification into a bounded receive.
pub(crate) fn reached_blocking(what: &str, reached: &Arc<Notify>) {
    let (sent, got) = std::sync::mpsc::channel();
    let reached = Arc::clone(reached);
    std::thread::spawn(move || {
        futures::executor::block_on(reached.notified());
        let _ = sent.send(());
    });
    assert!(
        got.recv_timeout(std::time::Duration::from_secs(30)).is_ok(),
        "{what} was not reached within 30 s"
    );
}

/// Await `step`, failing the test after 30 s so a broken handshake shows as
/// a named failure, not a CI timeout.
pub(crate) async fn within<T>(what: &str, step: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(std::time::Duration::from_secs(30), step)
        .await
        .unwrap_or_else(|_| panic!("{what} did not finish within 30 s"))
}

#[cfg(tp3)]
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

    /// A plain thread with no runtime parks at an armed point until the
    /// release; a second caller passes straight through.
    #[tokio::test]
    async fn slot_pause_on_thread_holds_a_plain_thread() {
        let slot = Arc::new(Slot::default());
        let (reached, release) = slot.arm();
        let parked = Arc::clone(&slot);
        let (done, mut finished) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            parked.pause_on_thread();
            let _ = done.send(());
        });
        within("thread reached", reached.notified()).await;
        slot.pause_on_thread();
        // limit-under-test (fires-only): the parked thread cannot finish before the release, so this window always expires; a slow runner only delays it.
        let window = std::time::Duration::from_millis(100);
        // timing: absence
        let early = tokio::time::timeout(window, &mut finished).await;
        assert!(early.is_err(), "the armed thread did not wait for release");
        release.notify_one();
        let after = within("thread finishes", finished).await;
        assert!(after.is_ok(), "the parked thread ended without finishing");
    }
}
