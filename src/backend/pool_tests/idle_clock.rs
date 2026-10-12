// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 P4b row B3: idle eviction is a duration, so a dark wall clock
//! does not stop it.

use super::*;
use crate::clock::test_clock;

/// MIK-8202 AC.2, P4b design r1 B3 (kept by r4; test plan r2: monotonic means
/// `tokio::time::Instant`): an idle slot's age is measured on the monotonic
/// clock, so a wall clock before 1970 neither hides nor fakes idleness.
///
/// Red on base: base stamps `last_used` and measures the age by reading the
/// wall clock directly, which neither the forced dark clock nor paused tokio
/// time reaches; real time barely moves during the test, so after the paused
/// advance the slot still reads as fresh and the post-advance assertion fails.
///
/// Mutant B3m (the eviction reads crate::clock's wall clock again): on the dark
/// clock either the read is an error taken as "not idle", killed by the
/// post-advance assertion, or it is taken as an ancient stamp, killed by the
/// pre-advance negative.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn an_idle_slot_is_stopped_after_its_limit_while_the_clock_is_dark() {
    let _clock = test_clock::before_epoch();
    let idle_for = Duration::from_secs(60);
    let backend = stoppable_backend(idle_for);
    let transport = Arc::new(SessionMock::new("shared"));
    backend.set_transport_for_test(transport.clone());

    tokio::time::advance(idle_for - Duration::from_secs(1)).await;
    assert!(
        !backend.stop_if_idle().await,
        "B3 pre-advance: a slot younger than its idle limit is not stopped"
    );
    assert!(!transport.closed.load(Ordering::SeqCst));

    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(
        backend.stop_if_idle().await,
        "B3: a slot idle past its limit is stopped though the wall clock reads before 1970"
    );
    assert!(transport.closed.load(Ordering::SeqCst));
}
