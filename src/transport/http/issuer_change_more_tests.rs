// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The install record under a changed issuer while a re-discovery is in
//! flight: a second confirm that lands meanwhile is the one adopted.

use std::sync::Arc;

use super::issuer_change_tests::{Caller, a_token, world};
use crate::test_pause::within;

// A second confirm bumps the install count while the first re-discovery is
// parked after fetching its documents. After the release the newest install is
// the one adopted, not the first. Red today: the serving client reads its own
// key and never reaches either install.
#[tokio::test]
async fn a_second_install_during_rediscovery_is_adopted_not_lost() {
    let w = Arc::new(world().await);
    w.confirm(a_token("first", Some("r1"))).await;
    let (reached, release) = w.serving_client().lock().await.rediscovery_pause.arm();
    let call = tokio::spawn({
        let w = Arc::clone(&w);
        async move { w.token(Caller::Interactive).await }
    });
    within("the re-discovery parks after its fetch", reached.notified()).await;

    w.confirm(a_token("second", Some("r2"))).await;
    release.notify_one();

    let adopted = call.await.expect("the call ran").expect("a token");
    assert_eq!(adopted.as_deref(), Some("second"));
}
