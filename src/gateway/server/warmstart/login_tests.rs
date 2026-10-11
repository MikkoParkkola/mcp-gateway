// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8339 LOGINDL.3: a warm-start attempt is a caller bounded by its own
//! ceiling (`effective_attempt_timeout`). When that ceiling fires during the
//! request-time login the attempt began, only the attempt's wait ends: the
//! login stays open, and the warm start's retry after approval uses it, with
//! no second browser.

use std::sync::Arc;
use std::time::Duration;

use super::{WarmStartMode, WarmStartPolicy, effective_attempt_timeout, warm_start_until_cached};
use crate::backend::BackendRegistry;
use crate::backend::tests::login_server::Upstream;
use crate::backend::tests::login_window::{approve_if_listening, approved_start, within};
use crate::backend::tests::token_lapse::lapse;

/// Gaps short enough that the retries after approval finish in real time.
fn quick_policy() -> WarmStartPolicy {
    WarmStartPolicy {
        fast_deadline: Duration::from_secs(180),
        initial_gap: Duration::from_millis(10),
        max_gap: Duration::from_millis(50),
        slow_gap: Duration::from_millis(50),
        attempt_timeout: Duration::from_millis(1),
    }
}

#[tokio::test]
async fn a_warm_start_attempts_bound_leaves_its_request_time_login_open() {
    let (backend, browser, _dir) = approved_start(Upstream::Plain, Duration::from_secs(2)).await;
    lapse(&backend).await;
    assert_eq!(
        browser.opens(),
        1,
        "premise: only the start's own login so far"
    );
    let registry = Arc::new(BackendRegistry::new());
    assert!(
        registry.register(Arc::clone(&backend)),
        "premise: registered"
    );

    let warm = {
        let registry = Arc::clone(&registry);
        let name = backend.name.clone();
        let instance = Arc::downgrade(&backend);
        tokio::spawn(async move {
            warm_start_until_cached(
                &registry,
                &name,
                &quick_policy(),
                WarmStartMode::Http,
                &instance,
            )
            .await;
        })
    };
    let url = browser
        .opened(2, "the warm start's request-time login")
        .await;
    // Past the attempt's own ceiling, with the person still away. Paused
    // time: the attempt waits on a login no I/O can advance, and the login's
    // own window (300 s) is well past the ceiling.
    let ceiling =
        effective_attempt_timeout(quick_policy().attempt_timeout, backend.request_timeout());
    assert!(
        ceiling < crate::oauth::OAUTH_AUTHORIZATION_WINDOW,
        "premise: the attempt ends before the login's own window"
    );
    tokio::time::pause();
    tokio::time::advance(ceiling + Duration::from_secs(1)).await;
    tokio::time::resume();
    assert!(
        !warm.is_finished(),
        "premise: no attempt cached tools before the approval"
    );

    // The timed-out attempt is dropped by now; give its teardown a moment.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        approve_if_listening(&url).await,
        "the login the warm start's attempt began was gone when the person approved it"
    );
    within("the warm start's retry after approval", warm)
        .await
        .expect("warm-start task");
    assert_eq!(
        browser.opens(),
        2,
        "the warm start's retry used the login its first attempt began"
    );
}
