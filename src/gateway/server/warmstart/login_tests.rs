// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8339 LOGINDL.3: a warm-start attempt is a caller bounded by its
//! backend's request timeout. When that bound fires during the request-time
//! login the attempt began, only the attempt's wait ends: the login stays
//! open, and the warm start's retry after approval uses it, with no second
//! browser.

use std::sync::Arc;
use std::time::Duration;

use super::{WarmStartMode, WarmStartPolicy, warm_start_until_cached};
use crate::backend::BackendRegistry;
use crate::backend::tests::login_server::Upstream;
use crate::backend::tests::login_window::{approve, approved_start, within};
use crate::backend::tests::token_lapse::lapse;

/// Gaps short enough that the retries after approval finish in real time.
/// The attempt ceiling is `max(floor, 20 x the 2 s request timeout)`, so the
/// request timeout, not the ceiling, is the bound each attempt meets.
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
    // Past the attempt's 2 s request bound, with the person still away.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !warm.is_finished(),
        "premise: no attempt cached tools before the approval"
    );

    approve(&url).await;
    within("the warm start's retry after approval", warm)
        .await
        .expect("warm-start task");
    assert_eq!(
        browser.opens(),
        2,
        "the warm start's retry used the login its first attempt began"
    );
}
