// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An HTTP start whose `server.shutdown_timeout` cannot hold the stop's stages
//! is refused before anything binds; a stdio gateway keeps its own small bound.

use std::time::Duration;

use super::Gateway;
use super::start_checks;
use crate::config::Config;

/// A hang bound only: the refused start returns at once.
const HANG_BOUND: Duration = Duration::from_secs(60);

fn with_timeout(total: Duration) -> Config {
    let mut config = Config::default();
    config.server.shutdown_timeout = total;
    config
}

#[test]
fn the_start_check_accepts_the_minimum_and_the_default_and_refuses_less() {
    // timing: fixture
    assert!(start_checks::http(&with_timeout(Duration::from_millis(12_500))).is_ok());
    assert!(
        start_checks::http(&Config::default()).is_ok(),
        "the 30 s default"
    );
    // timing: fixture
    let err = start_checks::http(&with_timeout(Duration::from_millis(12_499)))
        .expect_err("12.499 s cannot hold the stop");
    let message = err.to_string();
    assert!(message.contains("server.shutdown_timeout"), "{message}");
    assert!(
        message.contains("12.499") && message.contains("12.5s"),
        "{message}"
    );
}

#[tokio::test]
async fn an_http_start_below_the_stop_budget_minimum_is_refused_before_it_binds() {
    let dir = crate::test_dir_keep::kept_tempdir();
    // timing: fixture
    let mut config = with_timeout(Duration::from_millis(12_499));
    // Port 0 and temp stores: were the refusal missing, the start would bind
    // and serve, and the timeout below would fire.
    config.server.port = 0;
    config.tasks.store_dir = dir.path().join("tasks").to_string_lossy().into_owned();
    let gateway = Gateway::new(config)
        .await
        .expect("the config loads")
        .with_data_dir(dir.path().to_path_buf());

    let started = tokio::time::timeout(HANG_BOUND, gateway.run()).await;

    let err = started
        .expect("a refused start returns at once")
        .expect_err("started with a total the stop cannot fit in");
    let message = err.to_string();
    assert!(message.contains("server.shutdown_timeout"), "{message}");
    assert!(message.contains("12.5s"), "{message}");
}
