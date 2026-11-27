// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The HTTP gateway config that run-level rows start from: loopback on a
//! port the gateway picks, a 30 s stop, the task store under the row's own
//! directory. Each row adds what it tests on top.

use std::time::Duration;

use crate::config::Config;

/// The shared start of a run-level row's config, its task store under `dir`.
pub(super) fn http_test_config(dir: &std::path::Path) -> Config {
    let mut config = Config::default();
    config.server.host = "127.0.0.1".to_string();
    config.server.port = 0;
    config.server.shutdown_timeout = Duration::from_secs(30);
    config.tasks.store_dir = dir.join("tasks").to_string_lossy().into_owned();
    config
}
