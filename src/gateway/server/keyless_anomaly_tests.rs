// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7215.CONTROL.5, gap G5: an HTTP start with anomaly detection on and no
//! possible caller key is refused before anything binds.

use super::Gateway;
use crate::config::Config;

#[tokio::test]
async fn http_start_with_keyless_anomaly_detection_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = Config::default();
    config.auth.enabled = false;
    config.security.firewall.enabled = true;
    config.security.firewall.anomaly_detection = true;
    // Port 0 and temp stores: were the refusal missing, the start would bind
    // and serve, and the timeout below would fire.
    config.server.port = 0;
    config.tasks.store_dir = dir.path().join("tasks").to_string_lossy().into_owned();
    let gateway = Gateway::new(config)
        .await
        .expect("the config loads")
        .with_data_dir(dir.path().to_path_buf());

    let started = tokio::time::timeout(std::time::Duration::from_secs(5), gateway.run()).await;

    let err = started
        .expect("a refused start returns at once")
        .expect_err("started with no caller key for the detector");
    let message = err.to_string();
    assert!(message.contains("anomaly_detection"), "{message}");
    assert!(message.contains("auth.enabled"), "{message}");
}
