// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `backends.<name>.max_frame_bytes` loading and validation.

use super::*;
use crate::gateway::test_helpers::write_owner_only;

fn load_backend_yaml(body: &str) -> crate::Result<Config> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, body).expect("write");
    Config::load(Some(&path))
}

#[test]
fn max_frame_bytes_round_trips_on_a_stdio_backend() {
    let cfg = load_backend_yaml(
        "backends:\n  big:\n    command: \"echo hi\"\n    max_frame_bytes: 67108864\n",
    )
    .expect("a stdio backend may raise its frame limit");
    assert_eq!(cfg.backends["big"].max_frame_bytes, Some(64 * 1024 * 1024));
}

#[test]
fn max_frame_bytes_is_refused_outside_its_range_and_on_a_url_backend() {
    for yaml in [
        "backends:\n  b:\n    command: \"echo hi\"\n    max_frame_bytes: 100\n",
        "backends:\n  b:\n    command: \"echo hi\"\n    max_frame_bytes: 2147483648\n",
        "backends:\n  b:\n    http_url: \"http://127.0.0.1:39400/mcp\"\n    max_frame_bytes: 1048576\n",
    ] {
        let err = load_backend_yaml(yaml).expect_err(yaml).to_string();
        assert!(err.contains("max_frame_bytes"), "{err}");
    }
}
