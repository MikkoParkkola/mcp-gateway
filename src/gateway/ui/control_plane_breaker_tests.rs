// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::{
    ControlPlaneHealth, ControlPlaneServerStatus, runtime_health_from_backend,
    server_status_from_backend,
};
use crate::backend::Backend;
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};

fn backend() -> Backend {
    let transport = TransportConfig::Http {
        http_url: "http://127.0.0.1:9/mcp".to_string(),
        streamable_http: false,
        protocol_version: None,
    };
    let config = BackendConfig {
        transport,
        enabled: true,
        ..BackendConfig::default()
    };
    let timeout = std::time::Duration::from_secs(60);
    Backend::new("down", config, &FailsafeConfig::default(), timeout)
}

#[test]
fn control_plane_reports_open_breaker_down_and_blocked() {
    let backend = backend();
    let closed = backend.status();
    assert_eq!(
        server_status_from_backend(&closed),
        ControlPlaneServerStatus::Enabled
    );
    // Never started, so not running: a closed breaker reads as not yet known.
    assert_eq!(
        runtime_health_from_backend(&closed),
        ControlPlaneHealth::Unknown
    );

    backend.trip_circuit_breaker_for_test();
    let open = backend.status();
    assert_eq!(
        server_status_from_backend(&open),
        ControlPlaneServerStatus::Blocked
    );
    assert_eq!(runtime_health_from_backend(&open), ControlPlaneHealth::Down);
}
