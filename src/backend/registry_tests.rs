// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Registration around shutdown: a backend registered after `stop_all` is
//! refused, and a refused registration leaves the existing one in place.

use std::time::Duration;

use super::*;
use crate::config::{BackendConfig, TransportConfig};

fn stdio_backend(name: &str) -> Arc<Backend> {
    let cfg = BackendConfig {
        transport: TransportConfig::Stdio {
            command: "/nonexistent-mcp-binary".to_string(),
            cwd: None,
            protocol_version: None,
        },
        ..BackendConfig::default()
    };
    Arc::new(Backend::new(
        name,
        cfg,
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

// A backend registered after shutdown has taken its snapshot would never be
// stopped, and its process would outlive the gateway. Config reload can
// genuinely race shutdown, so the registry refuses late registrations
// rather than accepting one it cannot honour.
#[tokio::test]
async fn a_backend_registered_after_shutdown_is_refused() {
    let registry = BackendRegistry::new();
    assert!(
        registry.register(stdio_backend("before")),
        "registration before shutdown must be accepted"
    );

    registry.stop_all().await;

    assert!(
        !registry.register(stdio_backend("after")),
        "the registry accepted a backend after shutdown; nothing will ever \
         stop it"
    );
    assert!(
        registry.get("after").is_none(),
        "a backend refused during shutdown must not be in the registry"
    );
}

// A refused registration must not disturb an entry someone else registered
// successfully under the same name.
#[tokio::test]
async fn a_refused_registration_does_not_evict_an_existing_one() {
    let registry = BackendRegistry::new();
    let original = stdio_backend("shared-name");
    assert!(registry.register(Arc::clone(&original)));

    registry.stop_all().await;

    assert!(
        !registry.register(stdio_backend("shared-name")),
        "a registration during shutdown must be refused"
    );
    let still_there = registry
        .get("shared-name")
        .expect("the refused registration evicted an entry it did not create");
    assert!(
        Arc::ptr_eq(&still_there, &original),
        "the entry under this name is not the one that was registered"
    );
}
