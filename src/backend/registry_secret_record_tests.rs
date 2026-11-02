// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The order in which the stored scrub takes the retained value sets.

use std::sync::Arc;
use std::time::Duration;

use super::super::{Backend, BackendRegistry};

fn backend(name: &str) -> Arc<Backend> {
    let cfg = crate::config::BackendConfig {
        transport: crate::config::TransportConfig::Stdio {
            command: "/nonexistent-mcp-binary".to_string(),
            cwd: None,
            protocol_version: None,
        },
        ..crate::config::BackendConfig::default()
    };
    Arc::new(Backend::new(
        name,
        cfg,
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

/// The retained sets come back by backend name, not in the map's order or
/// the order the backends registered. Twelve names, registered out of order:
/// without the sort, the map's order matches by chance about once in 12!.
#[tokio::test]
async fn retained_sets_come_back_by_backend_name() {
    let registry = BackendRegistry::new();
    for name in ["g", "c", "k", "a", "j", "e", "l", "b", "h", "d", "i", "f"] {
        #[allow(
            clippy::disallowed_methods,
            reason = "Test: registers the backends whose sets are ordered"
        )]
        let registered = registry.register(backend(name));
        assert!(registered, "premise: {name} registered");
    }
    let sets = registry.retained_sets();
    let expected: Vec<_> = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"]
        .into_iter()
        .map(|name| Arc::clone(registry.needles.get(name).expect("premise: a set").value()))
        .collect();
    assert_eq!(sets.len(), expected.len(), "premise: one set per backend");
    for (at, (got, want)) in sets.iter().zip(&expected).enumerate() {
        assert!(
            Arc::ptr_eq(got, want),
            "set {at} is not the name-ordered one"
        );
    }
}
