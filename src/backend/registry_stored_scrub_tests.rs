// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stored answer is scrubbed against every value set the registry keeps,
//! including a removed backend's while its values are inside their grace.

use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::config::configured_secrets::{
    ConfiguredByBackend, ConfiguredSecret, ConfiguredSecrets, SecretOrigin,
};
use crate::config::{BackendConfig, TransportConfig};
use crate::protocol::{JsonRpcResponse, RequestId};

const GRACE: Duration = Duration::from_secs(3_600);
const VALUE: &str = "removed-backend-token-5c";

fn backend(name: &str) -> Arc<Backend> {
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

/// Whether a stored answer holding the value leaves with it removed.
fn served_redacted(registry: &BackendRegistry) -> bool {
    let mut answer = JsonRpcResponse::success(
        RequestId::Number(1),
        serde_json::json!({"text": format!("echo {VALUE}")}),
    );
    let _ = registry.scrub_stored(&mut answer);
    !serde_json::to_string(&answer)
        .expect("serializes")
        .contains(VALUE)
}

/// A removed backend's configured value is still removed from a stored
/// answer (served for any backend) until its grace passes, then not.
#[tokio::test(start_paused = true)]
async fn a_removed_backends_value_is_scrubbed_from_stored_answers_through_its_grace() {
    let registry = BackendRegistry::new().with_redaction_grace(GRACE);
    let record = ConfiguredSecrets::of(vec![ConfiguredSecret {
        field: "headers.X-Key".to_owned(),
        value: VALUE.to_owned(),
        origin: SecretOrigin::Explicit,
    }]);
    registry.set_load_record(ConfiguredByBackend::from([("gone".to_owned(), record)]));
    #[allow(
        clippy::disallowed_methods,
        reason = "Test: registers the backend the row removes"
    )]
    let registered = registry.register(backend("gone"));
    assert!(registered, "premise: registered");
    assert!(served_redacted(&registry), "premise: held while registered");

    assert!(registry.remove("gone"), "premise: removed");
    tokio::time::advance(Duration::from_secs(3_599)).await;
    assert!(
        served_redacted(&registry),
        "dropped before its grace passed"
    );
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(!served_redacted(&registry), "still held after its grace");
}

/// A replacement registered without the value its predecessor held starts
/// that value's grace once it is in: still removed until then, not after.
#[tokio::test(start_paused = true)]
async fn a_replacement_lacking_a_value_retires_it_a_grace_after_it_registers() {
    let registry = BackendRegistry::new().with_redaction_grace(GRACE);
    let record = ConfiguredSecrets::of(vec![ConfiguredSecret {
        field: "headers.X-Key".to_owned(),
        value: VALUE.to_owned(),
        origin: SecretOrigin::Explicit,
    }]);
    registry.set_load_record(ConfiguredByBackend::from([("b".to_owned(), record)]));
    #[allow(
        clippy::disallowed_methods,
        reason = "Test: registers the instance the row replaces"
    )]
    let first = registry.register(backend("b"));
    assert!(first, "premise: registered");
    registry.set_load_record(ConfiguredByBackend::new());
    #[allow(
        clippy::disallowed_methods,
        reason = "Test: registers the replacement, whose record lacks the value"
    )]
    let second = registry.register(backend("b"));
    assert!(second, "premise: the replacement registered");
    tokio::time::advance(Duration::from_secs(3_599)).await;
    assert!(
        served_redacted(&registry),
        "the value retired before its grace"
    );
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(
        !served_redacted(&registry),
        "the replaced instance's value never started its grace"
    );
}

/// Where one backend's redaction would form another's value, the stored
/// answer's outcome does not depend on the map's order. Each registry hashes
/// its names with its own seed, so the 16 below iterate in varying orders.
/// The sets are taken by backend name, so every one refuses: the first set
/// finds nothing, the second's marker forms its value, and the rescan refuses.
#[tokio::test(start_paused = true)]
async fn a_cross_set_answer_gets_one_outcome_in_any_map_order() {
    for round in 0..16 {
        let registry = BackendRegistry::new().with_redaction_grace(GRACE);
        let order = if round % 2 == 0 {
            ["a", "b"]
        } else {
            ["b", "a"]
        };
        for name in order {
            #[allow(
                clippy::disallowed_methods,
                reason = "Test: registers the two backends whose sets interact"
            )]
            let registered = registry.register(backend(name));
            assert!(registered, "premise: {name} registered");
        }
        registry.mark_for_test("a", "prefix[redact");
        registry.mark_for_test("b", "other-token-value");
        let mut answer = JsonRpcResponse::success(
            RequestId::Number(1),
            serde_json::json!({"text": "prefixother-token-value"}),
        );
        let outcome = registry.scrub_stored(&mut answer);
        let wire = serde_json::to_string(&answer).expect("serializes");
        assert_eq!(
            outcome,
            crate::security::needles::Scrubbed::Refuse,
            "round {round}: {wire}"
        );
        assert!(
            !wire.contains("prefix[redact"),
            "round {round}: the formed value left: {wire}"
        );
    }
}
