// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stored answer is scrubbed against every value set the registry keeps,
//! including a removed backend's while its values are inside their grace
//! (MIK-9105).

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
