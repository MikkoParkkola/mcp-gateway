// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The direct fixture's pieces for the MIK-8293 slot-cap rows: backends with
//! no rate limiter, and a propagating fixture (two backends that require
//! identity propagation to distinct audiences, with the audit sinks and HTTP
//! base URL a required propagation needs).

use std::sync::Arc;

use super::{Answer, Fx, MetaMcp, fixture};
use crate::config::{BackendConfig, FailsafeConfig};

/// A transparency log on a leaked temp file, alive for the test process.
pub(super) fn leaked_transparency_log() -> Arc<crate::security::TransparencyLogger> {
    use crate::security::transparency_log::TransparencyLogConfig;
    let file = tempfile::NamedTempFile::new().expect("tempfile");
    let path = file.path().to_string_lossy().to_string();
    std::mem::forget(file);
    let config = Arc::new(TransparencyLogConfig {
        enabled: true,
        path,
        key_id: "test".to_string(),
        ..TransparencyLogConfig::default()
    });
    Arc::new(crate::security::TransparencyLogger::open(config).expect("logger opens"))
}

/// The fixture's backends with the per-backend rate limiter off: no row here
/// tests it (`probe_tests` does, on its own backend), and the slot-cap rows
/// (MIK-8293) send 65 calls in a burst.
pub(super) fn fixture_failsafe() -> FailsafeConfig {
    let mut failsafe = FailsafeConfig::default();
    failsafe.rate_limit.enabled = false;
    failsafe
}

/// [`fixture`] whose two backends require identity propagation to distinct
/// audiences; `arm` installs the strategy (MIK-8293 S3c).
pub(crate) async fn fixture_propagating(answer: Answer, arm: impl FnOnce(&mut MetaMcp)) -> Fx {
    super::PROPAGATING.with(|p| p.set(true));
    let fx = fixture(answer, |meta| {
        // The meta layer checks for its own audit sink before a required mint.
        meta.enable_transparency_log(leaked_transparency_log());
        arm(meta);
    })
    .await;
    super::PROPAGATING.with(|p| p.set(false));
    fx
}

/// One fixture backend's config: pass-through or not, and, for a propagating
/// fixture, a required propagation to `aud-<name>` over an HTTP base URL.
pub(super) fn fixture_backend_config(name: &str, passthrough: bool) -> BackendConfig {
    BackendConfig {
        passthrough,
        // A propagating backend validates an HTTP base URL before it
        // reaches the scripted transport.
        transport: if super::PROPAGATING.with(std::cell::Cell::get) {
            crate::config::TransportConfig::Http {
                http_url: format!("https://{name}.internal/mcp"),
                streamable_http: Some(true),
                protocol_version: None,
            }
        } else {
            BackendConfig::default().transport
        },
        identity_propagation: super::PROPAGATING.with(std::cell::Cell::get).then(|| {
            crate::identity_propagation::IdentityPropagationConfig {
                strategy: crate::identity_propagation::PropagationStrategyKind::SignedAssertion,
                audience: format!("aud-{name}"),
                required: true,
                session_mode: crate::identity_propagation::SessionMode::Stateless,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }
        }),
        ..BackendConfig::default()
    }
}
