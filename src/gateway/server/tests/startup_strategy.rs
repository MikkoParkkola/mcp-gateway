// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Startup decisions read from config: the minting strategy, the single-user
//! leak warning and the SIEM export poll (moved from `server/mod.rs`, MIK-8144).

use super::*;

// ── GPT review F1 (MIK-6746): a passthrough-only deployment must NOT install
// the minting strategy, else the meta route would mint for a passthrough
// backend (INV-4 violation). Mixed deployments still install it. ──
fn backend_with_strategy(
    strategy: crate::identity_propagation::PropagationStrategyKind,
) -> BackendConfig {
    use crate::identity_propagation::{IdentityPropagationConfig, SessionMode};
    BackendConfig {
        transport: TransportConfig::Http {
            http_url: "https://backend.internal/mcp".to_string(),
            streamable_http: Some(false),
            protocol_version: None,
        },
        identity_propagation: Some(IdentityPropagationConfig {
            strategy,
            audience: "https://backend.internal".to_string(),
            required: true,
            session_mode: SessionMode::Stateless,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        }),
        ..BackendConfig::default()
    }
}

// ── SIEM export poison recovery (MIK-6909, AC.2) ─────────────────────────
// A panic elsewhere while the export mutex is held must not crash the export
// path: `poll_export_source` recovers the guard via `PoisonError::into_inner`
// and keeps forwarding. This proves the recovery both survives the poison
// AND still does useful work (forwards the pending log entry).
#[tokio::test]
async fn export_poll_recovers_from_a_poisoned_exporter_mutex() {
    use std::sync::Mutex;

    use super::super::poll_export_source;
    use crate::control_plane::{
        CollectingSink, ExportSink, ExportSource, LogExporter, SourceExportStatus,
    };
    use crate::security::TransparencyLogger;
    use crate::security::transparency_log::TransparencyLogConfig;

    let dir = tempfile::tempdir().expect("tempdir");
    let log_path = dir.path().join("inv.jsonl");
    let logger = TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: log_path.to_string_lossy().into_owned(),
        key_id: "test".to_string(),
        ..TransparencyLogConfig::default()
    }))
    .expect("open transparency log");
    logger
        .log_invocation("s1", "caller", "srv", "tool", "req:1", "resp:1")
        .expect("append one entry");

    let exporter = Arc::new(Mutex::new(
        LogExporter::open(
            ExportSource::Invocation,
            log_path.clone(),
            dir.path().join("cursor.json"),
        )
        .expect("open exporter"),
    ));

    // Poison the mutex: a separate thread panics while holding the guard.
    let poison_target = Arc::clone(&exporter);
    let _ = std::thread::spawn(move || {
        let _guard = poison_target.lock().expect("acquire lock before poisoning");
        panic!("intentional poison for the test");
    })
    .join();
    assert!(
        exporter.is_poisoned(),
        "precondition: the export mutex must be poisoned"
    );

    let collecting = Arc::new(CollectingSink::new());
    let sink: Arc<dyn ExportSink> = collecting.clone();
    let status = SourceExportStatus::default();

    // A pre-recovery `.expect(...)` over the poisoned lock would panic inside
    // `spawn_blocking`; tokio catches that as a `JoinError`, which the `Err(e)`
    // arm here turns into a logged failure with nothing delivered — so the
    // regression signal is `delivered().len() == 0`, not a panicking test.
    // With recovery in place the guard is reclaimed and the poll completes.
    poll_export_source(&exporter, &sink, &status, "invocation").await;

    assert_eq!(
        collecting.delivered().len(),
        2,
        "recovered poll must forward the genesis open record (#2275) and the pending entry"
    );
}

#[test]
fn passthrough_only_deployment_installs_no_minting_strategy() {
    use crate::identity_propagation::PropagationStrategyKind;
    let mut config = Config::default();
    config.backends.insert(
        "pass".to_string(),
        backend_with_strategy(PropagationStrategyKind::Passthrough),
    );
    assert!(
        !super::super::config_installs_minting_strategy(&config),
        "passthrough-only must not install the minting strategy (F1)"
    );
}

#[test]
fn minting_and_mixed_deployments_install_the_strategy() {
    use crate::identity_propagation::PropagationStrategyKind;
    let mut minting = Config::default();
    minting.backends.insert(
        "sign".to_string(),
        backend_with_strategy(PropagationStrategyKind::SignedAssertion),
    );
    assert!(super::super::config_installs_minting_strategy(&minting));
    // Mixed: one minting + one passthrough still installs it (residual F1 on
    // the meta route for the passthrough backend tracked on MIK-6746).
    minting.backends.insert(
        "pass".to_string(),
        backend_with_strategy(PropagationStrategyKind::Passthrough),
    );
    assert!(super::super::config_installs_minting_strategy(&minting));
}

// ── GW.3 (MIK-6784): the single_user startup warning must name exactly the
// backends that hold a non-shared gateway OAuth token, and stay silent
// otherwise. `leaky_single_user_backends` is the pure predicate the warning
// branch consumes. ──
fn backend_with_oauth(enabled: bool, shared: bool) -> BackendConfig {
    BackendConfig {
        oauth: Some(crate::config::OAuthConfig {
            enabled,
            scopes: vec![],
            client_id: None,
            client_secret: None,
            callback_host: None,
            callback_port: None,
            callback_path: None,
            token_refresh_buffer_secs: 300,
            shared_account: shared,
        }),
        ..BackendConfig::default()
    }
}

#[test]
fn leaky_backends_empty_when_not_single_user() {
    let mut config = Config::default();
    config.auth.single_user = false;
    config
        .backends
        .insert("leaky".to_string(), backend_with_oauth(true, false));
    assert!(
        super::super::leaky_single_user_backends(&config).is_empty(),
        "no warning target unless single_user is asserted"
    );
}

#[test]
fn leaky_backends_names_only_non_shared_oauth_under_single_user() {
    let mut config = Config::default();
    config.auth.single_user = true;
    config
        .backends
        .insert("leaky".to_string(), backend_with_oauth(true, false));
    config
        .backends
        .insert("shared".to_string(), backend_with_oauth(true, true));
    config
        .backends
        .insert("disabled".to_string(), backend_with_oauth(false, false));
    config
        .backends
        .insert("no_oauth".to_string(), BackendConfig::default());

    let leaky = super::super::leaky_single_user_backends(&config);
    assert_eq!(
        leaky,
        vec!["leaky"],
        "only the enabled, non-shared gateway-OAuth backend leaks under single_user"
    );
}

#[test]
fn leaky_backends_silent_when_all_oauth_is_shared() {
    let mut config = Config::default();
    config.auth.single_user = true;
    config
        .backends
        .insert("shared".to_string(), backend_with_oauth(true, true));
    assert!(
        super::super::leaky_single_user_backends(&config).is_empty(),
        "shared_account=true opts out of the leak warning"
    );
}

#[test]
fn unimplemented_minting_strategies_install_no_strategy() {
    // A backend configured for an as-yet-unimplemented minting strategy must
    // NOT trigger any install: doing so would mint the wrong credential shape
    // for a backend the operator asked to reach via a different trust model
    // (silent substitution, INV-4). Only wired minting kinds install (R2-3,
    // MIK-6746). `Vault` (MIK-6730) is not wired yet.
    use crate::identity_propagation::PropagationStrategyKind;
    let mut config = Config::default();
    config.backends.insert(
        "mint".to_string(),
        backend_with_strategy(PropagationStrategyKind::Vault),
    );
    assert!(
        !super::super::config_installs_minting_strategy(&config),
        "Vault must not install a minting strategy until it is wired"
    );
    assert_eq!(
        super::super::configured_minting_strategy_kind(&config),
        None
    );
}

// S1 (MIK-6729): the install path selects the strategy by configured kind.
// These assert the kind-selection helper that the install-site `match` keys
// off, closing the gap that let token-exchange ship unwired: the earlier
// helper allow-listed SignedAssertion only, so a token_exchange backend
// installed nothing and fell through to a static credential.
#[test]
fn configured_kind_is_token_exchange_for_a_token_exchange_backend() {
    use crate::identity_propagation::PropagationStrategyKind;
    let mut config = Config::default();
    config.backends.insert(
        "mail".to_string(),
        backend_with_strategy(PropagationStrategyKind::TokenExchange),
    );
    assert_eq!(
        super::super::configured_minting_strategy_kind(&config),
        Some(PropagationStrategyKind::TokenExchange)
    );
    assert!(super::super::config_installs_minting_strategy(&config));
}

#[test]
fn configured_kind_is_signed_assertion_for_a_signed_assertion_backend() {
    use crate::identity_propagation::PropagationStrategyKind;
    let mut config = Config::default();
    config.backends.insert(
        "sign".to_string(),
        backend_with_strategy(PropagationStrategyKind::SignedAssertion),
    );
    assert_eq!(
        super::super::configured_minting_strategy_kind(&config),
        Some(PropagationStrategyKind::SignedAssertion)
    );
}

#[test]
fn configured_kind_is_none_for_passthrough_only_and_no_idp() {
    use crate::identity_propagation::PropagationStrategyKind;
    // Passthrough-only: mints nothing, installs nothing.
    let mut passthrough = Config::default();
    passthrough.backends.insert(
        "pass".to_string(),
        backend_with_strategy(PropagationStrategyKind::Passthrough),
    );
    assert_eq!(
        super::super::configured_minting_strategy_kind(&passthrough),
        None,
        "passthrough-only must not select a minting kind"
    );
    // No identity_propagation configured at all.
    assert_eq!(
        super::super::configured_minting_strategy_kind(&Config::default()),
        None,
        "a no-idp config must not select a minting kind"
    );
}

#[test]
fn no_propagation_backend_installs_no_strategy() {
    assert!(!super::super::config_installs_minting_strategy(
        &Config::default()
    ));
}
