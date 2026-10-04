// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `security.signature_chain` validation and reload rules (ASI07 inc 2).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use super::{ChainEmit, SignatureChainConfig};
use crate::config::EnvOverlay;

fn config(signing_key: &str, key_id: &str) -> SignatureChainConfig {
    SignatureChainConfig {
        signing_key: signing_key.to_owned(),
        key_id: key_id.to_owned(),
        emit: ChainEmit::OnRequest,
        max_links: 8,
        resolved_identity: None,
    }
}

fn seed(len: usize) -> String {
    STANDARD.encode(vec![9u8; len])
}

#[test]
fn signature_chain_config_rejects_bad_seed() {
    for bad in [seed(31), seed(33), "not base64 !!".to_owned()] {
        let error = config(&bad, "gw-a").resolve_with_env(&EnvOverlay::none());
        assert!(
            matches!(error, Err(crate::Error::ConfigValidation(_))),
            "seed {bad:?}: {error:?}"
        );
    }
}

#[test]
fn signature_chain_config_rejects_bad_key_id() {
    for bad in [String::new(), "k".repeat(65)] {
        let error = config(&seed(32), &bad).resolve_with_env(&EnvOverlay::none());
        assert!(
            matches!(error, Err(crate::Error::ConfigValidation(_))),
            "key_id len {}: {error:?}",
            bad.len()
        );
    }
}

#[test]
fn signature_chain_config_rejects_unresolvable_env_ref() {
    let error =
        config("env:ASI07_CHAIN_KEY_NEVER_SET", "gw-a").resolve_with_env(&EnvOverlay::none());
    let Err(crate::Error::ConfigValidation(message)) = error else {
        panic!("expected ConfigValidation, got {error:?}");
    };
    assert!(
        message.starts_with("security.signature_chain.signing_key"),
        "{message}"
    );
}

#[test]
fn signature_chain_reload_refused() {
    let running = config(&seed(32), "gw-a");
    let mut other_key = running.clone();
    other_key.signing_key = seed(32).replace('C', "D");
    let mut other_id = running.clone();
    other_id.key_id = "gw-b".to_owned();
    let mut other_emit = running.clone();
    other_emit.emit = ChainEmit::Always;
    for (reloaded, field) in [
        (&other_key, "signing_key"),
        (&other_id, "key_id"),
        (&other_emit, "emit"),
    ] {
        assert_eq!(
            SignatureChainConfig::restart_changed_field(Some(&running), Some(reloaded)),
            Some(field)
        );
    }
    assert_eq!(
        SignatureChainConfig::restart_changed_field(Some(&running), Some(&running)),
        None
    );
}

/// C1 (inc3 D1): a gateway with one backend under `mode`, `origins` and
/// `signer`, the upstream key `gw-u` trusted, and its own chain identity.
fn chained_gateway(
    mode: super::ChainMode,
    origins: &[&str],
    signer: Option<&str>,
) -> crate::config::Config {
    use crate::security::remote_provenance::{
        RemoteServerSignatureAlgorithm, TrustedRemoteServerKeyConfig,
    };
    let mut gateway = crate::config::Config::default();
    gateway.security.signature_chain = Some(config(&seed(32), "gw-d"));
    gateway.security.remote_server_signing.trusted_keys.insert(
        "gw-u".to_owned(),
        TrustedRemoteServerKeyConfig {
            algorithm: RemoteServerSignatureAlgorithm::Ed25519,
            public_key: seed(32),
        },
    );
    let backend = crate::config::BackendConfig {
        transport: crate::config::TransportConfig::Http {
            http_url: "http://127.0.0.1:9/mcp".to_owned(),
            streamable_http: true,
            protocol_version: None,
        },
        signature_chain: mode,
        chain_origins: origins.iter().map(|o| (*o).to_owned()).collect(),
        chain_signer: signer.map(str::to_owned),
        ..crate::config::BackendConfig::default()
    };
    gateway.backends.insert("upstream".to_owned(), backend);
    gateway
}

fn chain_refusal(config: &crate::config::Config) -> Option<String> {
    match config.validate_with_env(&EnvOverlay::none()) {
        Err(crate::Error::ConfigValidation(message)) => Some(message),
        _ => None,
    }
}

#[test]
fn chain_backend_config_validation() {
    use super::ChainMode::{Off, Require, Verify};
    let valid = chained_gateway(Verify, &["gw-u"], Some("gw-u"));
    assert_eq!(
        chain_refusal(&valid),
        None,
        "a complete verify config loads"
    );
    assert_eq!(crate::config::BackendConfig::default().signature_chain, Off);
    assert_eq!(chain_refusal(&chained_gateway(Off, &[], None)), None);
    for (config, field) in [
        (chained_gateway(Require, &[], Some("gw-u")), "chain_origins"),
        (chained_gateway(Verify, &["gw-u"], None), "chain_signer"),
        (
            chained_gateway(Verify, &["gw-missing"], Some("gw-u")),
            "chain_origins",
        ),
        (
            chained_gateway(Verify, &["gw-u"], Some("gw-missing")),
            "chain_signer",
        ),
    ] {
        let message = chain_refusal(&config).unwrap_or_else(|| panic!("{field} must refuse"));
        assert!(
            message.contains(&format!("backends.upstream.{field}")),
            "{message}"
        );
    }
    let mut no_identity = chained_gateway(Verify, &["gw-u"], Some("gw-u"));
    no_identity.security.signature_chain = None;
    let message = chain_refusal(&no_identity).expect("no own identity must refuse");
    assert!(message.contains("security.signature_chain"), "{message}");
}
