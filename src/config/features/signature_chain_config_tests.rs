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
