// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shared fixtures for the ASI07 origin-emission tests: one self signer and a
//! verifier that trusts exactly that signer.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use serde_json::Value;

use crate::security::remote_provenance::{
    RemoteServerSignatureAlgorithm, TrustedRemoteServerKeyConfig,
};
use crate::security::signature_chain::{
    ChainLink, ChainPolicy, ChainPurpose, ChainSigner, LinkSource, Upstream, verify_chain,
};

/// `_meta` key that carries the chain on a result.
pub(crate) const CHAIN_KEY: &str = "io.mcp-gateway/signature-chain";
/// `params._meta` key that carries the caller's chain nonce.
pub(crate) const NONCE_KEY: &str = "io.mcp-gateway/chain-nonce";
/// The gateway's own chain identity in tests.
pub(crate) const KEY_ID: &str = "gw-self";
const SEED: [u8; 32] = [7; 32];

/// The signer every test installs.
pub(crate) fn signer() -> ChainSigner {
    ChainSigner::from_seed(&SEED, KEY_ID).expect("test seed is 32 bytes")
}

/// The chain value on a result, if any.
pub(crate) fn chain_of(result: &Value) -> Option<&Value> {
    result.get("_meta")?.get(CHAIN_KEY)
}

/// True when the chain key is present anywhere a client could read it.
pub(crate) fn carries_chain(result: &Value) -> bool {
    chain_of(result).is_some() || result.to_string().contains(CHAIN_KEY)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

/// The key set that trusts exactly the signer every test installs.
pub(crate) fn trusted_self() -> BTreeMap<String, TrustedRemoteServerKeyConfig> {
    let pair = Ed25519KeyPair::from_seed_unchecked(&SEED).expect("seed");
    BTreeMap::from([(
        KEY_ID.to_owned(),
        TrustedRemoteServerKeyConfig {
            algorithm: RemoteServerSignatureAlgorithm::Ed25519,
            public_key: STANDARD.encode(pair.public_key().as_ref()),
        },
    )])
}

/// Verify `chain` as a one-link origin chain from this gateway to itself.
/// `received` is the digest of the result the link covers.
pub(crate) fn verify_self(
    chain: &Value,
    received: &str,
    nonce: &str,
) -> Result<Vec<ChainLink>, crate::security::signature_chain::ChainRefusal> {
    let trusted = trusted_self();
    let origins = [KEY_ID.to_owned()];
    let policy = ChainPolicy {
        trusted_keys: &trusted,
        origins: &origins,
        signer: KEY_ID,
        replay_window: 300,
        max_links: 8,
        purpose: ChainPurpose::Terminal,
    };
    verify_chain(chain, &policy, received, nonce, now())
}

/// Assert the shape of an origin link and return it.
pub(crate) fn origin_link(chain: &Value, src: LinkSource, nonce: Option<&str>) -> ChainLink {
    let links: Vec<ChainLink> =
        serde_json::from_value(chain.clone()).expect("chain is a link array");
    assert_eq!(links.len(), 1, "exactly one origin link");
    let link = links.into_iter().next().expect("one link");
    assert_eq!(link.up, Upstream::None);
    assert_eq!(link.src, src);
    assert_eq!(link.prev, None);
    assert_eq!(link.input, None);
    assert_eq!(link.gw, KEY_ID);
    assert_eq!(link.nonce.as_deref(), nonce);
    link
}
