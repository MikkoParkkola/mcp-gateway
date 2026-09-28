// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Multi-gateway Ed25519 signature chain (OWASP ASI07).
//!
//! A result that passes through several gateways carries one signed link per
//! hop in `_meta["io.mcp-gateway/signature-chain"]`, oldest first. This module
//! holds the pure parts: the v1 link schema, its canonical form, signing, and
//! verification against the shared trusted-publisher keys with per-backend
//! pinning of the origin gateway and the last signer. Wiring into the invoke
//! paths lives with the callers.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::remote_provenance::TrustedRemoteServerKeyConfig;
use crate::Result;

/// Upstream verification state recorded by a link's signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Upstream {
    /// Origin link: nothing upstream.
    None,
    /// The signer verified the incoming chain.
    Verified,
    /// The signer stripped an incoming chain that failed verification.
    Unverified,
}

/// Whether a link was minted for a live backend call or a stored replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum LinkSource {
    /// Fresh backend call.
    Live,
    /// Idempotency replay or task recovery of a stored result.
    Replay,
}

/// One v1 chain link. Every key is required on the wire; absent values are
/// explicit `null`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChainLink {
    pub(crate) v: u8,
    pub(crate) alg: String,
    pub(crate) domain: String,
    pub(crate) gw: String,
    pub(crate) up: Upstream,
    pub(crate) src: LinkSource,
    #[serde(rename = "in", deserialize_with = "Option::deserialize")]
    pub(crate) input: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub(crate) out: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub(crate) prev: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub(crate) nonce: Option<String>,
    pub(crate) ts: u64,
    pub(crate) sig: String,
}

/// The signer-chosen fields of a link; the rest are fixed by v1.
#[derive(Debug, Clone)]
pub(crate) struct LinkFields {
    pub(crate) up: Upstream,
    pub(crate) src: LinkSource,
    pub(crate) input: Option<String>,
    pub(crate) out: Option<String>,
    pub(crate) prev: Option<String>,
    pub(crate) nonce: Option<String>,
    pub(crate) ts: u64,
}

/// Why a chain was refused. Names the rule, never the data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChainRefusal {
    Size,
    Schema,
    UntrustedSigner,
    BadSignature,
    Unverified,
    Origin,
    Commitment,
    Linkage,
    LastSigner,
    Content,
    Nonce,
    Stale,
    Future,
    Unhashable,
}

/// Per-backend verification policy.
pub(crate) struct ChainPolicy<'a> {
    /// The shared `remote_server_signing.trusted_keys` map.
    pub(crate) trusted_keys: &'a BTreeMap<String, TrustedRemoteServerKeyConfig>,
    /// `backends.<n>.chain_origins`.
    pub(crate) origins: &'a [String],
    /// `backends.<n>.chain_signer`.
    pub(crate) signer: &'a str,
    /// `message_signing.replay_window`, seconds.
    pub(crate) replay_window: u64,
    /// `security.signature_chain.max_links`; incoming chains hold at most one less.
    pub(crate) max_links: usize,
}

/// This gateway's persistent Ed25519 chain identity.
pub(crate) struct ChainSigner {
    key_id: String,
}

impl ChainSigner {
    pub(crate) fn from_seed(_seed: &[u8], key_id: &str) -> Result<Self> {
        Ok(Self {
            key_id: key_id.to_owned(),
        })
    }

    pub(crate) fn sign(&self, fields: LinkFields) -> ChainLink {
        ChainLink {
            v: 0,
            alg: String::new(),
            domain: String::new(),
            gw: self.key_id.clone(),
            up: fields.up,
            src: fields.src,
            input: fields.input,
            out: fields.out,
            prev: fields.prev,
            nonce: fields.nonce,
            ts: fields.ts,
            sig: String::new(),
        }
    }
}

/// `HL(link)`: SHA-256 hex of RFC 8785 of the whole link, `sig` included.
pub(crate) fn link_hash(_link: &ChainLink) -> String {
    String::new()
}

/// `H(result)`: SHA-256 hex of RFC 8785 of the result minus top-level `_meta`
/// and `_signature`.
pub(crate) fn content_digest(_result: &Value) -> std::result::Result<String, ChainRefusal> {
    Ok(String::new())
}

/// Verify an incoming chain (design checks 1-7, in order).
pub(crate) fn verify_chain(
    _chain: &Value,
    _policy: &ChainPolicy<'_>,
    _received: &str,
    _nonce: &str,
    _now: u64,
) -> std::result::Result<Vec<ChainLink>, ChainRefusal> {
    Ok(Vec::new())
}

#[cfg(test)]
#[path = "signature_chain_tests.rs"]
mod tests;
