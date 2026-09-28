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

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::message_signing::has_interoperable_numbers;
use super::remote_provenance::{RemoteServerSignatureAlgorithm, TrustedRemoteServerKeyConfig};
use crate::hashing::sha256_hex;
use crate::{Error, Result};

const VERSION: u8 = 1;
const ALG: &str = "ed25519";
/// Signed domain tag: a link signature is never valid for another envelope.
const DOMAIN: &str = "mcp-gateway-chain-v1";
const MAX_GW_BYTES: usize = 64;
const MAX_NONCE_BYTES: usize = 256;
const MAX_LINK_BYTES: usize = 1024;
const MAX_CHAIN_BYTES: usize = 16 * 1024;
const MAX_FUTURE_SKEW_SECS: u64 = 60;

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
    key_pair: Ed25519KeyPair,
    key_id: String,
}

impl ChainSigner {
    /// Build the signer from a 32-byte Ed25519 seed and its 1..64-byte key id.
    pub(crate) fn from_seed(seed: &[u8], key_id: &str) -> Result<Self> {
        if !(1..=MAX_GW_BYTES).contains(&key_id.len()) {
            return Err(Error::ConfigValidation(
                "signature_chain key_id must be 1..64 bytes".to_owned(),
            ));
        }
        let key_pair = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| {
            Error::ConfigValidation("signature_chain signing_key must be a 32-byte seed".to_owned())
        })?;
        Ok(Self {
            key_pair,
            key_id: key_id.to_owned(),
        })
    }

    /// Sign one link. The caller supplies the hop-specific fields.
    pub(crate) fn sign(&self, fields: LinkFields) -> ChainLink {
        let mut link = ChainLink {
            v: VERSION,
            alg: ALG.to_owned(),
            domain: DOMAIN.to_owned(),
            gw: self.key_id.clone(),
            up: fields.up,
            src: fields.src,
            input: fields.input,
            out: fields.out,
            prev: fields.prev,
            nonce: fields.nonce,
            ts: fields.ts,
            sig: String::new(),
        };
        let signature = self.key_pair.sign(&signing_input(&link));
        link.sig = STANDARD.encode(signature.as_ref());
        link
    }
}

/// RFC 8785 of a link. `with_sig` false gives the signing input.
fn canonical_link(link: &ChainLink, with_sig: bool) -> Vec<u8> {
    let mut value = serde_json::to_value(link).unwrap_or(Value::Null);
    if !with_sig && let Some(members) = value.as_object_mut() {
        members.remove("sig");
    }
    // A link holds only strings, small integers and nulls, so JCS cannot fail.
    serde_json_canonicalizer::to_vec(&value).unwrap_or_default()
}

fn signing_input(link: &ChainLink) -> Vec<u8> {
    canonical_link(link, false)
}

/// `HL(link)`: SHA-256 hex of RFC 8785 of the whole link, `sig` included.
pub(crate) fn link_hash(link: &ChainLink) -> String {
    sha256_hex(&canonical_link(link, true))
}

/// `H(result)`: SHA-256 hex of RFC 8785 of the result minus top-level `_meta`
/// and `_signature`. Content outside the v2 interoperable-number range is
/// unhashable, because two distinct integers could share one canonical form.
pub(crate) fn content_digest(result: &Value) -> std::result::Result<String, ChainRefusal> {
    let members = result.as_object().ok_or(ChainRefusal::Unhashable)?;
    let content: BTreeMap<&str, &Value> = members
        .iter()
        .filter(|(key, _)| !matches!(key.as_str(), "_meta" | "_signature"))
        .map(|(key, value)| (key.as_str(), value))
        .collect();
    if !content
        .values()
        .all(|value| has_interoperable_numbers(value))
    {
        return Err(ChainRefusal::Unhashable);
    }
    let bytes = serde_json_canonicalizer::to_vec(&content).map_err(|_| ChainRefusal::Unhashable)?;
    Ok(sha256_hex(&bytes))
}

/// Counts serialized bytes and stops at the cap, so an oversized chain is
/// never copied into a second buffer just to be measured.
struct CappedSink {
    len: usize,
    cap: usize,
}

impl std::io::Write for CappedSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.len += bytes.len();
        if self.len > self.cap {
            return Err(std::io::ErrorKind::FileTooLarge.into());
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn exceeds(value: &Value, cap: usize) -> bool {
    serde_json::to_writer(&mut CappedSink { len: 0, cap }, value).is_err()
}

fn is_digest(value: Option<&String>) -> bool {
    value.is_none_or(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn schema_ok(link: &ChainLink) -> bool {
    link.v == VERSION
        && link.alg == ALG
        && link.domain == DOMAIN
        && (1..=MAX_GW_BYTES).contains(&link.gw.len())
        && link
            .nonce
            .as_ref()
            .is_none_or(|nonce| (1..=MAX_NONCE_BYTES).contains(&nonce.len()))
        && is_digest(link.input.as_ref())
        && is_digest(link.out.as_ref())
        && is_digest(link.prev.as_ref())
}

fn signature_ok(link: &ChainLink, key: &TrustedRemoteServerKeyConfig) -> bool {
    let RemoteServerSignatureAlgorithm::Ed25519 = key.algorithm;
    let (Ok(public_key), Ok(sig)) = (STANDARD.decode(&key.public_key), STANDARD.decode(&link.sig))
    else {
        return false;
    };
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&signing_input(link), &sig)
        .is_ok()
}

/// Verify an incoming chain against design checks 1-7, in order. Each check
/// refuses with its own [`ChainRefusal`]; the returned links are the verified
/// upstream evidence.
pub(crate) fn verify_chain(
    chain: &Value,
    policy: &ChainPolicy<'_>,
    received: &str,
    nonce: &str,
    now: u64,
) -> std::result::Result<Vec<ChainLink>, ChainRefusal> {
    // 1. Size caps before anything is parsed or verified, then schema.
    if exceeds(chain, MAX_CHAIN_BYTES) {
        return Err(ChainRefusal::Size);
    }
    let items = chain.as_array().ok_or(ChainRefusal::Schema)?;
    if items.len() >= policy.max_links {
        return Err(ChainRefusal::Size);
    }
    if items.iter().any(|item| exceeds(item, MAX_LINK_BYTES)) {
        return Err(ChainRefusal::Size);
    }
    let links = items
        .iter()
        .map(|item| ChainLink::deserialize(item).map_err(|_| ChainRefusal::Schema))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if links.is_empty() || !links.iter().all(schema_ok) {
        return Err(ChainRefusal::Schema);
    }

    // 2. Every signer is trusted and every signature verifies.
    for link in &links {
        let key = policy
            .trusted_keys
            .get(&link.gw)
            .ok_or(ChainRefusal::UntrustedSigner)?;
        if !signature_ok(link, key) {
            return Err(ChainRefusal::BadSignature);
        }
    }

    // 3. No hop admitted an unverified upstream.
    if links.iter().any(|link| link.up == Upstream::Unverified) {
        return Err(ChainRefusal::Unverified);
    }

    // 4. Every link commits to its output; the origin is pinned and starts clean.
    if links.iter().any(|link| link.out.is_none()) {
        return Err(ChainRefusal::Commitment);
    }
    let origin = &links[0];
    if origin.prev.is_some()
        || origin.input.is_some()
        || origin.up != Upstream::None
        || !policy.origins.contains(&origin.gw)
    {
        return Err(ChainRefusal::Origin);
    }

    // 5. Each later link hashes its predecessor and consumed its output.
    for pair in links.windows(2) {
        let (before, link) = (&pair[0], &pair[1]);
        if link.prev.as_deref() != Some(link_hash(before).as_str())
            || link.input.is_none()
            || link.input != before.out
            || link.up != Upstream::Verified
        {
            return Err(ChainRefusal::Linkage);
        }
    }

    // 6. The last link is the pinned signer, commits to what arrived, answers
    //    this request's nonce, and is fresh.
    let last = &links[links.len() - 1];
    if last.gw != policy.signer {
        return Err(ChainRefusal::LastSigner);
    }
    if last.out.as_deref() != Some(received) {
        return Err(ChainRefusal::Content);
    }
    if last.nonce.as_deref() != Some(nonce) {
        return Err(ChainRefusal::Nonce);
    }
    if now.saturating_sub(last.ts) > policy.replay_window {
        return Err(ChainRefusal::Stale);
    }

    // 7. No link from the future. Hop clocks differ, so there is no ordering
    //    between links; ancestors are fresh through `prev` to the last link.
    if links
        .iter()
        .any(|link| link.ts > now.saturating_add(MAX_FUTURE_SKEW_SECS))
    {
        return Err(ChainRefusal::Future);
    }
    if links.windows(2).any(|p| p[0].ts > p[1].ts) {
        return Err(ChainRefusal::Future);
    }
    Ok(links)
}

#[cfg(test)]
#[path = "signature_chain_tests.rs"]
mod tests;
