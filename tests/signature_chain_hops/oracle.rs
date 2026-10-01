// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The client's verifier, written independently of the gateway's own
//! `verify_chain`. It uses `ring` Ed25519, RFC 8785 and SHA-256 from their
//! crates, and none of the gateway's signing, hashing or policy code, so "the
//! client can verify the full chain" is shown by code that does not share the
//! implementation under test.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

pub const CHAIN_KEY: &str = "io.mcp-gateway/signature-chain";

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn jcs(value: &Value) -> Vec<u8> {
    serde_json_canonicalizer::to_vec(value).expect("canonical JSON")
}

/// `H(result)`: the result minus top-level `_meta` and `_signature`.
pub fn content_digest(result: &Value) -> String {
    let mut members = result.as_object().expect("object result").clone();
    members.remove("_meta");
    members.remove("_signature");
    sha256_hex(&jcs(&Value::Object(members)))
}

/// `HL(link)`: the whole link, `sig` included.
pub fn link_hash(link: &Value) -> String {
    sha256_hex(&jcs(link))
}

/// The base64 Ed25519 public key for a 32-byte test seed.
pub fn public_key(seed: [u8; 32]) -> String {
    let pair = Ed25519KeyPair::from_seed_unchecked(&seed).expect("seed");
    STANDARD.encode(pair.public_key().as_ref())
}

/// Sign `link` (all fields but `sig`) with `seed`, the way any v1 signer must.
pub fn sign(mut link: Value, seed: [u8; 32]) -> Value {
    let pair = Ed25519KeyPair::from_seed_unchecked(&seed).expect("seed");
    link.as_object_mut().expect("link").remove("sig");
    let signature = pair.sign(&jcs(&link));
    link["sig"] = Value::String(STANDARD.encode(signature.as_ref()));
    link
}

/// What the client trusts: key ids to public keys, the origins it accepts and
/// the gateway it called.
pub struct Trust<'a> {
    pub keys: &'a BTreeMap<String, String>,
    pub origins: &'a [&'a str],
    pub signer: &'a str,
}

/// Verify the chain on a delivered `result` for the client's `nonce`. `Err`
/// names the first rule that failed.
pub fn verify(result: &Value, trust: &Trust<'_>, nonce: &str) -> Result<Vec<Value>, &'static str> {
    let links = result
        .get("_meta")
        .and_then(|meta| meta.get(CHAIN_KEY))
        .and_then(Value::as_array)
        .ok_or("absent")?
        .clone();
    if links.is_empty() {
        return Err("empty");
    }
    for link in &links {
        let gw = link["gw"].as_str().ok_or("schema")?;
        let key = trust.keys.get(gw).ok_or("untrusted")?;
        let key = STANDARD.decode(key).map_err(|_| "key")?;
        let sig = STANDARD
            .decode(link["sig"].as_str().ok_or("schema")?)
            .map_err(|_| "signature")?;
        let mut unsigned = link.clone();
        unsigned.as_object_mut().ok_or("schema")?.remove("sig");
        UnparsedPublicKey::new(&ED25519, key)
            .verify(&jcs(&unsigned), &sig)
            .map_err(|_| "signature")?;
        if link["up"] == "unverified" {
            return Err("unverified");
        }
    }
    let origin = &links[0];
    if !origin["prev"].is_null()
        || !origin["in"].is_null()
        || origin["up"] != "none"
        || !trust
            .origins
            .contains(&origin["gw"].as_str().unwrap_or_default())
    {
        return Err("origin");
    }
    for pair in links.windows(2) {
        if pair[1]["prev"].as_str() != Some(link_hash(&pair[0]).as_str())
            || pair[1]["in"] != pair[0]["out"]
            || pair[1]["up"] != "verified"
        {
            return Err("linkage");
        }
    }
    let last = &links[links.len() - 1];
    if last["gw"] != trust.signer {
        return Err("last signer");
    }
    if last["out"].as_str() != Some(content_digest(result).as_str()) {
        return Err("content");
    }
    if last["nonce"].as_str() != Some(nonce) {
        return Err("nonce");
    }
    Ok(links)
}
