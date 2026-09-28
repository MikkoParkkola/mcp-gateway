// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tests for the pure signature-chain module (ASI07 design section 6).

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use serde_json::{Value, json};

use super::*;
use crate::security::remote_provenance::{
    RemoteServerSignatureAlgorithm, TrustedRemoteServerKeyConfig,
};

const NOW: u64 = 1_750_000_000;
const WINDOW: u64 = 300;
const NONCE: &str = "caller-nonce-1";

/// Test gateways: (`key_id`, seed byte). `gw-x` is trusted but pinned nowhere;
/// `gw-u` is not trusted at all.
const A: (&str, u8) = ("gw-a", 1);
const B: (&str, u8) = ("gw-b", 2);
const C: (&str, u8) = ("gw-c", 3);
const X: (&str, u8) = ("gw-x", 9);
const U: (&str, u8) = ("gw-u", 8);

fn public_key_b64(seed: u8) -> String {
    let pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).expect("seed");
    STANDARD.encode(pair.public_key().as_ref())
}

fn trusted() -> BTreeMap<String, TrustedRemoteServerKeyConfig> {
    [A, B, C, X]
        .iter()
        .map(|(id, seed)| {
            (
                (*id).to_owned(),
                TrustedRemoteServerKeyConfig {
                    algorithm: RemoteServerSignatureAlgorithm::Ed25519,
                    public_key: public_key_b64(*seed),
                },
            )
        })
        .collect()
}

fn result() -> Value {
    json!({"content": [{"type": "text", "text": "hello"}], "isError": false})
}

fn received() -> String {
    content_digest(&result()).expect("digest")
}

fn digest(i: usize) -> String {
    format!("{:064x}", i + 1)
}

/// Sign hops in order. Each link's `prev`/`in` are derived from the
/// already-signed predecessor, then `edit` may override any field before
/// signing, so a mutated ancestor still yields validly re-signed descendants.
fn build(hops: &[(&str, u8)], edit: impl Fn(usize, &mut LinkFields)) -> Vec<ChainLink> {
    let mut links: Vec<ChainLink> = Vec::new();
    let last = hops.len() - 1;
    for (i, (gw, seed)) in hops.iter().enumerate() {
        let before = links.last();
        let mut fields = LinkFields {
            up: if i == 0 {
                Upstream::None
            } else {
                Upstream::Verified
            },
            src: LinkSource::Live,
            input: before.and_then(|p| p.out.clone()),
            out: Some(if i == last { received() } else { digest(i) }),
            prev: before.map(link_hash),
            nonce: Some(if i == last {
                NONCE.to_owned()
            } else {
                format!("n{i}")
            }),
            ts: NOW,
        };
        edit(i, &mut fields);
        let signer = ChainSigner::from_seed(&[*seed; 32], gw).expect("signer");
        links.push(signer.sign(fields));
    }
    links
}

fn abc() -> Vec<ChainLink> {
    build(&[A, B, C], |_, _| {})
}

fn wire(links: &[ChainLink]) -> Value {
    serde_json::to_value(links).expect("serialize")
}

fn verify_with(
    chain: &Value,
    max_links: usize,
) -> std::result::Result<Vec<ChainLink>, ChainRefusal> {
    let keys = trusted();
    let origins = vec![A.0.to_owned()];
    let policy = ChainPolicy {
        trusted_keys: &keys,
        origins: &origins,
        signer: C.0,
        replay_window: WINDOW,
        max_links,
    };
    verify_chain(chain, &policy, &received(), NONCE, NOW)
}

fn verify(chain: &Value) -> std::result::Result<Vec<ChainLink>, ChainRefusal> {
    verify_with(chain, 8)
}

fn gws(links: &[ChainLink]) -> Vec<&str> {
    links.iter().map(|l| l.gw.as_str()).collect()
}

fn assert_accepts(chain: &Value) {
    let links = verify(chain).expect("chain must verify");
    assert_eq!(
        gws(&links),
        gws(&serde_json::from_value::<Vec<ChainLink>>(chain.clone()).expect("links"))
    );
    assert!(!links.is_empty());
}

// ── Row 1 (pure part) ───────────────────────────────────────────────────────

#[test]
fn valid_three_link_chain_verifies() {
    let links = verify(&wire(&abc())).expect("valid chain");
    assert_eq!(gws(&links), ["gw-a", "gw-b", "gw-c"]);
    assert_eq!(links, abc());
}

// ── Rows 2-6 ────────────────────────────────────────────────────────────────

#[test]
fn tampered_content_fails_out_digest() {
    // Last link commits to a different result than the one received.
    let chain = build(&[A, B, C], |i, f| {
        if i == 2 {
            f.out = Some(digest(99));
        }
    });
    assert_eq!(verify(&wire(&chain)), Err(ChainRefusal::Content));
}

#[test]
fn truncated_chain_fails_prev() {
    // Removing B: C's `prev` no longer matches HL(A). Keep `in` consistent so
    // only the `prev` rule can refuse.
    let mut chain = abc();
    let a = chain[0].clone();
    let c = build(&[A, B, C], |i, f| {
        if i == 2 {
            f.input = a.out.clone();
        }
    })
    .remove(2);
    chain = vec![a, c];
    assert_eq!(verify(&wire(&chain)), Err(ChainRefusal::Linkage));
}

#[test]
fn in_mismatch_fails_linkage() {
    let chain = build(&[A, B, C], |i, f| {
        if i == 1 {
            f.input = Some(digest(42));
        }
    });
    assert_eq!(verify(&wire(&chain)), Err(ChainRefusal::Linkage));
}

#[test]
fn prev_mismatch_fails_linkage() {
    let chain = build(&[A, B, C], |i, f| {
        if i == 1 {
            f.prev = Some(digest(42));
        }
    });
    assert_eq!(verify(&wire(&chain)), Err(ChainRefusal::Linkage));
}

#[test]
fn origin_replacement_refused() {
    // gw-x is trusted but not a pinned origin; it drops A and re-signs as origin.
    let chain = build(&[X, B, C], |_, _| {});
    assert_eq!(verify(&wire(&chain)), Err(ChainRefusal::Origin));
}

#[test]
fn wrong_last_signer_refused() {
    let chain = build(&[A, B, X], |_, _| {});
    assert_eq!(verify(&wire(&chain)), Err(ChainRefusal::LastSigner));
}

#[test]
fn replayed_chain_refused_nonce() {
    let chain = build(&[A, B, C], |i, f| {
        if i == 2 {
            f.nonce = Some("old-nonce".to_owned());
        }
    });
    assert_eq!(verify(&wire(&chain)), Err(ChainRefusal::Nonce));
    let chain = build(&[A, B, C], |i, f| {
        if i == 2 {
            f.nonce = None;
        }
    });
    assert_eq!(verify(&wire(&chain)), Err(ChainRefusal::Nonce));
}

// ── Row 7: freshness ────────────────────────────────────────────────────────

fn with_ts(index: usize, ts: u64) -> Vec<ChainLink> {
    build(&[A, B, C], |i, f| {
        if i == index {
            f.ts = ts;
        }
    })
}

#[test]
fn stale_last_link_refused() {
    assert_eq!(
        verify(&wire(&with_ts(2, NOW - WINDOW - 1))),
        Err(ChainRefusal::Stale)
    );
    assert_accepts(&wire(&with_ts(2, NOW - WINDOW)));
}

#[test]
fn future_ts_refused() {
    for index in 0..3 {
        assert_eq!(
            verify(&wire(&with_ts(index, NOW + 61))),
            Err(ChainRefusal::Future),
            "link {index}"
        );
        assert_accepts(&wire(&with_ts(index, NOW + 60)));
    }
}

#[test]
fn clock_skewed_ancestor_accepted() {
    // Ancestor clock 5 s ahead of its successor: no cross-hop ordering.
    let chain = build(&[A, B, C], |i, f| {
        f.ts = if i == 0 { NOW + 5 } else { NOW };
    });
    assert_accepts(&wire(&chain));
    // Ancestor older than the replay window: freshness binds the last link only.
    assert_accepts(&wire(&with_ts(0, NOW - WINDOW * 10)));
    assert_accepts(&wire(&with_ts(1, NOW - WINDOW * 10)));
}

// ── Rows 8, 9: content digest ──────────────────────────────────────────────

#[test]
fn unsafe_integer_content_unhashable() {
    let max_exact: u64 = (1 << 53) - 1;
    assert!(content_digest(&json!({"n": max_exact})).is_ok());
    assert!(content_digest(&json!({"n": -9_007_199_254_740_991_i64})).is_ok());
    for bad in [
        json!({"n": 1_u64 << 53}),
        json!({"n": (1_u64 << 53) + 1}),
        json!({"n": -(1_i64 << 53)}),
        json!({"deep": {"list": [1, {"n": (1_u64 << 53) + 1}]}}),
        json!({"a": {"_meta": {"n": (1_u64 << 53) + 1}}}),
    ] {
        assert_eq!(content_digest(&bad), Err(ChainRefusal::Unhashable), "{bad}");
    }
    // An unsafe number inside the excluded top-level `_meta` does not matter.
    assert!(content_digest(&json!({"a": 1, "_meta": {"n": (1_u64 << 53) + 1}})).is_ok());
}

#[test]
fn non_object_result_unhashable() {
    for bad in [json!([1]), json!("x"), json!(null), json!(1)] {
        assert_eq!(content_digest(&bad), Err(ChainRefusal::Unhashable));
    }
}

#[test]
fn content_excludes_meta_and_signature() {
    let base = content_digest(&result()).expect("digest");
    let mut with = result();
    with["_meta"] = json!({"io.mcp-gateway/signature-chain": []});
    with["_signature"] = json!({"mac": "x"});
    assert_eq!(content_digest(&with).expect("digest"), base);
    // Nested members of the same names are ordinary payload.
    let mut nested = result();
    nested["content"][0]["_signature"] = json!("x");
    assert_ne!(content_digest(&nested).expect("digest"), base);
    let mut nested = result();
    nested["content"][0]["_meta"] = json!({});
    assert_ne!(content_digest(&nested).expect("digest"), base);
}

#[test]
fn content_digest_known_answer() {
    // Independent RFC 8785 vector: floats, and keys whose UTF-16 order
    // (U+1F600 before U+FF41) differs from code-point order.
    let value = json!({
        "\u{1F600}": 1, "\u{FF41}": 2,
        "a": [1.5, 0.1, -3, true, null], "b": {"z": "\u{e9}", "y": 2.0}
    });
    assert_eq!(
        content_digest(&value).expect("digest"),
        "bb83d27f2d43bf29a60bf6e9bedb5e1264374c00527ba041dab1853fff74f2ad"
    );
}

// ── Row 11 (pure part): check 3 ─────────────────────────────────────────────

#[test]
fn verifier_rejects_unverified() {
    for index in 0..3 {
        let chain = build(&[A, B, C], |i, f| {
            if i == index {
                f.up = Upstream::Unverified;
            }
        });
        assert_eq!(
            verify(&wire(&chain)),
            Err(ChainRefusal::Unverified),
            "link {index}"
        );
    }
}

// ── Row 13: bounds ──────────────────────────────────────────────────────────

fn hops(n: usize) -> Vec<(&'static str, u8)> {
    let mut hops = vec![A];
    hops.resize(n - 1, B);
    hops.push(C);
    hops
}

#[test]
fn outgoing_chain_within_max_links() {
    // Incoming at most max_links - 1, so this gateway's link keeps it <= max.
    assert_eq!(
        verify_with(&wire(&build(&hops(8), |_, _| {})), 8),
        Err(ChainRefusal::Size)
    );
    let links = verify_with(&wire(&build(&hops(7), |_, _| {})), 8).expect("7 links");
    assert_eq!(links.len(), 7);
}

#[test]
fn oversized_link_refused_before_verify() {
    // Extra member and broken signature: only a size check that runs first
    // can report `Size`.
    let mut chain = wire(&abc());
    chain[1]["pad"] = json!("x".repeat(1100));
    chain[1]["sig"] = json!("not base64");
    assert_eq!(verify(&chain), Err(ChainRefusal::Size));
}

#[test]
fn oversized_chain_refused_before_verify() {
    // Every link under 1 KiB and max_links raised, so only the 16 KiB
    // aggregate cap can refuse. Walk up to the limit from below.
    let mut refused = false;
    for n in 3..80 {
        let chain = wire(&build(&hops(n), |i, f| {
            if i > 0 && i + 1 < n {
                f.nonce = Some("n".repeat(200));
            }
        }));
        for link in chain.as_array().expect("array") {
            assert!(serde_json::to_vec(link).expect("json").len() <= 1024);
        }
        let total = serde_json::to_vec(&chain).expect("json").len();
        if total > 16 * 1024 {
            // A broken signature proves the cap runs before verification.
            let mut chain = chain;
            chain[1]["sig"] = json!(STANDARD.encode([0_u8; 64]));
            assert_eq!(verify_with(&chain, 100), Err(ChainRefusal::Size), "n={n}");
            refused = true;
            break;
        }
        assert_eq!(verify_with(&chain, 100).expect("under cap").len(), n);
    }
    assert!(refused);
}

// ── Row 16: known-answer vector ─────────────────────────────────────────────

fn kat_fields() -> LinkFields {
    LinkFields {
        up: Upstream::Verified,
        src: LinkSource::Live,
        input: Some("a".repeat(64)),
        out: Some("b".repeat(64)),
        prev: Some("c".repeat(64)),
        nonce: Some("n-1".to_owned()),
        ts: 1_750_000_000,
    }
}

#[test]
fn link_signature_known_answer() {
    // Independent vector: seed 00..1f, Ed25519 over the sorted-key compact
    // JSON of the link without `sig` (equal to RFC 8785 for these values).
    let seed: Vec<u8> = (0..32).collect();
    let link = ChainSigner::from_seed(&seed, "gw-kat")
        .expect("signer")
        .sign(kat_fields());
    assert_eq!(
        (link.v, link.alg.as_str(), link.domain.as_str()),
        (1, "ed25519", "mcp-gateway-chain-v1")
    );
    assert_eq!(
        link.sig,
        "WOWd6FmMhH4KT0GauNVxQNuGJ/v1iz7tO3css5vIp7JdtKPyfAr0jTcyF5UhPyQtydmj3BB4u3tom7n2kCdqCw=="
    );
    assert_eq!(
        link_hash(&link),
        "a9af4a84c8a5b3ec20ff1d0a2d2ae2c23902bf71650ccc36952d73502a5e2b6d"
    );
}

// ── Row 18: `prev` covers `sig`; every key required ────────────────────────

#[test]
fn prev_covers_sig() {
    let a = abc().remove(0);
    let mut resigned = a.clone();
    resigned.sig = STANDARD.encode([7_u8; 64]);
    assert_ne!(link_hash(&a), link_hash(&resigned));
    // A successor that committed to HL(link without sig) is refused.
    let mut unsigned = serde_json::to_value(&a).expect("json");
    unsigned.as_object_mut().expect("object").remove("sig");
    let bytes = serde_json_canonicalizer::to_vec(&unsigned).expect("jcs");
    let without_sig = crate::hashing::sha256_hex(&bytes);
    let chain = build(&[A, B, C], |i, f| {
        if i == 1 {
            f.prev = Some(without_sig.clone());
        }
    });
    assert_eq!(verify(&wire(&chain)), Err(ChainRefusal::Linkage));
}

const KEYS: [&str; 12] = [
    "v", "alg", "domain", "gw", "up", "src", "in", "out", "prev", "nonce", "ts", "sig",
];

fn with_member(index: usize, key: &str, value: Value) -> Value {
    let mut chain = wire(&abc());
    chain[index][key] = value;
    chain
}

#[test]
fn omitted_key_refused() {
    for key in KEYS {
        for index in 0..3 {
            let mut chain = wire(&abc());
            chain[index].as_object_mut().expect("object").remove(key);
            assert_eq!(
                verify(&chain),
                Err(ChainRefusal::Schema),
                "{key} on {index}"
            );
        }
    }
    for (key, value) in [
        ("extra", json!(1)),
        ("v", json!(2)),
        ("v", json!("1")),
        ("alg", json!("hmac-sha256")),
        ("domain", json!("mcp-gateway-response-v2")),
        ("up", json!("maybe")),
        ("src", json!("cached")),
        ("ts", json!(-1)),
        ("ts", json!("1")),
    ] {
        assert_eq!(
            verify(&with_member(1, key, value)),
            Err(ChainRefusal::Schema),
            "{key}"
        );
    }
    for bad in [json!({}), json!("x"), json!([1]), json!([])] {
        assert_eq!(verify(&bad), Err(ChainRefusal::Schema), "{bad}");
    }
}

#[test]
fn schema_bounds_refused() {
    let refused = [
        ("gw", json!("")),
        ("gw", json!("g".repeat(65))),
        ("nonce", json!("")),
        ("nonce", json!("n".repeat(257))),
    ];
    for (key, value) in refused {
        assert_eq!(
            verify(&with_member(1, key, value)),
            Err(ChainRefusal::Schema),
            "{key}"
        );
    }
    for key in ["in", "out", "prev"] {
        for value in [
            "A".repeat(64),
            "a".repeat(63),
            "g".repeat(64),
            "a".repeat(65),
        ] {
            assert_eq!(
                verify(&with_member(1, key, json!(value))),
                Err(ChainRefusal::Schema),
                "{key}={value}"
            );
        }
    }
    // Upper bounds are inclusive: 64 bytes of multibyte gw passes the schema
    // and fails on trust; a 256-byte nonce on a middle link verifies.
    assert_eq!(
        verify(&with_member(1, "gw", json!("\u{e9}".repeat(32)))),
        Err(ChainRefusal::UntrustedSigner)
    );
    let chain = build(&[A, B, C], |i, f| {
        if i == 1 {
            f.nonce = Some("n".repeat(256));
        }
    });
    assert_accepts(&wire(&chain));
}

// ── Row 19 (pure part): null commitments ────────────────────────────────────

fn edited(index: usize, edit: impl Fn(&mut LinkFields)) -> Value {
    wire(&build(&[A, B, C], |i, f| {
        if i == index {
            edit(f);
        }
    }))
}

#[test]
fn null_commitment_links_refused() {
    for index in 0..3 {
        assert_eq!(
            verify(&edited(index, |f| f.out = None)),
            Err(ChainRefusal::Commitment),
            "null out on {index}"
        );
    }
    for index in 1..3 {
        assert_eq!(
            verify(&edited(index, |f| f.input = None)),
            Err(ChainRefusal::Linkage)
        );
        assert_eq!(
            verify(&edited(index, |f| f.prev = None)),
            Err(ChainRefusal::Linkage)
        );
        assert_eq!(
            verify(&edited(index, |f| f.up = Upstream::None)),
            Err(ChainRefusal::Linkage)
        );
    }
}

#[test]
fn origin_link_shape_enforced() {
    assert_eq!(
        verify(&edited(0, |f| f.prev = Some(digest(5)))),
        Err(ChainRefusal::Origin)
    );
    assert_eq!(
        verify(&edited(0, |f| f.input = Some(digest(5)))),
        Err(ChainRefusal::Origin)
    );
    assert_eq!(
        verify(&edited(0, |f| f.up = Upstream::Verified)),
        Err(ChainRefusal::Origin)
    );
}

// ── Signatures and keys ─────────────────────────────────────────────────────

#[test]
fn untrusted_or_bad_signature_refused() {
    assert_eq!(
        verify(&wire(&build(&[A, U, C], |_, _| {}))),
        Err(ChainRefusal::UntrustedSigner)
    );
    let mut chain = wire(&abc());
    let mut sig = STANDARD
        .decode(chain[1]["sig"].as_str().expect("sig"))
        .expect("base64");
    sig[10] ^= 0x01;
    chain[1]["sig"] = json!(STANDARD.encode(&sig));
    assert_eq!(verify(&chain), Err(ChainRefusal::BadSignature));
    for bad in ["not base64", "AAAA"] {
        assert_eq!(
            verify(&with_member(1, "sig", json!(bad))),
            Err(ChainRefusal::BadSignature)
        );
    }
    // A malformed trusted public key cannot verify anything.
    let mut keys = trusted();
    keys.get_mut(B.0).expect("key").public_key = "not base64".to_owned();
    let origins = vec![A.0.to_owned()];
    let policy = ChainPolicy {
        trusted_keys: &keys,
        origins: &origins,
        signer: C.0,
        replay_window: WINDOW,
        max_links: 8,
    };
    assert_eq!(
        verify_chain(&wire(&abc()), &policy, &received(), NONCE, NOW),
        Err(ChainRefusal::BadSignature)
    );
}

#[test]
fn from_seed_rejects_bad_input() {
    assert!(ChainSigner::from_seed(&[1; 31], "gw-a").is_err());
    assert!(ChainSigner::from_seed(&[1; 33], "gw-a").is_err());
    assert!(ChainSigner::from_seed(&[1; 32], "").is_err());
    assert!(ChainSigner::from_seed(&[1; 32], &"g".repeat(65)).is_err());
    assert!(ChainSigner::from_seed(&[1; 32], &"g".repeat(64)).is_ok());
}
