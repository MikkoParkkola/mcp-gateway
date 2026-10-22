// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8398 AC1: a receipt verifies with only the public JWK.
//!
//! No `mcp_gateway` item is used: the fixtures are verified independently with
//! ring, base64 and serde_json only, and the binary runs with a cleared
//! environment so no signing secret is present.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{ED25519, UnparsedPublicKey};
use serde_json::Value;

const DOMAIN_TAG: &[u8] = b"mcp-gateway-provenance-ed25519-v1\0";
const KID: &str = "prov-test-1";
/// RFC 8785 of the fixture result: plain sorted-key compact JSON.
const RESULT_RFC8785: &[u8] = br#"{"content":[{"text":"ok","type":"text"}]}"#;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mik_8398").join(name)
}

fn read_fixture(name: &str) -> Vec<u8> {
    std::fs::read(fixture_path(name)).unwrap_or_else(|error| {
        panic!("fixture {name} missing: bless with UPDATE_GOLDEN=1 on the implemented tree: {error}")
    })
}

fn fixture_json(name: &str) -> Value {
    serde_json::from_slice(&read_fixture(name)).expect("fixture parses")
}

fn copy_fixture_to(home: &Path, name: &str) -> PathBuf {
    let target = home.join(name);
    write_private(&target, &read_fixture(name));
    target
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("a String never fails a write");
    }
    out
}

/// Verify a provenance object against a JWK with no gateway code.
fn independent_verify(jwk: &Value, prov: &Value) -> bool {
    let (Some(x), Some(payload_b64), Some(sig_b64)) = (
        jwk.get("x").and_then(Value::as_str),
        prov.pointer("/public_signature/payload").and_then(Value::as_str),
        prov.pointer("/public_signature/sig").and_then(Value::as_str),
    ) else {
        return false;
    };
    let (Ok(key), Ok(payload_raw), Ok(sig)) = (
        URL_SAFE_NO_PAD.decode(x),
        URL_SAFE_NO_PAD.decode(payload_b64),
        URL_SAFE_NO_PAD.decode(sig_b64),
    ) else {
        return false;
    };
    let payload: Value = match serde_json::from_slice(&payload_raw) {
        Ok(payload) => payload,
        Err(_) => return false,
    };
    if payload["kid"] != jwk["kid"] {
        return false;
    }
    let mut message = DOMAIN_TAG.to_vec();
    message.extend_from_slice(&payload_raw);
    UnparsedPublicKey::new(&ED25519, key).verify(&message, &sig).is_ok()
}

fn verify_args(trust: &Path, receipt: &Path, result: Option<&Path>) -> Vec<String> {
    let mut args = vec![
        "provenance".to_owned(),
        "verify".to_owned(),
        "--trust".to_owned(),
        trust.display().to_string(),
        receipt.display().to_string(),
    ];
    if let Some(result) = result {
        args.push("--result".to_owned());
        args.push(result.display().to_string());
    }
    args
}

fn write_private(path: &Path, contents: &[u8]) {
    std::fs::write(path, contents).expect("file writes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("file is owner-only");
    }
}

fn run(home: &Path, args: &[String]) -> std::process::Output {
    let mut command = gateway_bin::command(home, gateway_bin::Inherit::Nothing);
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    command.args(args).output().expect("the binary runs")
}

#[test]
fn a_receipt_verifies_with_only_the_public_jwk() {
    let jwk = fixture_json("jwk.json");
    let prov = fixture_json("provenance.json");
    assert!(independent_verify(&jwk, &prov));
    let payload_b64 = prov["public_signature"]["payload"].as_str().expect("a payload");
    let payload_raw = URL_SAFE_NO_PAD.decode(payload_b64).expect("payload decodes");
    let payload: Value = serde_json::from_slice(&payload_raw).expect("payload parses");
    assert_eq!(payload["v"].as_u64(), Some(1));
    assert_eq!(payload["alg"].as_str(), Some("EdDSA"));
    assert_eq!(payload["kid"].as_str(), Some(KID));
    assert_eq!(payload["receipt"], prov["receipt"]);
    let digest = ring::digest::digest(&ring::digest::SHA256, RESULT_RFC8785);
    let expected = hex(digest.as_ref());
    assert_eq!(payload["result_sha256"].as_str(), Some(expected.as_str()));
}

#[test]
fn a1b_the_binary_reports_bound_with_only_the_public_jwk() {
    let home = tempfile::tempdir().expect("temporary home");
    let trust = copy_fixture_to(home.path(), "jwk.json");
    let receipt = copy_fixture_to(home.path(), "provenance.json");
    let result = copy_fixture_to(home.path(), "result.json");
    let args = verify_args(&trust, &receipt, Some(&result));
    let out = run(home.path(), &args);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(stdout, "BOUND kid=prov-test-1\n");
}

#[test]
fn a_flipped_payload_byte_fails() {
    let jwk = fixture_json("jwk.json");
    let mut tampered = fixture_json("provenance.json");
    let payload_b64 = tampered["public_signature"]["payload"].as_str().expect("a payload");
    let mut payload = URL_SAFE_NO_PAD.decode(payload_b64).expect("payload decodes");
    payload[10] ^= 0x01;
    tampered["public_signature"]["payload"] = Value::from(URL_SAFE_NO_PAD.encode(&payload));
    assert!(!independent_verify(&jwk, &tampered));

    let home = tempfile::tempdir().expect("temporary home");
    let receipt = home.path().join("tampered.json");
    let bytes = serde_json::to_vec(&tampered).expect("tampered serializes");
    write_private(&receipt, &bytes);
    let trust = copy_fixture_to(home.path(), "jwk.json");
    let expected = copy_fixture_to(home.path(), "result.json");
    let args = verify_args(&trust, &receipt, Some(&expected));
    let out = run(home.path(), &args);
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(stdout, "INVALID bad_signature\n");
}

#[test]
fn the_wrong_key_fails() {
    let other = fixture_json("jwk_other.json");
    let prov = fixture_json("provenance.json");
    assert!(!independent_verify(&other, &prov));

    let home = tempfile::tempdir().expect("temporary home");
    let trust = copy_fixture_to(home.path(), "jwk_other.json");
    let receipt = copy_fixture_to(home.path(), "provenance.json");
    let result = copy_fixture_to(home.path(), "result.json");
    let args = verify_args(&trust, &receipt, Some(&result));
    let out = run(home.path(), &args);
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(stdout, "INVALID bad_signature\n");
}

#[test]
fn unknown_kid_fails() {
    let trust_jwk = fixture_json("jwk_unknown_kid.json");
    let prov = fixture_json("provenance.json");
    assert!(!independent_verify(&trust_jwk, &prov));

    let home = tempfile::tempdir().expect("temporary home");
    let trust = copy_fixture_to(home.path(), "jwk_unknown_kid.json");
    let receipt = copy_fixture_to(home.path(), "provenance.json");
    let result = copy_fixture_to(home.path(), "result.json");
    let args = verify_args(&trust, &receipt, Some(&result));
    let out = run(home.path(), &args);
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(stdout, "INVALID unknown_kid\n");
}

#[test]
fn a_changed_jwk_kid_fails() {
    let mut jwk = fixture_json("jwk.json");
    jwk["kid"] = Value::from("prov-test-9");
    let prov = fixture_json("provenance.json");
    assert!(!independent_verify(&jwk, &prov));
}

#[test]
fn a_missing_domain_tag_fails() {
    let jwk = fixture_json("jwk.json");
    let prov = fixture_json("provenance.json");
    let key = URL_SAFE_NO_PAD.decode(jwk["x"].as_str().expect("an x")).expect("x decodes");
    let payload = URL_SAFE_NO_PAD
        .decode(prov["public_signature"]["payload"].as_str().expect("a payload"))
        .expect("payload decodes");
    let sig = URL_SAFE_NO_PAD
        .decode(prov["public_signature"]["sig"].as_str().expect("a sig"))
        .expect("sig decodes");
    assert!(UnparsedPublicKey::new(&ED25519, key).verify(&payload, &sig).is_err());
}

#[test]
fn the_jwk_has_no_private_member() {
    let jwk = fixture_json("jwk.json");
    assert!(jwk.get("d").is_none(), "no private member");
    assert_eq!(jwk["kty"].as_str(), Some("OKP"));
    assert_eq!(jwk["crv"].as_str(), Some("Ed25519"));
    let x = URL_SAFE_NO_PAD.decode(jwk["x"].as_str().expect("an x")).expect("x decodes");
    assert_eq!(x.len(), 32);
}
