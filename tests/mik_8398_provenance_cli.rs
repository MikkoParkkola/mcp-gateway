// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8398 rows C1-C4: the `provenance` CLI through the binary.
//!
//! Inputs are the A fixtures, copied (or edited, for tamper rows) into a
//! tempdir. No `mcp_gateway` item is used.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::Value;

const SEED_ENV: &str = "GATEWAY_PROVENANCE_SIGNING_SEED";
const KID_ENV: &str = "GATEWAY_PROVENANCE_KEY_ID";
const KID: &str = "prov-test-1";

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

fn write_private(path: &Path, contents: &[u8]) {
    std::fs::write(path, contents).expect("file writes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("file is owner-only");
    }
}

fn copy_fixture_to(home: &Path, name: &str) -> PathBuf {
    let target = home.join(name);
    write_private(&target, &read_fixture(name));
    target
}

fn seed_env_file(home: &Path, seed: &[u8; 32], kid: &str) -> PathBuf {
    let env_file = home.join("prov.env");
    let text = format!("{SEED_ENV}={}\n{KID_ENV}={kid}\n", STANDARD.encode(seed));
    write_private(&env_file, text.as_bytes());
    env_file
}

fn config_with_env_files(home: &Path, env_files: &[PathBuf]) -> PathBuf {
    let config = home.join("gateway.yaml");
    let mut text = String::from("server:\n  port: 39400\nenv_files:\n");
    for file in env_files {
        text.push_str(&format!("  - '{}'\n", file.display()));
    }
    write_private(&config, text.as_bytes());
    config
}

fn public_key_args(config: &Path) -> Vec<String> {
    vec![
        "--config".to_owned(),
        config.display().to_string(),
        "provenance".to_owned(),
        "public-key".to_owned(),
    ]
}

fn verify_args(
    trust: &Path,
    receipt: &Path,
    result: Option<&Path>,
    flags: &[&str],
) -> Vec<String> {
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
    for flag in flags {
        args.push((*flag).to_owned());
    }
    args
}

fn run(home: &Path, args: &[String], extra_env: &[(&str, &str)]) -> std::process::Output {
    let mut command = gateway_bin::command(home, gateway_bin::Inherit::Nothing);
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    for (key, value) in extra_env {
        command.env(*key, *value);
    }
    command.args(args).output().expect("the binary runs")
}

#[test]
fn public_key_prints_the_jwk_and_thumbprint() {
    let home = tempfile::tempdir().expect("temporary home");
    let seed_b64 = STANDARD.encode([7u8; 32]);
    let env_file = seed_env_file(home.path(), &[7u8; 32], KID);
    let config = config_with_env_files(home.path(), &[env_file]);
    let out = run(home.path(), &public_key_args(&config), &[]);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "exit 0, stderr: {stderr}");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let printed: Value = serde_json::from_str(&stdout).expect("stdout is one JSON object");
    assert_eq!(printed["jwk"], fixture_json("jwk.json"));
    let x = printed["jwk"]["x"].as_str().expect("an x");
    let message = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{x}\"}}");
    let digest = ring::digest::digest(&ring::digest::SHA256, message.as_bytes());
    let expected = URL_SAFE_NO_PAD.encode(digest);
    assert_eq!(printed["thumbprint"].as_str(), Some(expected.as_str()));
    assert!(!stdout.contains(seed_b64.as_str()), "stdout leaks the seed");
    assert!(!stderr.contains(seed_b64.as_str()), "stderr leaks the seed");
}

#[test]
fn public_key_reads_the_config_from_the_environment() {
    let home = tempfile::tempdir().expect("temporary home");
    let env_file = seed_env_file(home.path(), &[7u8; 32], KID);
    let config = config_with_env_files(home.path(), &[env_file]);
    let config_text = config.display().to_string();
    let args = vec!["provenance".to_owned(), "public-key".to_owned()];
    let out = run(home.path(), &args, &[("MCP_GATEWAY_CONFIG", config_text.as_str())]);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "exit 0, stderr: {stderr}");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let printed: Value = serde_json::from_str(&stdout).expect("stdout is one JSON object");
    assert_eq!(printed["jwk"], fixture_json("jwk.json"));
}

#[test]
fn env_file_wins_over_the_process_environment() {
    let home = tempfile::tempdir().expect("temporary home");
    let env_file = seed_env_file(home.path(), &[7u8; 32], KID);
    let config = config_with_env_files(home.path(), &[env_file]);
    let override_seed = STANDARD.encode([9u8; 32]);
    let out = run(
        home.path(),
        &public_key_args(&config),
        &[(SEED_ENV, override_seed.as_str()), (KID_ENV, "prov-test-2")],
    );
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let printed: Value = serde_json::from_str(&stdout).expect("stdout is one JSON object");
    assert_eq!(printed["jwk"], fixture_json("jwk.json"));
    assert_eq!(printed["jwk"]["kid"], serde_json::json!("prov-test-1"));
    assert_ne!(printed["jwk"], fixture_json("jwk_other.json"));
}

#[test]
fn public_key_without_a_seed_names_the_variable() {
    let home = tempfile::tempdir().expect("temporary home");
    let config = home.path().join("gateway.yaml");
    write_private(&config, b"server:\n  port: 39400\n");
    let out = run(home.path(), &public_key_args(&config), &[]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(stderr.contains(SEED_ENV), "stderr names the variable: {stderr}");
}

#[test]
fn public_key_with_a_bad_seed_leaks_nothing() {
    let home = tempfile::tempdir().expect("temporary home");
    let bad = STANDARD.encode([7u8; 31]);
    let env_file = home.path().join("prov.env");
    let text = format!("{SEED_ENV}={bad}\n{KID_ENV}={KID}\n");
    write_private(&env_file, text.as_bytes());
    let config = config_with_env_files(home.path(), &[env_file]);
    let out = run(home.path(), &public_key_args(&config), &[]);
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(!stdout.contains(bad.as_str()), "stdout leaks the seed");
    assert!(!stderr.contains(bad.as_str()), "stderr leaks the seed");
}

#[test]
fn verify_bounds_with_a_result() {
    let home = tempfile::tempdir().expect("temporary home");
    let trust = copy_fixture_to(home.path(), "jwk.json");
    let receipt = copy_fixture_to(home.path(), "provenance.json");
    let result = copy_fixture_to(home.path(), "result.json");
    let out = run(home.path(), &verify_args(&trust, &receipt, Some(&result), &[]), &[]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(stdout, "BOUND kid=prov-test-1\n");
}

#[test]
fn verify_without_a_result_needs_its_flag() {
    let home = tempfile::tempdir().expect("temporary home");
    let trust = copy_fixture_to(home.path(), "jwk.json");
    let receipt = copy_fixture_to(home.path(), "provenance.json");
    let out = run(home.path(), &verify_args(&trust, &receipt, None, &[]), &[]);
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(stdout, "SIGNATURE-ONLY kid=prov-test-1\n");
    let args = verify_args(&trust, &receipt, None, &["--signature-only"]);
    let out = run(home.path(), &args, &[]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(stdout, "SIGNATURE-ONLY kid=prov-test-1 (accepted: --signature-only)\n");
}

#[test]
fn verify_unbound_needs_its_flag() {
    let home = tempfile::tempdir().expect("temporary home");
    let trust = copy_fixture_to(home.path(), "jwk.json");
    let receipt = copy_fixture_to(home.path(), "provenance_unbound.json");
    let result = home.path().join("unbound_result.json");
    write_private(&result, b"{\"n\":9007199254740992}");
    let out = run(home.path(), &verify_args(&trust, &receipt, Some(&result), &[]), &[]);
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(stdout, "UNBOUND kid=prov-test-1\n");
    let args = verify_args(&trust, &receipt, Some(&result), &["--accept-unbound"]);
    let out = run(home.path(), &args, &[]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(stdout, "UNBOUND kid=prov-test-1 (accepted: --accept-unbound)\n");
}

#[test]
fn verify_flags_do_not_cross_rescue() {
    let home = tempfile::tempdir().expect("temporary home");
    let trust = copy_fixture_to(home.path(), "jwk.json");
    let bound = copy_fixture_to(home.path(), "provenance.json");
    let unbound = copy_fixture_to(home.path(), "provenance_unbound.json");
    let result = home.path().join("unbound_result.json");
    write_private(&result, b"{\"n\":9007199254740992}");
    let args = verify_args(&trust, &bound, None, &["--accept-unbound"]);
    let out = run(home.path(), &args, &[]);
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(stdout, "SIGNATURE-ONLY kid=prov-test-1\n");
    let args = verify_args(&trust, &unbound, Some(&result), &["--signature-only"]);
    let out = run(home.path(), &args, &[]);
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(stdout, "UNBOUND kid=prov-test-1\n");
}

#[test]
fn verify_tampered_is_invalid_with_both_flags() {
    let home = tempfile::tempdir().expect("temporary home");
    let trust = copy_fixture_to(home.path(), "jwk.json");
    let mut prov = fixture_json("provenance.json");
    prov["receipt"]["tool"] = serde_json::json!("other_tool");
    let receipt = home.path().join("tampered.json");
    let bytes = serde_json::to_vec(&prov).expect("tampered serializes");
    write_private(&receipt, &bytes);
    let result = copy_fixture_to(home.path(), "result.json");
    let flags = ["--signature-only", "--accept-unbound"];
    let out = run(home.path(), &verify_args(&trust, &receipt, Some(&result), &flags), &[]);
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(stdout, "INVALID outer_receipt_mismatch\n");
}

#[test]
fn verify_accepts_a_stamped_result_as_receipt() {
    let home = tempfile::tempdir().expect("temporary home");
    let trust = copy_fixture_to(home.path(), "jwk.json");
    let result = fixture_json("result.json");
    let stamped = serde_json::json!({
        "content": result["content"].clone(),
        "_meta": {"provenance": fixture_json("provenance.json")},
    });
    let receipt = home.path().join("stamped.json");
    let bytes = serde_json::to_vec(&stamped).expect("stamped serializes");
    write_private(&receipt, &bytes);
    let expected = copy_fixture_to(home.path(), "result.json");
    let out = run(home.path(), &verify_args(&trust, &receipt, Some(&expected), &[]), &[]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(stdout, "BOUND kid=prov-test-1\n");
}

#[test]
fn verify_accepts_a_stamped_result_as_result() {
    let home = tempfile::tempdir().expect("temporary home");
    let trust = copy_fixture_to(home.path(), "jwk.json");
    let receipt = copy_fixture_to(home.path(), "provenance.json");
    let result = fixture_json("result.json");
    let stamped = serde_json::json!({
        "content": result["content"].clone(),
        "_meta": {"provenance": fixture_json("provenance.json")},
    });
    let stamped_result = home.path().join("stamped_result.json");
    let bytes = serde_json::to_vec(&stamped).expect("stamped serializes");
    write_private(&stamped_result, &bytes);
    let out = run(home.path(), &verify_args(&trust, &receipt, Some(&stamped_result), &[]), &[]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(stdout, "BOUND kid=prov-test-1\n");
}

#[test]
fn verify_result_mismatch_is_invalid_under_every_flag_set() {
    let home = tempfile::tempdir().expect("temporary home");
    let trust = copy_fixture_to(home.path(), "jwk.json");
    let receipt = copy_fixture_to(home.path(), "provenance.json");
    let other = home.path().join("other_result.json");
    write_private(&other, b"{\"content\":[{\"type\":\"text\",\"text\":\"other\"}]}");
    let flag_sets: [&[&str]; 4] = [
        &[],
        &["--signature-only"],
        &["--accept-unbound"],
        &["--signature-only", "--accept-unbound"],
    ];
    for flags in flag_sets {
        let out = run(home.path(), &verify_args(&trust, &receipt, Some(&other), flags), &[]);
        assert_eq!(out.status.code(), Some(1), "flags {flags:?} must not rescue a mismatch");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        assert_eq!(stdout, "INVALID result_mismatch\n");
    }
}

#[test]
fn verify_unhashable_offer_is_invalid_under_every_flag_set() {
    let home = tempfile::tempdir().expect("temporary home");
    let trust = copy_fixture_to(home.path(), "jwk.json");
    let receipt = copy_fixture_to(home.path(), "provenance.json");
    let array = home.path().join("array_result.json");
    write_private(&array, b"[1,2]");
    let flag_sets: [&[&str]; 4] = [
        &[],
        &["--signature-only"],
        &["--accept-unbound"],
        &["--signature-only", "--accept-unbound"],
    ];
    for flags in flag_sets {
        let out = run(home.path(), &verify_args(&trust, &receipt, Some(&array), flags), &[]);
        assert_eq!(out.status.code(), Some(1), "flags {flags:?} must not rescue");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        assert_eq!(stdout, "INVALID result_unhashable\n");
    }
}

#[test]
fn verify_signature_without_domain_tag_is_invalid() {
    use ring::signature::Ed25519KeyPair;

    let home = tempfile::tempdir().expect("temporary home");
    let trust = copy_fixture_to(home.path(), "jwk.json");
    let mut prov = fixture_json("provenance.json");
    let payload = URL_SAFE_NO_PAD
        .decode(prov["public_signature"]["payload"].as_str().expect("a payload"))
        .expect("payload decodes");
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&[7u8; 32]).expect("a seed loads");
    let bare = URL_SAFE_NO_PAD.encode(key_pair.sign(&payload).as_ref());
    prov["public_signature"]["sig"] = serde_json::json!(bare);
    let receipt = home.path().join("bare_tag.json");
    let bytes = serde_json::to_vec(&prov).expect("tampered serializes");
    write_private(&receipt, &bytes);
    let result = copy_fixture_to(home.path(), "result.json");
    for flags in [&[][..], &["--signature-only", "--accept-unbound"][..]] {
        let out = run(home.path(), &verify_args(&trust, &receipt, Some(&result), flags), &[]);
        assert_eq!(out.status.code(), Some(1), "flags {flags:?} must not rescue");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        assert_eq!(stdout, "INVALID bad_signature\n");
    }
}

#[test]
fn verify_newline_kid_prints_one_line() {
    use ring::signature::Ed25519KeyPair;

    let home = tempfile::tempdir().expect("temporary home");
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&[7u8; 32]).expect("a seed loads");
    let x = URL_SAFE_NO_PAD.encode(key_pair.public_key().as_ref());
    let trust_text =
        format!("{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"prov-test-1\",\"x\":\"{x}\"}}");
    let trust = home.path().join("trust.json");
    write_private(&trust, trust_text.as_bytes());
    let inner = serde_json::json!({
        "subject_kind": "runtime",
        "backend_id": "github",
        "tool": "search_issues",
        "observed_at": "2026-07-13T10:15:30Z",
        "cache": "miss",
        "backend_ok": true,
        "evidence_kind": "observed"
    });
    let payload = serde_json::json!({
        "v": 1,
        "alg": "EdDSA",
        "kid": "prov\ntest",
        "receipt": inner,
        "result_sha256": null,
    });
    let payload_bytes = serde_json::to_vec(&payload).expect("payload serializes");
    let prov = serde_json::json!({
        "receipt": inner,
        "key_id": "bnaut/gateway",
        "algorithm": "HS256",
        "signature": "dummy",
        "public_signature": {
            "payload": URL_SAFE_NO_PAD.encode(&payload_bytes),
            "sig": URL_SAFE_NO_PAD.encode([0u8; 64]),
        },
    });
    let receipt = home.path().join("newline_kid.json");
    let bytes = serde_json::to_vec(&prov).expect("receipt serializes");
    write_private(&receipt, &bytes);
    let out = run(home.path(), &verify_args(&trust, &receipt, None, &[]), &[]);
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(stdout.lines().count(), 1, "exactly one stdout line: {stdout:?}");
    assert!(stdout.ends_with('\n'), "the line ends with a newline: {stdout:?}");
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[test]
fn doctor_output_holds_no_canary_seed() {
    let home = tempfile::tempdir().expect("temporary home");
    let canary = [42u8; 32];
    let canary_b64 = STANDARD.encode(canary);
    let canary_hex = hex(&canary);
    let env_file = seed_env_file(home.path(), &canary, "prov-canary");
    let config = config_with_env_files(home.path(), &[env_file]);
    let args = vec!["--config".to_owned(), config.display().to_string(), "doctor".to_owned()];
    let out = run(home.path(), &args, &[]);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "doctor exits 0, stderr: {stderr}");
    assert!(
        stdout.contains(config.display().to_string().as_str()),
        "doctor names the supplied config path: {stdout}"
    );
    let combined = format!("{stdout}{stderr}");
    assert!(!combined.contains(canary_b64.as_str()), "doctor leaks the canary seed");
    assert!(!combined.contains(canary_hex.as_str()), "doctor leaks the canary hex");
}

#[cfg(feature = "config-export")]
#[test]
fn config_export_output_holds_no_canary_seed() {
    let home = tempfile::tempdir().expect("temporary home");
    let canary = [42u8; 32];
    let canary_b64 = STANDARD.encode(canary);
    let canary_hex = hex(&canary);
    let env_file = seed_env_file(home.path(), &canary, "prov-canary");
    let config = config_with_env_files(home.path(), &[env_file]);
    let args = vec![
        "setup".to_owned(),
        "export".to_owned(),
        "--target".to_owned(),
        "generic".to_owned(),
        "--config".to_owned(),
        config.display().to_string(),
    ];
    let out = run(home.path(), &args, &[]);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "export exits 0, stderr: {stderr}");
    let parsed: Value = serde_json::from_str(&stdout).expect("stdout parses as JSON");
    assert!(parsed.get("mcpServers").is_some(), "export prints its JSON shape: {stdout}");
    let combined = format!("{stdout}{stderr}");
    assert!(!combined.contains(canary_b64.as_str()), "export leaks the canary seed");
    assert!(!combined.contains(canary_hex.as_str()), "export leaks the canary hex");
}
