// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Focused unit tests for the EXISTING [`super::resolve_secrets`] helper.
//!
//! Everything material happens through an in-memory fake overlay: no
//! `std::env` read, no process environment mutation, so these tests are
//! order-independent and safe under a threaded test runner.
//!
//! Scope note: `resolve_secrets` sees only store-key and cross-adapter reuse,
//! so that is all the first group of tests exercises. GATEWAY AUTHENTICATION
//! separation is a separate pair of entry points and is covered by the second
//! group below, against `GatewayCredential` values built from configured text.
//! Nothing here claims any RUNTIME property: this is configuration only.

use std::cell::RefCell;
use std::collections::BTreeMap;

use super::{AccountsConfigError, AdapterConfig, AdapterKind, resolve_secrets};
// The overlay contract lives one level up, in `config.rs`.
use super::super::SecretOverlay;

/// Fake overlay: a fixed name -> value table plus read tracking, so a test can
/// assert WHICH names were looked up and that nothing else was.
struct FakeOverlay {
    values: BTreeMap<String, String>,
    reads: RefCell<Vec<String>>,
}

impl FakeOverlay {
    fn new(pairs: &[(&str, &str)]) -> Self {
        Self {
            values: pairs
                .iter()
                .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
                .collect(),
            reads: RefCell::new(Vec::new()),
        }
    }

    fn reads(&self) -> Vec<String> {
        self.reads.borrow().clone()
    }
}

impl SecretOverlay for FakeOverlay {
    fn resolve(&self, name: &str) -> Option<String> {
        self.reads.borrow_mut().push(name.to_string());
        self.values.get(name).cloned()
    }
}

/// A structurally valid adapter pointing at `env:<variable>`.
fn adapter(installation_id: &str, variable: &str) -> AdapterConfig {
    AdapterConfig {
        kind: AdapterKind::OpenwebuiSignedHeader,
        installation_id: installation_id.to_string(),
        header: "X-OpenWebUI-Assertion".to_string(),
        issuer: "open-webui".to_string(),
        hmac_secret_ref: format!("env:{variable}"),
        allowed_api_key_names: vec!["desktop".to_string()],
        max_lifetime_seconds: 300,
        clock_skew_seconds: 30,
    }
}

/// Exactly 32 ASCII bytes, distinct per `tag`.
fn secret_32(tag: char) -> String {
    std::iter::repeat_n(tag, 32).collect()
}

fn no_store_keys() -> BTreeMap<String, Vec<u8>> {
    BTreeMap::new()
}

#[test]
fn secret_of_thirty_one_bytes_is_refused() {
    let short: String = std::iter::repeat_n('a', 31).collect();
    let overlay = FakeOverlay::new(&[("OPENWEBUI_HMAC", short.as_str())]);

    let error = resolve_secrets(
        &[adapter("desk", "OPENWEBUI_HMAC")],
        &overlay,
        &no_store_keys(),
    )
    .expect_err("31 bytes is below the 32-byte minimum");

    assert!(
        matches!(
            error,
            AccountsConfigError::AdapterSecretTooShort { index: 0 }
        ),
        "expected AdapterSecretTooShort at index 0, got {error:?}"
    );
    assert_eq!(overlay.reads(), vec!["OPENWEBUI_HMAC".to_string()]);
}

#[test]
fn distinct_thirty_two_byte_secret_is_accepted() {
    let overlay = FakeOverlay::new(&[("OPENWEBUI_HMAC", secret_32('a').as_str())]);

    let read = resolve_secrets(
        &[adapter("desk", "OPENWEBUI_HMAC")],
        &overlay,
        &no_store_keys(),
    )
    .expect("a distinct 32-byte secret satisfies both material rules");

    // Names only, in list order — never the material.
    assert_eq!(read, vec!["OPENWEBUI_HMAC".to_string()]);
    assert_eq!(overlay.reads(), vec!["OPENWEBUI_HMAC".to_string()]);
}

#[test]
fn missing_reference_is_an_explicit_unresolved_error() {
    let overlay = FakeOverlay::new(&[]);

    let error = resolve_secrets(&[adapter("desk", "ABSENT_VAR")], &overlay, &no_store_keys())
        .expect_err("an absent variable must not read as an empty secret");

    match error {
        AccountsConfigError::AdapterSecretUnresolved { index, variable } => {
            assert_eq!(index, 0);
            assert_eq!(variable, "ABSENT_VAR");
        }
        other => panic!("expected AdapterSecretUnresolved, got {other:?}"),
    }
}

#[test]
fn raw_store_key_reuse_is_rejected() {
    // The overlay hands back the SAME bytes held as an account store key.
    let material = secret_32('k');
    let mut store_keys = no_store_keys();
    store_keys.insert("key-1".to_string(), material.clone().into_bytes());
    let overlay = FakeOverlay::new(&[("OPENWEBUI_HMAC", material.as_str())]);

    let error = resolve_secrets(&[adapter("desk", "OPENWEBUI_HMAC")], &overlay, &store_keys)
        .expect_err("signing key must not equal an account store key");

    assert!(
        matches!(error, AccountsConfigError::AdapterSecretReuse { index: 0 }),
        "expected AdapterSecretReuse at index 0, got {error:?}"
    );
}

#[test]
fn base64_encoded_store_key_reuse_is_rejected() {
    // `accounts.keys` holds base64; an operator pointing both at one variable
    // sees "encoded text" vs "decoded key" and must still be refused.
    use base64::Engine as _;
    let key_bytes = secret_32('k').into_bytes();
    let encoded = base64::engine::general_purpose::STANDARD.encode(&key_bytes);
    let mut store_keys = no_store_keys();
    store_keys.insert("key-1".to_string(), key_bytes);
    let overlay = FakeOverlay::new(&[("OPENWEBUI_HMAC", encoded.as_str())]);

    let error = resolve_secrets(&[adapter("desk", "OPENWEBUI_HMAC")], &overlay, &store_keys)
        .expect_err("the base64 form of a store key is the same secret");

    assert!(
        matches!(error, AccountsConfigError::AdapterSecretReuse { index: 0 }),
        "expected AdapterSecretReuse at index 0, got {error:?}"
    );
}

#[test]
fn two_installations_sharing_one_actual_secret_are_rejected() {
    let shared = secret_32('s');
    let overlay = FakeOverlay::new(&[("HMAC_ONE", shared.as_str()), ("HMAC_TWO", shared.as_str())]);
    let adapters = [adapter("desk", "HMAC_ONE"), adapter("laptop", "HMAC_TWO")];

    let error = resolve_secrets(&adapters, &overlay, &no_store_keys())
        .expect_err("two installations must not share one signing secret");

    // Reported against the SECOND adapter, the one that collides.
    assert!(
        matches!(error, AccountsConfigError::AdapterSecretReuse { index: 1 }),
        "expected AdapterSecretReuse at index 1, got {error:?}"
    );
    assert_eq!(
        overlay.reads(),
        vec!["HMAC_ONE".to_string(), "HMAC_TWO".to_string()]
    );
}

#[test]
fn distinct_secrets_across_separate_installations_are_accepted() {
    let overlay = FakeOverlay::new(&[
        ("HMAC_ONE", secret_32('a').as_str()),
        ("HMAC_TWO", secret_32('b').as_str()),
    ]);
    let adapters = [adapter("desk", "HMAC_ONE"), adapter("laptop", "HMAC_TWO")];

    let read = resolve_secrets(&adapters, &overlay, &no_store_keys())
        .expect("distinct per-installation secrets are the intended configuration");

    assert_eq!(read, vec!["HMAC_ONE".to_string(), "HMAC_TWO".to_string()]);
}

// ── Gateway authentication separation ─────────────────────────────────────────
//
// The two halves are tested through their own entry points, because that is how
// the loader calls them: the reference check reads nothing and runs for every
// config, the material check resolves through the same fake overlay and runs
// only where the store is enabled.

use super::{
    GatewayCredential, validate_no_gateway_material_reuse, validate_no_gateway_reference_alias,
};

/// The reported credential label, or a panic naming what came back instead.
fn gateway_reuse_credential(error: &AccountsConfigError, expected_index: usize) -> String {
    match error {
        AccountsConfigError::AdapterSecretReusesGatewayAuth { index, credential } => {
            assert_eq!(
                *index, expected_index,
                "refusal must name the offending adapter"
            );
            credential.clone()
        }
        other => panic!("expected AdapterSecretReusesGatewayAuth, got {other:?}"),
    }
}

/// No refusal — Display or Debug — may carry secret bytes, only coordinates.
fn assert_no_material_leaked(error: &AccountsConfigError, material: &[&str]) {
    let rendered = format!("{error} | {error:?}");
    for secret in material {
        assert!(
            !rendered.contains(secret),
            "refusal must name configuration coordinates, never secret material: {rendered}"
        );
    }
}

#[test]
fn one_variable_named_by_both_an_adapter_and_the_bearer_token_is_refused() {
    // Decidable from the text alone: no overlay is passed, so this refusal
    // stands even for a disabled store whose variables need not exist.
    let error = validate_no_gateway_reference_alias(
        &[adapter("desk", "SHARED_SECRET")],
        &[GatewayCredential::BearerToken("env:SHARED_SECRET")],
    )
    .expect_err("one variable wired into both places is one secret");

    assert_eq!(gateway_reuse_credential(&error, 0), "auth.bearer_token");
}

#[test]
fn one_variable_named_by_both_an_adapter_and_an_api_key_is_refused() {
    let error = validate_no_gateway_reference_alias(
        &[
            adapter("desk", "HMAC_ONE"),
            adapter("laptop", "SHARED_SECRET"),
        ],
        &[GatewayCredential::ApiKey {
            index: 1,
            name: "owui-gateway-key",
            spec: "env:SHARED_SECRET",
        }],
    )
    .expect_err("an api key variable must not double as adapter signing material");

    let credential = gateway_reuse_credential(&error, 1);
    assert!(
        credential.contains("auth.api_keys[1]") && credential.contains("owui-gateway-key"),
        "refusal must name the api key by field path and operator label, got {credential}"
    );
}

#[test]
fn two_different_variables_holding_the_same_bytes_are_refused_on_material() {
    let shared = secret_32('g');
    let overlay = FakeOverlay::new(&[
        ("OPENWEBUI_HMAC", shared.as_str()),
        ("GATEWAY_BEARER", shared.as_str()),
    ]);
    let adapters = [adapter("desk", "OPENWEBUI_HMAC")];
    let credentials = [GatewayCredential::BearerToken("env:GATEWAY_BEARER")];

    // Two names, so the reference check cannot see it — that is the point.
    validate_no_gateway_reference_alias(&adapters, &credentials)
        .expect("distinct variable NAMES pass the structural check");

    let error = validate_no_gateway_material_reuse(&adapters, &overlay, &credentials)
        .expect_err("two names holding one value are one secret");

    assert_eq!(gateway_reuse_credential(&error, 0), "auth.bearer_token");
    assert_no_material_leaked(&error, &[shared.as_str()]);
}

#[test]
fn an_adapter_secret_equal_to_a_literal_bearer_token_is_refused() {
    let literal = secret_32('b');
    let overlay = FakeOverlay::new(&[("OPENWEBUI_HMAC", literal.as_str())]);

    let error = validate_no_gateway_material_reuse(
        &[adapter("desk", "OPENWEBUI_HMAC")],
        &overlay,
        // A literal credential in the file is still the credential the gateway
        // authenticates with, so it is compared as material.
        &[GatewayCredential::BearerToken(literal.as_str())],
    )
    .expect_err("a literal bearer token is still gateway authentication material");

    assert_eq!(gateway_reuse_credential(&error, 0), "auth.bearer_token");
    assert_no_material_leaked(&error, &[literal.as_str()]);
}

#[test]
fn an_adapter_secret_equal_to_a_literal_api_key_is_refused() {
    let literal = secret_32('k');
    let overlay = FakeOverlay::new(&[("OPENWEBUI_HMAC", literal.as_str())]);

    let error = validate_no_gateway_material_reuse(
        &[adapter("desk", "OPENWEBUI_HMAC")],
        &overlay,
        &[GatewayCredential::ApiKey {
            index: 0,
            name: "owui-gateway-key",
            spec: literal.as_str(),
        }],
    )
    .expect_err("a literal api key is still gateway authentication material");

    let credential = gateway_reuse_credential(&error, 0);
    assert!(
        credential.contains("auth.api_keys[0]") && credential.contains("owui-gateway-key"),
        "refusal must name the api key by field path and operator label, got {credential}"
    );
    assert_no_material_leaked(&error, &[literal.as_str()]);
}

#[test]
fn distinct_adapter_and_gateway_credentials_are_accepted_by_both_halves() {
    let adapter_secret = secret_32('a');
    let bearer = secret_32('b');
    let api_key = secret_32('c');
    let overlay = FakeOverlay::new(&[
        ("OPENWEBUI_HMAC", adapter_secret.as_str()),
        ("GATEWAY_BEARER", bearer.as_str()),
    ]);
    let adapters = [adapter("desk", "OPENWEBUI_HMAC")];
    let credentials = [
        GatewayCredential::BearerToken("env:GATEWAY_BEARER"),
        GatewayCredential::ApiKey {
            index: 0,
            name: "owui-gateway-key",
            spec: api_key.as_str(),
        },
    ];

    validate_no_gateway_reference_alias(&adapters, &credentials)
        .expect("separate variables are the intended configuration");
    validate_no_gateway_material_reuse(&adapters, &overlay, &credentials)
        .expect("separate material is the intended configuration");
}

#[test]
fn an_auto_bearer_token_is_skipped_rather_than_compared_as_text() {
    // `auto` mints a fresh random token per resolution, so the sentinel TEXT is
    // not configured material. An adapter secret that happens to equal the
    // sentinel spelling must therefore still be accepted: a refusal here would
    // prove the sentinel was being compared as a literal credential.
    let overlay = FakeOverlay::new(&[("OPENWEBUI_HMAC", "auto")]);
    let adapters = [adapter("desk", "OPENWEBUI_HMAC")];
    let credentials = [GatewayCredential::BearerToken("auto")];

    validate_no_gateway_reference_alias(&adapters, &credentials)
        .expect("`auto` is not an env: reference, so it aliases no variable");
    validate_no_gateway_material_reuse(&adapters, &overlay, &credentials)
        .expect("`auto` has no configured material to reuse");
}
