// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! ADR-028: `keychain:NAME` references, resolved through the
//! overlay's reader. Every test here uses an in-memory keychain.

use std::sync::Arc;

use super::EnvOverlay;
use super::keychain::{FakeKeychain, KeychainError, WipedBytes};
use super::secret_ref::SecretRef;

const FIELD: &str = "auth.bearer_token";
const NAME: &str = "mcp-gateway.auth-bearer-token.1761418800123.9f3a1c2e04b7d815";
const SENTINEL: &str = "kc-sentinel-7f3a";

fn overlay_with(fake: &Arc<FakeKeychain>) -> EnvOverlay {
    EnvOverlay::none().with_keychain(fake.clone())
}

fn resolve(fake: &Arc<FakeKeychain>, text: &str) -> crate::Result<String> {
    SecretRef::parse(text).resolve(FIELD, &overlay_with(fake))
}

fn message(result: crate::Result<String>) -> String {
    match result {
        Ok(value) => panic!("expected a refusal, got a value of {} bytes", value.len()),
        Err(error) => error.to_string(),
    }
}

#[test]
fn a1_keychain_prefix_parses() {
    assert_eq!(SecretRef::parse("keychain:abc"), SecretRef::Keychain("abc"));
    assert_eq!(
        SecretRef::parse("keychainabc"),
        SecretRef::Literal("keychainabc")
    );
}

#[test]
fn a1_invalid_names_are_refused_without_a_lookup() {
    let long = "a".repeat(129);
    for name in ["", long.as_str(), "a/b", "a b", "a\0b"] {
        let fake = Arc::new(FakeKeychain::default());
        let text = format!("keychain:{name}");
        let error = message(resolve(&fake, &text));
        assert!(error.contains(FIELD), "{error}");
        assert!(error.contains("not a valid keychain name"), "{error}");
        assert!(fake.asked().is_empty(), "looked up {:?}", fake.asked());
    }
}

#[test]
fn a1_a_128_character_name_is_valid() {
    let name = "a".repeat(128);
    let fake = Arc::new(FakeKeychain::default());
    fake.insert(&name, b"s3cr3t");
    assert_eq!(
        resolve(&fake, &format!("keychain:{name}")).unwrap(),
        "s3cr3t"
    );
}

#[test]
fn a1_an_entry_resolves() {
    let fake = Arc::new(FakeKeychain::default());
    fake.insert(NAME, b"s3cr3t");
    assert_eq!(
        resolve(&fake, &format!("keychain:{NAME}")).unwrap(),
        "s3cr3t"
    );
    assert_eq!(fake.asked(), vec![NAME.to_owned()]);
}

#[test]
fn a2_a_missing_entry_is_refused_by_name() {
    let fake = Arc::new(FakeKeychain::default());
    let error = message(resolve(&fake, &format!("keychain:{NAME}")));
    assert!(error.contains(FIELD), "{error}");
    assert!(error.contains(NAME), "{error}");
    assert!(error.contains("does not exist"), "{error}");
}

#[test]
fn a2_an_empty_entry_is_refused() {
    let fake = Arc::new(FakeKeychain::default());
    fake.insert(NAME, b"");
    let error = message(resolve(&fake, &format!("keychain:{NAME}")));
    assert!(error.contains(NAME), "{error}");
    assert!(error.contains("empty secrets are refused"), "{error}");
}

#[test]
fn a2_a_locked_keychain_is_refused_by_name() {
    let fake = Arc::new(FakeKeychain::default());
    fake.fail(NAME, KeychainError::Locked);
    let error = message(resolve(&fake, &format!("keychain:{NAME}")));
    assert!(error.contains(NAME), "{error}");
    assert!(error.contains("locked"), "{error}");
}

#[test]
fn a3_bytes_are_returned_exactly() {
    let fake = Arc::new(FakeKeychain::default());
    fake.insert(NAME, b" a\n");
    assert_eq!(resolve(&fake, &format!("keychain:{NAME}")).unwrap(), " a\n");
}

#[test]
fn a3_bytes_that_are_not_utf8_are_refused() {
    let fake = Arc::new(FakeKeychain::default());
    fake.insert(NAME, &[0xff, 0xfe]);
    let error = message(resolve(&fake, &format!("keychain:{NAME}")));
    assert!(error.contains(NAME), "{error}");
    assert!(error.contains("not UTF-8"), "{error}");
}

#[test]
fn a7_no_refusal_carries_the_value() {
    let other = "mcp-gateway.other.1.0000000000000000";
    let cases: [(&str, Option<KeychainError>); 4] = [
        (other, None),
        (NAME, Some(KeychainError::Locked)),
        (NAME, Some(KeychainError::Timeout)),
        (NAME, Some(KeychainError::NotUtf8)),
    ];
    for (asked, failure) in cases {
        let fake = Arc::new(FakeKeychain::default());
        fake.insert(NAME, SENTINEL.as_bytes());
        if let Some(error) = failure {
            fake.fail(NAME, error);
        }
        let error = resolve(&fake, &format!("keychain:{asked}")).unwrap_err();
        assert!(!error.to_string().contains(SENTINEL), "{error}");
        assert!(!format!("{error:?}").contains(SENTINEL), "{error:?}");
    }
    let wiped = WipedBytes::new(SENTINEL.as_bytes().to_vec());
    assert!(!format!("{wiped:?}").contains(SENTINEL));
}

#[test]
fn a12_an_unsupported_reader_never_yields_the_text() {
    let fake = Arc::new(FakeKeychain::default());
    fake.fail(
        NAME,
        KeychainError::Unavailable("unsupported on this target".to_owned()),
    );
    let result = resolve(&fake, &format!("keychain:{NAME}"));
    assert!(result.is_err(), "resolved to a value");
    let error = message(result);
    assert!(error.contains(FIELD) && error.contains(NAME), "{error}");
}
