// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Key rotation with a grace period (ADR-022): a rotated key keeps its
//! principal, accepts its previous secret until `previous_expires_at` and
//! refuses it after; load refuses a previous digest without an expiry, two
//! keys sharing a principal, and any two equal credential digests.

use chrono::{DateTime, Utc};

use super::ResolvedAuthConfig;
use crate::config::AuthConfig;

/// The secret a key had before its last rotation.
const OLD: &str = "k-rotation-old";
/// The secret it has now.
const NEW: &str = "k-rotation-new";
/// The secret after a second rotation.
const NEWER: &str = "k-rotation-newer";
/// An explicit principal no derived one collides with.
const PRINCIPAL: &str = "a1b2c3d4e5f6";

fn hex_of(key: &str) -> String {
    crate::hashing::sha256_hex(key.as_bytes())
}

fn spec(key: &str) -> String {
    format!("sha256:{}", hex_of(key))
}

/// The grace's end in every clock test.
fn grace_end() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-10-26T12:00:00Z")
        .expect("fixed instant")
        .with_timezone(&Utc)
}

/// A grace still running whenever the wall-clock path judges it.
fn far_future() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2999-01-01T00:00:00Z")
        .expect("fixed instant")
        .with_timezone(&Utc)
}

fn rfc3339(at: DateTime<Utc>) -> String {
    at.to_rfc3339()
}

/// One API key entry: `current` secret, optional (`previous` secret, grace end).
fn key(name: &str, current: &str, previous: Option<(&str, DateTime<Utc>)>) -> serde_json::Value {
    let mut entry = serde_json::json!({
        "name": name,
        "key_sha256": spec(current),
        "backends": ["*"]
    });
    if let Some((secret, until)) = previous {
        entry["previous_key_sha256"] = serde_json::Value::String(spec(secret));
        entry["previous_expires_at"] = serde_json::Value::String(rfc3339(until));
    }
    entry
}

fn with_principal(mut entry: serde_json::Value, principal: &str) -> serde_json::Value {
    entry["principal"] = serde_json::Value::String(principal.to_owned());
    entry
}

fn auth(keys: &[serde_json::Value], bearer: Option<&str>) -> AuthConfig {
    let mut value = serde_json::json!({ "enabled": true, "api_keys": keys });
    if let Some(token) = bearer {
        value["bearer_token"] = serde_json::Value::String(token.to_owned());
    }
    serde_json::from_value(value).expect("auth config fixture deserializes")
}

fn resolve(config: &AuthConfig) -> crate::Result<ResolvedAuthConfig> {
    ResolvedAuthConfig::try_from_config(
        config,
        &crate::config::EnvOverlay::none(),
        crate::gateway::record_principal::TEST_RECORD_KEY,
    )
}

fn resolved(keys: &[serde_json::Value]) -> ResolvedAuthConfig {
    resolve(&auth(keys, None)).expect("resolves")
}

/// Every load-time refusal the config path applies, in its order
/// (config validation, then resolution), as one message.
fn load_refusal(config: &AuthConfig) -> Option<String> {
    let overlay = crate::config::EnvOverlay::none();
    config
        .validate_api_key_material(&overlay)
        .and_then(|()| config.validate_distinct_principals(&overlay))
        .and_then(|()| resolve(config).map(|_| ()))
        .err()
        .map(|error| error.to_string())
}

fn accepted_at(config: &ResolvedAuthConfig, token: &str, now: DateTime<Utc>) -> bool {
    config.validate_token_at(token, now).is_some()
}

// ROT.1: the previous secret works until the grace ends and not from then on.
#[test]
fn previous_secret_is_accepted_until_its_grace_ends() {
    let config = resolved(&[key("ops", NEW, Some((OLD, grace_end())))]);
    let second = crate::duration_bound::delta!(seconds, 1);
    assert!(accepted_at(&config, OLD, grace_end() - second));
    assert!(!accepted_at(&config, OLD, grace_end()));
    assert!(!accepted_at(&config, OLD, grace_end() + second));
}

// ROT.1: both expiries share one boundary, judged at exactly the instant.
#[test]
fn key_expiry_and_grace_expiry_share_one_boundary() {
    fn refused_at_exactly(config: &ResolvedAuthConfig, token: &str, at: DateTime<Utc>) {
        assert!(accepted_at(
            config,
            token,
            at - crate::duration_bound::delta!(seconds, 1)
        ));
        assert!(!accepted_at(config, token, at), "refused at exactly {at}");
    }
    let rotated = resolved(&[key("ops", NEW, Some((OLD, grace_end())))]);
    refused_at_exactly(&rotated, OLD, grace_end());
    let mut expiring = key("ops", NEW, None);
    expiring["expires_at"] = serde_json::Value::String(rfc3339(grace_end()));
    refused_at_exactly(&resolved(&[expiring]), NEW, grace_end());
}

// ROT.1: the key's lifetime and the grace are separate.
#[test]
fn current_secret_outlives_the_grace_and_the_key_expiry_ends_both() {
    let config = resolved(&[key("ops", NEW, Some((OLD, grace_end())))]);
    assert!(accepted_at(
        &config,
        NEW,
        grace_end() + crate::duration_bound::delta!(hours, 1)
    ));

    let key_end = grace_end() - crate::duration_bound::delta!(minutes, 5);
    let mut entry = key("ops", NEW, Some((OLD, grace_end())));
    entry["expires_at"] = serde_json::Value::String(rfc3339(key_end));
    let config = resolved(&[entry]);
    assert!(!accepted_at(&config, NEW, key_end));
    assert!(
        !accepted_at(&config, OLD, key_end),
        "inside the grace, past the key's own expiry"
    );
}

// ROT.2: a previous digest without its expiry never loads.
#[test]
fn previous_digest_without_expiry_is_refused_at_load() {
    let mut entry = key("ops", NEW, None);
    entry["previous_key_sha256"] = serde_json::Value::String(spec(OLD));
    let refusal = load_refusal(&auth(&[entry], None)).expect("refused");
    assert!(
        refusal.contains("ops") && refusal.contains("previous_expires_at"),
        "names the key and the missing field: {refusal}"
    );
}

// ROT.2: an expiry with no previous digest cannot keep a secret valid; it loads.
#[test]
fn grace_end_without_previous_digest_loads() {
    let mut entry = key("ops", NEW, None);
    entry["previous_expires_at"] = serde_json::Value::String(rfc3339(grace_end()));
    assert_eq!(load_refusal(&auth(&[entry], None)), None);
}

// ROT.3 (guard): a key with no previous digest refuses the old secret, even
// while another key in the table has one.
#[test]
fn key_after_a_leak_refuses_the_old_secret() {
    let config = resolved(&[
        key("leaked", NEW, None),
        key("other", NEWER, Some(("k-other-old", grace_end()))),
    ]);
    assert!(!accepted_at(
        &config,
        OLD,
        grace_end() - crate::duration_bound::delta!(hours, 1)
    ));
    assert!(accepted_at(
        &config,
        NEW,
        grace_end() - crate::duration_bound::delta!(hours, 1)
    ));
}

// ROT.4: a second rotation replaces the previous digest, ending the first grace.
#[test]
fn second_rotation_ends_the_first_grace() {
    let config = resolved(&[key("ops", NEWER, Some((NEW, grace_end())))]);
    let inside = grace_end() - crate::duration_bound::delta!(minutes, 1);
    assert!(!accepted_at(&config, OLD, inside));
    assert!(accepted_at(&config, NEW, inside));
    assert!(accepted_at(&config, NEWER, inside));
}

// ROT.5 (a) and ROT.10: both secrets resolve to the explicit principal and the
// same quota bucket.
#[test]
fn both_secrets_resolve_to_the_explicit_principal() {
    let config = resolved(&[with_principal(
        key("ops", NEW, Some((OLD, grace_end()))),
        PRINCIPAL,
    )]);
    let inside = grace_end() - crate::duration_bound::delta!(minutes, 1);
    let current = config
        .validate_token_at(NEW, inside)
        .expect("current secret");
    let previous = config
        .validate_token_at(OLD, inside)
        .expect("previous secret");
    assert_eq!(current.principal.storage_form(), PRINCIPAL);
    assert_eq!(previous.principal.storage_form(), PRINCIPAL);
    assert_eq!(current.quota_principal, previous.quota_principal);
}

// ROT.10: the provenance says which of the key's digests matched.
#[test]
fn provenance_records_a_previous_secret_match() {
    let config = resolved(&[key("ops", NEW, Some((OLD, far_future())))]);
    let (_, current) = config
        .validate_token_with_origin(NEW)
        .expect("current secret");
    let (_, previous) = config
        .validate_token_with_origin(OLD)
        .expect("previous secret");
    let current = current.expect("an API key");
    let previous = previous.expect("an API key");
    assert!(!current.matched_previous_digest());
    assert!(previous.matched_previous_digest());
    assert_eq!(previous.name(), "ops");
}

// ROT.6: a rotated key's event watches still find it by its principal.
#[test]
fn client_for_key_finds_a_rotated_key_by_its_principal() {
    let config = resolved(&[with_principal(
        key("ops", NEW, Some((OLD, grace_end()))),
        PRINCIPAL,
    )]);
    let inside = grace_end() - crate::duration_bound::delta!(minutes, 1);
    assert!(config.client_for_key("ops", PRINCIPAL).is_some());
    assert!(config.client_for_key_at("ops", PRINCIPAL, inside).is_some());
    let derived = hex_of(NEW)[..12].to_owned();
    assert!(
        config.client_for_key("ops", &derived).is_none(),
        "the digest prefix is no longer the key's principal"
    );
}

// ROT.5 (b): no code derives a configured key's principal by slicing a digest
// outside the one function in auth.rs. Whitespace is removed first, so a slice
// split across lines is still seen; each cfg(test) item is left out.
#[test]
fn no_digest_prefix_slice_outside_auth_rs() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("src is readable") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let rel = path.strip_prefix(&root).expect("under src");
            let name = rel.to_string_lossy().replace('\\', "/");
            let is_rust = path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"));
            if !is_rust || name == "gateway/auth.rs" || name.ends_with("_tests.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("source is readable");
            if derives_digest_principal(&text) {
                offenders.push(format!("src/{name}"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "digest-prefix principals outside auth.rs: {offenders:?}"
    );
    // Control: the scan sees the one derivation it exempts.
    let own = std::fs::read_to_string(root.join("gateway/auth.rs")).expect("auth.rs is readable");
    assert!(DIGEST_SHAPES.is_match(&own.split_whitespace().collect::<String>()));
}

/// A 6-byte prefix of anything named for a digest, or 12 hex characters of an
/// encoded hash: the two shapes a digest-derived principal takes.
static DIGEST_SHAPES: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"(?i)digest\w*\)?\[0?\.\.6\]|(sha256_hex|encode)\(.{0,80}?\)\[0?\.\.12\]")
        .expect("pattern compiles")
});

/// Whether a source file's production code derives a principal from a digest
/// prefix. Each `#[cfg(test)]` item is left out by its own extent, and
/// whitespace is removed, so a slice split across lines is still seen.
fn derives_digest_principal(text: &str) -> bool {
    let compact: String = crate::test_source_text::production_text(text)
        .split_whitespace()
        .collect();
    DIGEST_SHAPES.is_match(&compact)
}

/// A digest slice after an early test module is production code and counts.
#[test]
fn a_digest_slice_after_an_early_test_module_counts() {
    let source = "#[cfg(test)]\nmod early {\n    fn t() {}\n}\n\nfn principal(digest: &[u8]) -> &[u8] {\n    &digest[..6]\n}\n";
    assert!(derives_digest_principal(source));
}

// ROT.7: two keys cannot share a principal through an explicit one.
#[test]
fn explicit_principals_cannot_collide() {
    let twins = auth(
        &[
            with_principal(key("a", NEW, None), PRINCIPAL),
            with_principal(key("b", NEWER, None), PRINCIPAL),
        ],
        None,
    );
    assert!(
        load_refusal(&twins).is_some(),
        "two keys, one explicit principal"
    );

    let derived = hex_of(NEW)[..12].to_owned();
    let shadow = auth(
        &[
            key("a", NEW, None),
            with_principal(key("b", NEWER, None), &derived),
        ],
        None,
    );
    assert!(
        load_refusal(&shadow).is_some(),
        "an explicit principal equal to another key's derived one"
    );

    let bearer = "bearer-for-rotation-tests";
    let bearer_principal = hex_of(bearer)[..12].to_owned();
    let takes_bearer = auth(
        &[with_principal(key("a", NEW, None), &bearer_principal)],
        Some(bearer),
    );
    assert!(
        load_refusal(&takes_bearer).is_some(),
        "an explicit principal equal to the bearer's"
    );
}

// ROT.8: no two credential digests are equal. Distinct explicit principals in
// every case, so only the digest rule can refuse it.
#[test]
fn equal_credential_digests_are_refused() {
    let p = |entry, suffix: &str| with_principal(entry, &format!("{}{suffix}", &PRINCIPAL[..10]));
    let cases = [
        (
            "current = another key's previous",
            vec![
                p(key("a", NEW, None), "01"),
                p(key("b", NEWER, Some((NEW, grace_end()))), "02"),
            ],
        ),
        (
            "two equal previous digests",
            vec![
                p(key("a", NEW, Some((OLD, grace_end()))), "01"),
                p(key("b", NEWER, Some((OLD, grace_end()))), "02"),
            ],
        ),
        (
            "previous = own current",
            vec![p(key("a", NEW, Some((NEW, grace_end()))), "01")],
        ),
    ];
    for (case, keys) in cases {
        assert!(load_refusal(&auth(&keys, None)).is_some(), "{case}");
    }

    let bearer = "bearer-for-rotation-tests";
    let current_is_bearer = auth(&[p(key("a", bearer, None), "01")], Some(bearer));
    assert!(
        load_refusal(&current_is_bearer).is_some(),
        "a key's current digest = the bearer's"
    );
    let previous_is_bearer = auth(
        &[p(key("a", NEW, Some((bearer, grace_end()))), "01")],
        Some(bearer),
    );
    assert!(
        load_refusal(&previous_is_bearer).is_some(),
        "a key's previous digest = the bearer's"
    );

    // The same two cases for an `auto` bearer, which exists only once it is
    // generated at resolution: the generated token is fixed so a key can equal it.
    let auto_cases = [
        (
            "a key's current digest = the auto bearer's",
            key("a", bearer, None),
        ),
        (
            "a key's previous digest = the auto bearer's",
            key("a", NEW, Some((bearer, grace_end()))),
        ),
    ];
    for (case, entry) in auto_cases {
        let config = auth(&[p(entry, "01")], Some("auto"));
        let refusal = super::resolved::with_auto_bearer(bearer, || load_refusal(&config));
        assert!(refusal.is_some(), "{case}");
        let control =
            super::resolved::with_auto_bearer("another-auto-bearer", || load_refusal(&config));
        assert_eq!(control, None, "control, {case}: no collision, no refusal");
    }
}

// ROT.8 (guard): with no explicit principal, a key equal to the bearer already
// collides on principal and is refused today.
#[test]
fn key_equal_to_bearer_without_explicit_principal_is_refused() {
    let bearer = "bearer-for-rotation-tests";
    assert!(load_refusal(&auth(&[key("a", bearer, None)], Some(bearer))).is_some());
}

// ROT.9: the dummy digest stands in for a key with no previous secret and can
// never authenticate. Pointing the dummy at a known token's digest proves the
// mask, not the improbability of a preimage, keeps it out.
#[test]
fn dummy_digest_never_authenticates() {
    let token = "k-equal-to-the-dummy";
    let digest: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(token.as_bytes()).into();
    let config = resolved(&[key("ops", NEW, None)]);
    super::resolved::with_dummy_digest(digest, || {
        assert!(
            !accepted_at(&config, token, grace_end()),
            "the dummy matched"
        );
    });
}

// The Debug form never renders a digest or the principal.
#[test]
fn debug_output_renders_no_digest() {
    let config = resolved(&[with_principal(
        key("ops", NEW, Some((OLD, grace_end()))),
        PRINCIPAL,
    )]);
    let rendered = format!("{config:?}");
    for secret in [hex_of(NEW), hex_of(OLD), PRINCIPAL.to_owned()] {
        assert!(
            !rendered.contains(&secret),
            "Debug leaks {secret}: {rendered}"
        );
    }
}

// D1 (guard): deriving Default made no field optional: a key entry with a name
// and no digest is still refused at load.
#[test]
fn key_entry_without_digest_is_refused() {
    let config = auth(
        &[serde_json::json!({ "name": "ops", "backends": ["*"] })],
        None,
    );
    let refusal = load_refusal(&config).expect("refused");
    assert!(refusal.contains("has no key_sha256"), "{refusal}");
}

// ROT.1: a previous secret is refused when the clock cannot be read, while a
// key with no expiry still needs no clock. The readable-clock half is the
// control: without it, a matcher that never accepts a previous secret passes.
#[test]
fn previous_secret_is_refused_on_an_unreadable_clock() {
    let config = resolved(&[key("ops", NEW, Some((OLD, far_future())))]);
    assert!(
        config.validate_token(OLD).is_some(),
        "control: readable clock"
    );
    let _clock = crate::clock::test_clock::before_epoch();
    assert!(
        config.validate_token(OLD).is_none(),
        "previous secret, clock before 1970"
    );
    assert!(
        config.validate_token(NEW).is_some(),
        "current secret needs no clock"
    );
}

// ROT.1: the wall-clock path judges the key's expiry and the grace at one clock
// reading. The second queued read falls after the grace; a path that read the
// clock again for the grace would refuse the previous secret.
#[test]
fn key_expiry_and_grace_are_judged_at_one_clock_reading() {
    let mut entry = key("ops", NEW, Some((OLD, grace_end())));
    entry["expires_at"] = serde_json::Value::String(rfc3339(far_future()));
    let config = resolved(&[entry]);
    let end = u64::try_from(grace_end().timestamp()).expect("after 1970");
    let _clock = crate::clock::test_clock::queued(&[Some(end - 1), Some(end + 1)]);
    assert!(
        config.validate_token(OLD).is_some(),
        "the grace is judged at the reading the key's expiry used"
    );
}

// The load-path twin of the re-issue pin (auth_tests): a key re-issued under
// its old name with a new secret and no rotation fields is another caller, so
// it inherits neither the old principal (its grants, sessions and tasks) nor
// its quota bucket, and the old principal no longer finds a key.
#[test]
fn a_reissued_key_loaded_from_config_is_another_caller() {
    let before = resolved(&[key("ops", OLD, None)]);
    let after = resolved(&[key("ops", NEW, None)]);
    let old_caller = before.validate_token(OLD).expect("the original key");
    let new_caller = after.validate_token(NEW).expect("the re-issued key");
    assert_ne!(
        old_caller.principal.storage_form(),
        new_caller.principal.storage_form()
    );
    assert_ne!(old_caller.quota_principal, new_caller.quota_principal);
    assert!(
        after.validate_token(OLD).is_none(),
        "the old secret is gone"
    );
    assert!(
        after
            .client_for_key("ops", old_caller.principal.storage_form())
            .is_none(),
        "a watch stored under the old principal does not follow the name"
    );
}
