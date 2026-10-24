// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8697 leak rows L1-L3 (lead, 2026-10-24): an idempotency or cache key
//! ends in the caller's stored principal, and the auth Debug output used to
//! name its digest. None of them may print it. Each row is red on f547571b3.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use crate::idempotency::{GuardOutcome, IdempotencyCache, enforce};

/// A stored principal, as a credential caller's keys carry it.
const P: &str = "c0ffee5eed42";

/// An idempotency or cache key ending in [`P`], in the `|cred:<len>:<p>`
/// form the caller principal suffix takes.
fn key() -> String {
    format!("3:abc|cred:12:{P}")
}

fn captured(run: impl FnOnce()) -> String {
    crate::test_log_capture::records(run)
        .iter()
        .map(serde_json::Value::to_string)
        .collect()
}

/// L1: the in-flight duplicate refusal keeps its prefix and names no key.
#[test]
fn l1_the_duplicate_refusal_names_no_principal() {
    let cache = Arc::new(IdempotencyCache::new());
    let GuardOutcome::Proceed(_held) = enforce(&cache, &key(), "fp").expect("first") else {
        panic!("the first caller is admitted");
    };
    let Err(refusal) = enforce(&cache, &key(), "fp") else {
        panic!("the duplicate is refused");
    };
    let refusal = refusal.to_string();
    assert!(
        refusal.contains("Duplicate request in progress for key:"),
        "premise: {refusal}"
    );
    assert!(
        !refusal.contains(P),
        "the refusal names the principal: {refusal}"
    );
    // The same key for another request while the first is in flight: the
    // mismatch refusal names no key either.
    let Err(mismatch) = enforce(&cache, &key(), "other-fp") else {
        panic!("a reused key is refused");
    };
    let mismatch = mismatch.to_string();
    assert!(
        mismatch.contains("already in use for a different request"),
        "premise: {mismatch}"
    );
    assert!(!mismatch.contains(P), "the mismatch names it: {mismatch}");
}

/// L2: the abandoned-reservation and cache-refusal DEBUG lines name no key.
#[test]
fn l2_idempotency_and_cache_debug_lines_name_no_principal() {
    let text = captured(|| {
        let cache = Arc::new(IdempotencyCache::new());
        let GuardOutcome::Proceed(held) = enforce(&cache, &key(), "fp").expect("first") else {
            panic!("the first caller is admitted");
        };
        drop(held);
        let responses = crate::cache::ResponseCache::new();
        let ttl = Duration::from_secs(60);
        assert!(!responses.set(&key(), json!({"isError": true, "content": []}), ttl));
        assert!(!responses.set(&key(), json!({"resultType": "input_required"}), ttl));
    });
    for line in [
        "Released abandoned idempotency reservation",
        "Refused to cache an error result",
        "Refused to cache a non-final result",
    ] {
        assert!(text.contains(line), "premise, {line}: {text}");
    }
    assert!(
        !text.contains(P),
        "a DEBUG line names the principal: {text}"
    );
}

/// L3: the auth config's Debug output and the auto-bearer startup line name
/// no credential digest.
#[test]
fn l3_auth_diagnostics_name_no_credential_digest() {
    const BEARER: &str = "canary-bearer-secret-0123456789";
    const API_KEY: &str = "canary-api-key-0123456789";
    let yaml = format!(
        "enabled: true\nbearer_token: \"{BEARER}\"\napi_keys:\n  - name: c\n    key_sha256: \"{}\"\n    backends: [\"*\"]\n",
        crate::config::api_key_digest_spec(API_KEY.as_bytes())
    );
    let auth: crate::config::AuthConfig = crate::yaml::from_str(&yaml).expect("auth yaml");
    let resolved = crate::gateway::ResolvedAuthConfig::from_config(
        &auth,
        crate::gateway::record_principal::TEST_RECORD_KEY,
    );
    let shown = format!("{resolved:?}");
    let bearer = crate::gateway::auth::principal_of(BEARER);
    let digest = &crate::hashing::sha256_hex(API_KEY.as_bytes())[..12];
    assert!(shown.contains("<redacted"), "premise: {shown}");
    assert!(!shown.contains(bearer.storage_form()), "{shown}");
    assert!(!shown.contains(digest), "{shown}");

    let auto_config: crate::config::AuthConfig =
        crate::yaml::from_str("enabled: true\nbearer_token: auto\n").expect("auto yaml");
    let mut generated = None;
    let text = captured(|| {
        generated = crate::gateway::ResolvedAuthConfig::from_config(
            &auto_config,
            crate::gateway::record_principal::TEST_RECORD_KEY,
        )
        .bearer_token;
    });
    let token = generated.expect("a generated bearer");
    assert!(
        text.contains("Auto-generated bearer token"),
        "premise: {text}"
    );
    let token_principal = crate::gateway::auth::principal_of(&token);
    assert!(!text.contains(token_principal.storage_form()), "{text}");
    assert!(!text.contains(&token), "{text}");
}

/// L4 (gpt confirmation round): the Debug output of the types holding a
/// stored principal, or a key or binding built from one, names none of it.
#[test]
fn l4_debug_output_names_no_principal_or_derived_key() {
    let api_key = crate::events::ApiKeyRef {
        name: "c".to_owned(),
        principal: P.to_owned(),
    };
    let credential = crate::events::Credential {
        kind: crate::security::audit::CredentialKind::StaticBearer,
        principal: P.to_owned(),
        api_key: Some(api_key.clone()),
        expires_at: None,
        binding: Some(crate::events::LiveBinding::StaticBearerSha256 {
            bearer_sha256: format!("{P}{P}"),
        }),
    };
    let evidence = crate::security::tenant_reads::RejectionEvidence {
        caller_key: Some(key()),
        verdict: crate::security::tenant_reads::ReadVerdict::Blocked,
        attribution: crate::security::tenant_reads::ReadAttribution::of(
            std::collections::BTreeSet::new(),
            false,
        ),
    };
    let cache = Arc::new(IdempotencyCache::new());
    let GuardOutcome::Proceed(held) = enforce(&cache, &key(), "fp").expect("first") else {
        panic!("the first caller is admitted");
    };
    for shown in [
        format!("{api_key:?}"),
        format!("{credential:?}"),
        format!("{evidence:?}"),
        format!("{held:?}"),
        format!("{cache:?}"),
    ] {
        assert!(
            shown.contains("<redacted>") || shown.contains("entries"),
            "premise: {shown}"
        );
        assert!(!shown.contains(P), "Debug names the principal: {shown}");
    }
}
