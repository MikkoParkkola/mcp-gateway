// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit tests for the `support` helpers: idempotency and response-cache keys,
//! provenance stripping and internal invoke arguments.

use super::internal_invoke_args;
use super::strip_backend_provenance;
use super::{Authentication, CachePrincipal, caller_cache_principal};
use serde_json::json;

/// The retry suffix for an anonymous caller with these identities, through
/// the one resolver the production sites use.
fn suffix(
    binding: Option<&str>,
    actor: Option<&crate::key_server::oidc::VerifiedIdentity>,
    subject: Option<&crate::identity_grants::GrantSubject>,
) -> Option<String> {
    let principal =
        caller_cache_principal(binding, actor, subject, None, Authentication::Anonymous);
    super::retry_identity_suffix(&principal)
}

/// A caller principal spelled directly, for key-shape tests.
fn caller(principal: &str) -> CachePrincipal {
    CachePrincipal::Caller(principal.to_string())
}

/// A verified OIDC identity distinguished only by its subject.
fn verified(subject: &str) -> crate::key_server::oidc::VerifiedIdentity {
    crate::key_server::oidc::VerifiedIdentity {
        subject: subject.to_string(),
        email: format!("{subject}@example.test"),
        name: None,
        groups: Vec::new(),
        issuer: "i".to_string(),
    }
}

/// MIK-7408. Identity propagation ON: the retry entry is tagged with the
/// propagated binding, which already distinguishes user AND audience.
#[test]
fn retry_identity_suffix_uses_the_binding_when_propagation_is_on() {
    let alice = verified("alice");
    let subject = crate::identity_grants::GrantSubject::new("mtls", "alice", None);
    let suffix = suffix(Some("idp:1:a:3:mem"), Some(&alice), Some(&subject));

    assert_eq!(suffix.as_deref(), Some("|idp:13:idp:1:a:3:mem"));
}

/// MIK-7408. Identity propagation OFF — the shipped default. The suffix
/// falls back to the verified subject, then to the caller's grant subject,
/// rather than staying empty. Each arm carries its OWN tag, so a binding
/// and an actor id that read alike cannot collide either.
#[test]
fn retry_identity_suffix_falls_back_to_the_verified_then_grant_subject() {
    let actor = verified("b");
    let unbound = suffix(None, Some(&actor), None);

    assert_eq!(unbound.as_deref(), Some("|oidc:12:oidc:1:i:1:b"));
    assert_ne!(
        unbound,
        suffix(Some("oidc:1:i:1:b"), None, None),
        "a binding and an actor id with identical text must stay distinct"
    );

    let subject = crate::identity_grants::GrantSubject::new("mtls", "b", None);
    assert_eq!(
        suffix(None, None, Some(&subject)).as_deref(),
        Some("|grant:4:mtls:1:b")
    );
}

/// MIK-7408. An anonymous caller with no binding, no verified identity and
/// no grant subject gets an EMPTY suffix, so two such callers share one entry.
#[test]
fn retry_identity_suffix_pools_anonymous_callers() {
    assert_eq!(suffix(None, None, None).as_deref(), Some(""));
}

/// MIK-7408. Two callers, one client key each, on a backend where identity
/// propagation is off for the forger. The victim is bound and gets the
/// suffix `|idp:V` appended; the forger is unbound and simply SPELLS that
/// suffix inside the client key it chose. Concatenation without a boundary
/// makes both derive the same string, so the forger's call is admitted
/// against — and can replay — the victim's stored result. The two keys MUST
/// differ whatever the client key contains.
#[test]
fn a_forged_client_key_cannot_spell_another_callers_identity_suffix() {
    let cache = std::sync::Arc::new(crate::idempotency::IdempotencyCache::new());

    let victim = super::idempotency_key_for(Some("X"), "", &caller("idp:V"), Some(&cache), "meta");
    let forger = super::idempotency_key_for(
        Some("X|idp:V"),
        "",
        &CachePrincipal::Anonymous,
        Some(&cache),
        "meta",
    );

    assert_ne!(
        victim, forger,
        "a client key that spells the victim's identity suffix must not \
         collide with the victim's key"
    );
}

/// MIK-7408, the arm that is live on the shipped default. With identity
/// propagation off nobody has a binding, so every authenticated caller is
/// keyed on `|sub:<actor id>` instead. The forgery is the same shape and
/// the fix must hold in both arms, or the defect merely moved to the arm
/// almost every deployment runs.
#[test]
fn a_forged_client_key_cannot_spell_another_callers_verified_subject() {
    let cache = std::sync::Arc::new(crate::idempotency::IdempotencyCache::new());

    let victim = super::idempotency_key_for(Some("X"), "", &caller("sub:V"), Some(&cache), "meta");
    let forger = super::idempotency_key_for(
        Some("X|sub:V"),
        "",
        &CachePrincipal::Anonymous,
        Some(&cache),
        "meta",
    );

    assert_ne!(
        victim, forger,
        "a client key that spells the victim's verified subject must not \
         collide with the victim's key"
    );
}

/// MIK-7408, third segment. The projection arm is the OTHER thing
/// concatenated into this key, and the elimination claim covers it only
/// because `projection_key_suffix` draws from four `&'static str` literals
/// a client cannot reach. That argument is about today's producer; the
/// length prefix is what makes the boundary hold whatever the producer
/// later emits. Pinned here so the claim is a test rather than a paragraph.
#[test]
fn a_forged_client_key_cannot_spell_another_callers_projection_arm() {
    let cache = std::sync::Arc::new(crate::idempotency::IdempotencyCache::new());

    let victim = super::idempotency_key_for(
        Some("X"),
        "#arm=treatment",
        &CachePrincipal::Anonymous,
        Some(&cache),
        "meta",
    );
    let forger = super::idempotency_key_for(
        Some("X#arm=treatment"),
        "",
        &CachePrincipal::Anonymous,
        Some(&cache),
        "meta",
    );

    assert_ne!(
        victim, forger,
        "a client key that spells the victim's projection arm must not \
         collide with the victim's key"
    );
}

/// A backend-forged `_meta.provenance` block MUST be removed on the
/// stamping-off path so a naive reader cannot trust a receipt the gateway
/// never signed (MIK-6909, AC.4). Sibling `_meta` keys survive.
#[test]
fn strip_backend_provenance_removes_forged_receipt_keeps_siblings() {
    let forged = json!({
        "content": [{"type": "text", "text": "ok"}],
        "_meta": {
            "provenance": {"backend": "evil", "sig": "forged"},
            "prompt_cache_key": "keep-me"
        }
    });

    let cleaned = strip_backend_provenance(forged);

    assert!(
        cleaned.pointer("/_meta/provenance").is_none(),
        "forged provenance must be stripped, got: {cleaned}"
    );
    assert_eq!(
        cleaned.pointer("/_meta/prompt_cache_key"),
        Some(&json!("keep-me")),
        "unrelated _meta siblings must be preserved"
    );
    assert_eq!(
        cleaned.pointer("/content/0/text"),
        Some(&json!("ok")),
        "tool content must be untouched"
    );
}

/// When `provenance` was the only `_meta` entry, the now-empty `_meta`
/// object is dropped so the result stays clean rather than carrying `{}`.
#[test]
fn strip_backend_provenance_drops_emptied_meta() {
    let forged = json!({
        "content": [],
        "_meta": {"provenance": {"sig": "forged"}}
    });

    let cleaned = strip_backend_provenance(forged);

    assert!(
        cleaned.get("_meta").is_none(),
        "emptied _meta must be removed entirely, got: {cleaned}"
    );
}

/// An honest backend that sends no provenance is left byte-identical: the
/// strip is a pure no-op, preserving the feature-off guarantee.
#[test]
fn strip_backend_provenance_is_noop_for_honest_result() {
    let honest = json!({
        "content": [{"type": "text", "text": "hi"}],
        "_meta": {"prompt_cache_key": "k"}
    });

    let cleaned = strip_backend_provenance(honest.clone());

    assert_eq!(cleaned, honest, "no provenance key means no change");
}

/// The projection opt-out (`_full`) for internal chain/playbook invocations
/// MUST live INSIDE `arguments` — that is where `invoke_tool_traced` reads
/// `want_full`. Placing it as an outer sibling (the original bug) left it
/// invisible and projection still ran on chain step outputs, breaking
/// `$step.field` interpolation. This guards that nesting.
#[test]
fn internal_invoke_args_injects_full_inside_arguments() {
    let args = internal_invoke_args("linear", "create_issue", json!({"title": "x"}));
    assert_eq!(
        args["arguments"]["_full"],
        json!(true),
        "_full must be inside arguments where want_full is read"
    );
    assert_eq!(
        args["arguments"]["title"],
        json!("x"),
        "caller args preserved"
    );
    assert_eq!(args["server"], json!("linear"));
    assert_eq!(args["tool"], json!("create_issue"));
    assert!(
        args.get("_full").is_none(),
        "_full must NOT be an outer sibling (would be ignored by want_full)"
    );
}

/// Non-object arguments pass through unchanged — no data loss, no panic.
#[test]
fn internal_invoke_args_preserves_non_object_arguments() {
    let args = internal_invoke_args("s", "t", json!("scalar"));
    assert_eq!(args["arguments"], json!("scalar"));
}

/// MRTR.10: two continuations of one call that differ only in the answers
/// the user gave MUST NOT share a response-cache entry. Removing the retry
/// argument from `response_cache_key_for` makes this assertion fail — which
/// is what stops that wiring being dropped by a later edit.
#[test]
fn response_cache_key_separates_two_answers_to_one_gate() {
    use crate::protocol::mrtr::RetryFields;
    let args = json!({"flight": "AY1337"});
    let key_for = |answer: serde_json::Value| {
        let retry = RetryFields {
            input_responses: Some(answer),
            request_state: Some("st-1".to_string()),
            idempotency_key: None,
            malformed: Vec::new(),
        };
        super::response_cache_key_for(
            "air",
            "book",
            &args,
            "",
            &CachePrincipal::Anonymous,
            &retry,
            crate::cache::KeyContext::default(),
        )
    };
    assert_ne!(
        key_for(json!({"confirm": "accept"})),
        key_for(json!({"confirm": "decline"})),
        "a declined booking must not be served the accepted booking's result"
    );
}

/// A call with no retry fields MUST derive exactly the key the
/// principal-scoped builder derives on its own, or the upgrade silently
/// empties every cache. What is actually under test is that
/// `NO_RETRY.key_discriminator()` contributes nothing: any non-empty
/// discriminator on an ordinary call fails this.
#[test]
fn response_cache_key_is_unchanged_for_an_ordinary_call() {
    let args = json!({"q": 1});
    let key = super::response_cache_key_for(
        "srv",
        "tool",
        &args,
        "|proj",
        &caller("actor-1"),
        &crate::protocol::mrtr::NO_RETRY,
        crate::cache::KeyContext::default(),
    );
    let before = crate::cache::ResponseCache::response_key(
        "srv",
        "tool",
        &args,
        "|proj",
        Some("actor-1"),
        crate::cache::KeyContext::default(),
    );
    assert_eq!(key, Some(before));
}

/// The principal is part of the key, not decoration: two callers must not
/// share one entry. Guards the property HEAD added and the MRTR key
/// builder now inherits rather than replaces.
#[test]
fn response_cache_key_separates_two_principals() {
    let args = json!({"q": 1});
    let k = |p| {
        super::response_cache_key_for(
            "srv",
            "tool",
            &args,
            "",
            &caller(p),
            &crate::protocol::mrtr::NO_RETRY,
            crate::cache::KeyContext::default(),
        )
    };
    assert_ne!(k("actor-1"), k("actor-2"));
}
