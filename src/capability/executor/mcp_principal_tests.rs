// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7825: which child an MCP call gets, and when a full pool refuses.
//!
//! BUSY.1: sixteen children of one capability all mid-call refuse a
//! seventeenth caller, and the pool takes callers again once one frees.
//! PRINCIPAL.2: an API-key caller on a multi-user gateway, named by nothing but
//! its credential digest, gets its own child instead of a refusal.

use std::sync::atomic::Ordering;

use serde_json::json;

use super::tests::{call, caller, capability, capability_yaml};
use super::{MAX_CHILDREN_PER_CAPABILITY, principal};
use crate::capability::executor::CapabilityExecutor;
use crate::capability::{CapabilityExecutionContext, parse_capability};
use crate::identity_grants::GrantSubject;
use crate::identity_propagation::CallerProvenance;

/// A caller that presented an API key and nothing else.
fn api_key(digest: &str) -> CapabilityExecutionContext {
    CapabilityExecutionContext {
        credential_principal: Some(digest.to_owned()),
        caller_provenance: CallerProvenance::Credential,
        ..CapabilityExecutionContext::default()
    }
}

fn multi_user() -> CapabilityExecutor {
    let executor = CapabilityExecutor::new();
    executor.multi_user.store(true, Ordering::Release);
    executor
}

/// BUSY.1: no idle child to evict means a refusal, never a seventeenth child.
#[tokio::test]
async fn a_pool_of_busy_children_refuses_the_next_caller_until_one_frees() {
    let executor = CapabilityExecutor::new();
    let cap = capability();
    let say = json!({"operation": "say", "text": "x"});
    for n in 0..MAX_CHILDREN_PER_CAPABILITY {
        call(
            &executor,
            &cap,
            say.clone(),
            &caller(&format!("caller-{n}")),
        )
        .await
        .unwrap();
    }
    let held = executor.mcp_children.hold_for_test("every child");
    assert_eq!(held.len(), MAX_CHILDREN_PER_CAPABILITY, "all sixteen held");
    let err = call(&executor, &cap, say.clone(), &caller("late"))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains(&format!(
            "already serves {MAX_CHILDREN_PER_CAPABILITY} busy callers"
        )),
        "{err}"
    );
    assert_eq!(executor.mcp_children.len(), MAX_CHILDREN_PER_CAPABILITY);
    drop(held);
    call(&executor, &cap, say, &caller("later"))
        .await
        .expect("a freed child makes room again");
}

/// PRINCIPAL.2: two API keys, two children; the same key twice, one.
#[tokio::test]
async fn api_key_callers_get_their_own_children_on_a_multi_user_gateway() {
    let executor = multi_user();
    let cap = capability();
    let say = json!({"operation": "say", "text": "x"});
    let a1 = call(&executor, &cap, say.clone(), &api_key("digest-a"))
        .await
        .expect("an API-key caller is served on a multi-user gateway");
    let a2 = call(&executor, &cap, say.clone(), &api_key("digest-a"))
        .await
        .unwrap();
    let b = call(&executor, &cap, say, &api_key("digest-b"))
        .await
        .unwrap();
    assert_eq!(a1["pid"], a2["pid"], "one key reuses its child");
    assert_ne!(a1["pid"], b["pid"], "another key gets another child");
    assert_ne!(a1["cwd"], b["cwd"], "and another directory");
}

/// The credential arm's exact key: tagged and length-prefixed, the spelling
/// the response cache uses for the same caller.
#[test]
fn a_credential_digest_keys_the_child_as_cred() {
    let key = principal(&capability(), &api_key("abc"), true).expect("named by its digest");
    assert_eq!(key, "cred:3:abc");
}

/// The arms above the credential still win, in their order.
#[test]
fn a_binding_or_a_grant_subject_beats_the_credential_digest() {
    let cap = capability();
    let bound = CapabilityExecutionContext {
        cache_binding: Some("bind".to_owned()),
        ..api_key("abc")
    };
    assert_eq!(principal(&cap, &bound, true).unwrap(), "idp:4:bind");
    let granted = CapabilityExecutionContext {
        caller_identity: Some(GrantSubject::new("test", "alice", None)),
        ..api_key("abc")
    };
    let grant_only = caller("alice");
    assert_eq!(
        principal(&cap, &granted, true).unwrap(),
        principal(&cap, &grant_only, true).unwrap()
    );
}

/// Control: an empty digest names no one, so a multi-user gateway still refuses.
#[test]
fn an_empty_digest_is_still_refused_on_a_multi_user_gateway() {
    let err = principal(&capability(), &api_key(""), true).unwrap_err();
    assert!(err.to_string().contains("identified caller"), "{err}");
}

/// T10: a verified identity beats the credential owner, as it does today.
#[test]
fn a_verified_identity_beats_the_credential_owner() {
    let identity = std::sync::Arc::new(crate::key_server::oidc::VerifiedIdentity {
        subject: "alice".to_owned(),
        email: "alice@example.test".to_owned(),
        name: None,
        groups: Vec::new(),
        issuer: "https://idp.example.test".to_owned(),
    });
    let verified = CapabilityExecutionContext {
        verified_identity: Some(std::sync::Arc::clone(&identity)),
        ..api_key("credential:5e1f0a2b3c4d")
    };
    assert_eq!(
        principal(&capability(), &verified, true).unwrap(),
        identity.stable_actor_id()
    );
}

/// D7: a cached MCP answer is read back only by the caller whose child gave
/// it. Two API keys, the same arguments: the second key gets its own child's
/// answer, not the first key's cached one.
#[tokio::test]
async fn a_cached_mcp_answer_is_served_only_to_the_key_that_produced_it() {
    let executor = multi_user();
    let yaml = capability_yaml().replacen(
        "description: MCP probe.\n",
        "description: MCP probe.\ncache:\n  ttl: 60\n  strategy: memory\n",
        1,
    );
    let cap = parse_capability(&yaml).expect("cacheable probe parses");
    assert!(cap.is_cacheable(), "premise: the probe caches");
    let say = json!({"operation": "say", "text": "x"});
    let run =
        |owner: &'static str| executor.execute_with_context(&cap, say.clone(), api_key(owner));
    let first = run("credential:1d2c3b4a5f6e")
        .await
        .expect("first key served");
    let again = run("credential:1d2c3b4a5f6e").await.unwrap();
    let other = run("credential:9e8d7c6b5a4f")
        .await
        .expect("second key served");
    assert_eq!(first, again, "one key reads its own answer back");
    assert!(first["pid"].is_i64(), "the probe reports its pid: {first}");
    assert_ne!(
        first["pid"], other["pid"],
        "another key never reads the first key's answer"
    );
}
