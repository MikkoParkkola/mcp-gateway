// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The retry key names the same caller the response cache names.
//!
//! A deployment that identifies callers by mTLS certificate, trusted headers
//! or an OAuth agent — with identity propagation off and no OIDC, the shipped
//! default — has only the caller's `GrantSubject` to tell two callers apart.
//! The response cache keys on it; the retry key must too, or two such callers
//! sending one client key share one stored result.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::authz_tests::{counted_backend, ctx, invoke_args};
use crate::gateway::meta_mcp::{MetaMcp, MetaMcpCallerContext};
use crate::identity_grants::GrantSubject;

#[tokio::test]
async fn a_second_grant_subject_is_not_served_the_firsts_idempotent_result() {
    let (registry, calls) = counted_backend("alpha");
    // No response cache: only the idempotency layer can separate or
    // de-duplicate these calls.
    let mut meta = MetaMcp::new(registry);
    meta.enable_idempotency(
        Arc::new(crate::idempotency::IdempotencyCache::new()),
        Duration::from_secs(300),
    );

    let retry = crate::protocol::mrtr::RetryFields {
        input_responses: None,
        request_state: None,
        idempotency_key: Some("one-key-both-callers".to_string()),
        malformed: Vec::new(),
        attestation: None,
    };
    let alice = GrantSubject::new("mtls", "spiffe://example.test/alice", None);
    let bob = GrantSubject::new("mtls", "spiffe://example.test/bob", None);
    let args = invoke_args("alpha", "read");
    let as_caller = |subject: &GrantSubject| MetaMcpCallerContext {
        grant_subject: Some(subject.clone()),
        retry: &retry,
        ..ctx(&AllowAll)
    };

    let first = meta.invoke_tool(&args, None, &as_caller(&alice)).await;
    assert!(first.is_ok(), "the first call must succeed: {first:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "and must reach the backend"
    );

    let second = meta.invoke_tool(&args, None, &as_caller(&bob)).await;
    assert!(second.is_ok(), "the second call must succeed: {second:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "bob was served alice's stored result — the caller's grant subject is \
         not reaching the retry key"
    );

    // The key is live, so the separation above cannot be idempotency being
    // inert: alice repeating her own call is de-duplicated.
    let repeat = meta.invoke_tool(&args, None, &as_caller(&alice)).await;
    assert!(repeat.is_ok(), "alice's repeat must succeed: {repeat:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "alice's own repeat reached the backend again — idempotency is inert \
         here, and the separation assertion above proved nothing"
    );
}
