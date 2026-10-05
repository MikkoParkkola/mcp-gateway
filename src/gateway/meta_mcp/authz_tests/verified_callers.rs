// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7408: idempotent results are not shared between verified callers.

use super::*;

/// A verified OIDC identity distinguished only by its subject.
fn verified(subject: &str) -> crate::key_server::oidc::VerifiedIdentity {
    crate::key_server::oidc::VerifiedIdentity {
        subject: subject.to_string(),
        email: format!("{subject}@example.test"),
        name: None,
        groups: Vec::new(),
        issuer: "https://issuer.example.test".to_string(),
    }
}

/// MIK-7408, production path. The helper-level forgery tests pin how the
/// retry key is COMPOSED; none of them pins that `invoke_tool` still hands the
/// identity to the composer. A wiring regression there is invisible to all of
/// them and visible here.
///
/// Two verified callers, one shared client key, identity propagation OFF —
/// `cache_binding` is `None`, which is the shipped default and the exact
/// configuration under which the suffix used to be empty for everyone.
#[tokio::test]
async fn a_second_verified_caller_is_not_served_the_firsts_idempotent_result() {
    let (registry, calls) = counted_backend("alpha");
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
    let alice = verified("alice");
    let bob = verified("bob");
    let args = invoke_args("alpha", "read");

    let first = meta
        .invoke_tool(
            &args,
            None,
            &MetaMcpCallerContext {
                verified_identity: Some(&alice),
                retry: &retry,
                ..ctx(&AllowAll)
            },
        )
        .await;
    assert!(first.is_ok(), "the first call must succeed: {first:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "and must reach the backend"
    );

    let second = meta
        .invoke_tool(
            &args,
            None,
            &MetaMcpCallerContext {
                verified_identity: Some(&bob),
                retry: &retry,
                ..ctx(&AllowAll)
            },
        )
        .await;
    assert!(second.is_ok(), "the second call must succeed: {second:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "bob was served alice's stored result — the verified identity is not \
         reaching the retry key on the production path"
    );

    // And the key IS live, so the assertion above cannot have passed because
    // idempotency was inert: alice repeating her own call is de-duplicated.
    let repeat = meta
        .invoke_tool(
            &args,
            None,
            &MetaMcpCallerContext {
                verified_identity: Some(&alice),
                retry: &retry,
                ..ctx(&AllowAll)
            },
        )
        .await;
    assert!(repeat.is_ok(), "alice's repeat must succeed: {repeat:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "alice's own repeat reached the backend a second time — idempotency is \
         inert here, and the caller-separation assertion above proved nothing"
    );
}
