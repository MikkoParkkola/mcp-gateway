// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How a bridged exchange that did not complete settles its key
//! (`settle_bridged`): refused before its backend only when the delivery
//! counted no send; otherwise the key is kept as may-have-run.
//!
//! Synthetic bridge state: the bridge is entered only after a backend
//! answered, so a delivery that sent nothing has no integration fixture. The
//! rows hand the settlement a real reservation and a real admission lease and
//! read what each came to.

use std::sync::Arc;

use serde_json::json;

use super::settle_bridged;
use crate::backend::BackendRegistry;
use crate::gateway::authz::AllowAll;
use crate::gateway::delivery_facts;
use crate::gateway::meta_mcp::admission::{SyncAdmission, SyncLease};
use crate::gateway::meta_mcp::authz_tests::ctx;
use crate::gateway::meta_mcp::{AdmissionOwner, MetaMcp, MetaMcpCallerContext};
use crate::idempotency::{
    CheckOutcome, GuardOutcome, IdempotencyCache, IdempotencyReservation, enforce,
};
use crate::protocol::mrtr::RetryFields;
use crate::protocol::{JsonRpcResponse, RequestId};

const KEY: &str = "k-parked-settle";

/// A reservation of `KEY` on a fresh cache.
fn reserve(cache: &Arc<IdempotencyCache>) -> IdempotencyReservation {
    match enforce(cache, KEY, "fp").expect("a fresh key is admitted") {
        GuardOutcome::Proceed(reservation) => reservation,
        other => panic!("a fresh key must proceed: {other:?}"),
    }
}

/// Whether the admission store would answer a repeat of the keyed call the
/// lease was admitted for from what the lease retained.
fn replays(meta: &MetaMcp, caller: &MetaMcpCallerContext<'_>, id: i64) -> bool {
    let admitted = meta.admit_meta_sync_for_test(
        AdmissionOwner::for_test(caller.owner_principal()),
        caller,
        "gateway_set_state",
        &json!({"state": "triage"}),
        Some("legacy:session"),
        &RequestId::Number(id),
    );
    matches!(admitted, Ok(SyncAdmission::Replay(..)))
}

/// The lease of a first keyed call that dispatched once.
fn dispatched_lease(meta: &MetaMcp, caller: &MetaMcpCallerContext<'_>) -> SyncLease {
    let admitted = meta.admit_meta_sync_for_test(
        AdmissionOwner::for_test(caller.owner_principal()),
        caller,
        "gateway_set_state",
        &json!({"state": "triage"}),
        Some("legacy:session"),
        &RequestId::Number(1),
    );
    let Ok(SyncAdmission::Owned(lease)) = admitted else {
        panic!("the key must be free for the first call");
    };
    lease.mark_dispatched();
    lease
}

fn refusal_body() -> JsonRpcResponse {
    JsonRpcResponse::success(RequestId::Number(1), json!({"isError": true}))
}

/// R19(a): a parked round whose delivery counted no send is refused before
/// its backend: the lease is withdrawn and the key released.
#[tokio::test]
async fn a_parked_round_that_sent_nothing_withdraws_its_lease_and_releases_its_key() {
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    let retry = RetryFields {
        idempotency_key: Some("admission-key".into()),
        ..RetryFields::default()
    };
    let caller = MetaMcpCallerContext {
        credential_principal: Some("verified-credential-owner"),
        retry: &retry,
        is_modern: false,
        era: crate::protocol::meta::Era::Modern,
        ..ctx(&AllowAll)
    };
    let lease = dispatched_lease(&meta, &caller);
    let cache = Arc::new(IdempotencyCache::new());
    let mut held = Some(reserve(&cache));

    delivery_facts::scope(async {
        assert!(
            delivery_facts::nothing_sent(),
            "premise: the delivery counted a send"
        );
        settle_bridged(&mut held, Some(&lease), true);
    })
    .await;

    assert!(held.is_none(), "the reservation was kept, not released");
    assert!(
        matches!(cache.check(KEY), CheckOutcome::Proceed),
        "the key is still held after a round that sent nothing"
    );
    lease.complete_delivery(&refusal_body(), None);
    assert!(
        !replays(&meta, &caller, 2),
        "the lease still protects a round that sent nothing"
    );
}

/// R19(b), settlement level: the same parked round after an earlier round
/// reached the backend keeps its key as may-have-run and keeps its lease.
#[tokio::test]
async fn a_parked_round_after_a_counted_send_keeps_its_lease_and_commits_its_key() {
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    let retry = RetryFields {
        idempotency_key: Some("admission-key".into()),
        ..RetryFields::default()
    };
    let caller = MetaMcpCallerContext {
        credential_principal: Some("verified-credential-owner"),
        retry: &retry,
        is_modern: false,
        era: crate::protocol::meta::Era::Modern,
        ..ctx(&AllowAll)
    };
    let lease = dispatched_lease(&meta, &caller);
    let cache = Arc::new(IdempotencyCache::new());
    let mut held = Some(reserve(&cache));

    delivery_facts::scope(async {
        delivery_facts::counted_send(async { Ok::<(), crate::Error>(()) })
            .await
            .expect("the earlier round's send returns");
        assert!(
            !delivery_facts::nothing_sent(),
            "premise: the earlier round was not counted as a send"
        );
        settle_bridged(&mut held, Some(&lease), true);
    })
    .await;

    assert!(held.is_some(), "the reservation was released after a send");
    drop(held);
    match cache.check(KEY) {
        CheckOutcome::Completed(stored) => assert!(
            stored.to_string().contains("may have reached the backend"),
            "the key was committed with something other than the notice: {stored}"
        ),
        other => panic!("the key was not committed as may-have-run: {other:?}"),
    }
    lease.complete_delivery(&refusal_body(), None);
    assert!(
        replays(&meta, &caller, 2),
        "the lease was withdrawn after a send"
    );
}
